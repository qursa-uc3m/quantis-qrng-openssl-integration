#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef USE_QUANTIS_READ
#include "Quantis.h"
#endif

#include "quantis_qrng_provider_rand.h"

#ifndef QUANTIS_DEVICE_PATTERN
#define QUANTIS_DEVICE_PATTERN "/dev/qrandom%d"
#endif

#ifdef MEASURE_RNG
#include <sys/mman.h>
#include <sys/stat.h>
#define SHARED_MEM_NAME "/random_numbers_shm"
#endif

#ifdef USE_QUANTIS_READ
#ifdef DEVICE_USB
static const QuantisDeviceType device_type = QUANTIS_DEVICE_USB;
#elif defined(DEVICE_PCIE)
static const QuantisDeviceType device_type = QUANTIS_DEVICE_PCI;
#endif
#endif

static const int device_number = DEVICE_NUMBER;

static OSSL_FUNC_rand_newctx_fn quantis_rand_newctx;
static OSSL_FUNC_rand_freectx_fn quantis_rand_freectx;
static OSSL_FUNC_rand_instantiate_fn quantis_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn quantis_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn quantis_rand_generate;
static OSSL_FUNC_rand_reseed_fn quantis_rand_reseed;
static OSSL_FUNC_rand_enable_locking_fn quantis_rand_enable_locking;
static OSSL_FUNC_rand_lock_fn quantis_rand_lock;
static OSSL_FUNC_rand_unlock_fn quantis_rand_unlock;
static OSSL_FUNC_rand_gettable_ctx_params_fn quantis_rand_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn quantis_rand_get_ctx_params;

static void *quantis_rand_newctx(void *provctx, void *parent,
    const OSSL_DISPATCH *parent_calls)
{
    QUANTIS_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    (void)parent;
    (void)parent_calls;
    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;
    ctx->state = EVP_RAND_STATE_UNINITIALISED;
    ctx->fd = -1;
    ctx->lock = CRYPTO_THREAD_lock_new();
    if (ctx->lock == NULL) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return NULL;
    }
    return ctx;
}

static void quantis_rand_freectx(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;

    if (ctx == NULL)
        return;
    if (ctx->fd >= 0)
        close(ctx->fd);
    CRYPTO_THREAD_lock_free(ctx->lock);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

#ifdef MEASURE_RNG
static int measure_random_numbers(size_t outlen)
{
    int ok = 0;
    int shm_fd = -1;
    size_t *counter = MAP_FAILED;

    shm_fd = shm_open(SHARED_MEM_NAME, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (shm_fd == -1)
        goto done;
    if (ftruncate(shm_fd, sizeof(*counter)) == -1)
        goto done;
    if (flock(shm_fd, LOCK_EX) == -1)
        goto done;

    counter = mmap(NULL, sizeof(*counter), PROT_READ | PROT_WRITE,
        MAP_SHARED, shm_fd, 0);
    if (counter == MAP_FAILED)
        goto done;
    if (SIZE_MAX - *counter < outlen)
        *counter = SIZE_MAX;
    else
        *counter += outlen;
    ok = 1;

done:
    if (counter != MAP_FAILED)
        munmap(counter, sizeof(*counter));
    if (shm_fd != -1) {
        flock(shm_fd, LOCK_UN);
        close(shm_fd);
    }
    return ok;
}

static void record_generated_bytes(size_t outlen)
{
    (void)measure_random_numbers(outlen);
}
#else
#define record_generated_bytes(outlen) ((void)(outlen))
#endif

#if defined(XOR_RANDOM) || defined(ALLOW_OS_FALLBACK)
static int os_random_bytes(unsigned char *out, size_t outlen)
{
    size_t offset = 0;

    while (offset < outlen) {
        size_t request = outlen - offset;
        ssize_t n;

        if (request > (size_t)SSIZE_MAX)
            request = (size_t)SSIZE_MAX;
        n = getrandom(out + offset, request, 0);
        if (n > 0) {
            offset += (size_t)n;
            continue;
        }
        if (n == -1 && errno == EINTR)
            continue;
        return 0;
    }
    return 1;
}
#endif

#ifdef USE_QUANTIS_READ
static int quantis_source_read(unsigned char *out, size_t outlen)
{
    size_t offset = 0;

    while (offset < outlen) {
        size_t chunk = outlen - offset;
        int read_bytes;

        if (chunk > QUANTIS_MAX_READ_SIZE)
            chunk = QUANTIS_MAX_READ_SIZE;
        read_bytes = QuantisRead(device_type, (unsigned int)device_number,
            out + offset, chunk);
        if (read_bytes < 0)
            return 0;
        if ((size_t)read_bytes != chunk)
            return 0;
        offset += chunk;
    }
    return 1;
}
#else
static int quantis_open_device(QUANTIS_RAND_CTX *ctx)
{
    char path[sizeof(QUANTIS_DEVICE_PATTERN) + 32];
    int length;
    struct stat status;

    length = snprintf(path, sizeof(path), QUANTIS_DEVICE_PATTERN, device_number);

    if (length < 0 || length >= (int)sizeof(path))
        return 0;
    ctx->fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (ctx->fd < 0)
        return 0;
    if (fstat(ctx->fd, &status) != 0 || !S_ISCHR(status.st_mode)) {
        close(ctx->fd);
        ctx->fd = -1;
        return 0;
    }
    return 1;
}

static int quantis_source_read(QUANTIS_RAND_CTX *ctx, unsigned char *out,
    size_t outlen)
{
    size_t offset = 0;

    if (ctx->fd < 0)
        return 0;
    while (offset < outlen) {
        ssize_t n = read(ctx->fd, out + offset, outlen - offset);

        if (n > 0) {
            offset += (size_t)n;
            continue;
        }
        if (n == -1 && errno == EINTR)
            continue;
        close(ctx->fd);
        ctx->fd = -1;
        return 0;
    }
    return 1;
}
#endif

static int quantis_rand_generate(void *vctx, unsigned char *out, size_t outlen,
    unsigned int strength,
    int prediction_resistance,
    const unsigned char *adin, size_t adinlen)
{
    QUANTIS_RAND_CTX *ctx = vctx;
    int source_ok;

    (void)prediction_resistance; /* Every request reads a live source. */
    if (ctx == NULL || ctx->state != EVP_RAND_STATE_READY || out == NULL) {
        if (ctx != NULL)
            QUANTIS_RAISE(ctx->provctx, QUANTIS_R_INVALID_STATE,
                "generator is not ready");
        return 0;
    }
    if (adinlen != 0) {
        QUANTIS_RAISE(ctx->provctx, QUANTIS_R_INVALID_INPUT,
            "additional input is not supported");
        return 0;
    }
    (void)adin;
    if (outlen > QUANTIS_RAND_MAX_REQUEST || strength > QUANTIS_RAND_STRENGTH) {
        QUANTIS_RAISE(ctx->provctx, QUANTIS_R_INVALID_INPUT,
            "request exceeds the advertised limits");
        return 0;
    }
    if (outlen == 0)
        return 1;

#ifdef XOR_RANDOM
    {
        unsigned char *quantis_out = OPENSSL_malloc(outlen);

        if (quantis_out == NULL) {
            QUANTIS_RAISE(ctx->provctx, QUANTIS_R_RANDOM_SOURCE_FAILURE,
                "temporary output allocation failed");
            return 0;
        }
#ifdef USE_QUANTIS_READ
        source_ok = quantis_source_read(quantis_out, outlen);
#else
        source_ok = quantis_source_read(ctx, quantis_out, outlen);
#endif
        if (source_ok) {
            size_t i;

            if (!os_random_bytes(out, outlen)) {
                OPENSSL_clear_free(quantis_out, outlen);
                OPENSSL_cleanse(out, outlen);
                ctx->state = EVP_RAND_STATE_ERROR;
                QUANTIS_RAISE(ctx->provctx, QUANTIS_R_RANDOM_SOURCE_FAILURE,
                    "operating-system random source failed");
                return 0;
            }
            for (i = 0; i < outlen; ++i)
                out[i] ^= quantis_out[i];
        }
        OPENSSL_clear_free(quantis_out, outlen);
    }
#else
#ifdef USE_QUANTIS_READ
    source_ok = quantis_source_read(out, outlen);
#else
    source_ok = quantis_source_read(ctx, out, outlen);
#endif
#endif

    if (source_ok) {
        record_generated_bytes(outlen);
        return 1;
    }
#ifdef ALLOW_OS_FALLBACK
    if (os_random_bytes(out, outlen)) {
        record_generated_bytes(outlen);
        return 1;
    }
    OPENSSL_cleanse(out, outlen);
    ctx->state = EVP_RAND_STATE_ERROR;
    QUANTIS_RAISE(ctx->provctx, QUANTIS_R_RANDOM_SOURCE_FAILURE,
        "operating-system random source failed");
    return 0;
#else
    OPENSSL_cleanse(out, outlen);
    ctx->state = EVP_RAND_STATE_ERROR;
    QUANTIS_RAISE(ctx->provctx, QUANTIS_R_RANDOM_SOURCE_FAILURE,
        "Quantis source failed and operating-system fallback is disabled");
    return 0;
#endif
}

static int quantis_rand_instantiate(void *vctx, unsigned int strength,
    int prediction_resistance,
    const unsigned char *pstr, size_t pstr_len,
    const OSSL_PARAM params[])
{
    QUANTIS_RAND_CTX *ctx = vctx;

    (void)prediction_resistance;
    if (pstr_len != 0) {
        QUANTIS_RAISE(ctx == NULL ? NULL : ctx->provctx,
            QUANTIS_R_INVALID_INPUT,
            "personalisation strings are not supported");
        return 0;
    }
    (void)pstr;
    (void)params;
    if (ctx == NULL)
        return 0;
    if (strength > QUANTIS_RAND_STRENGTH) {
        QUANTIS_RAISE(ctx->provctx, QUANTIS_R_INVALID_INPUT,
            "requested strength exceeds the advertised strength");
        return 0;
    }
#ifndef USE_QUANTIS_READ
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    if (!quantis_open_device(ctx)) {
#ifndef ALLOW_OS_FALLBACK
        ctx->state = EVP_RAND_STATE_ERROR;
        QUANTIS_RAISE(ctx->provctx, QUANTIS_R_DEVICE_UNAVAILABLE,
            "Quantis device is unavailable or is not a character device");
        return 0;
#endif
    }
#endif
    ctx->state = EVP_RAND_STATE_READY;
    return 1;
}

static int quantis_rand_uninstantiate(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;

    if (ctx == NULL)
        return 0;
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    ctx->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int quantis_rand_reseed(void *vctx, int prediction_resistance,
    const unsigned char *ent, size_t ent_len, const unsigned char *adin,
    size_t adin_len)
{
    QUANTIS_RAND_CTX *ctx = vctx;

    (void)prediction_resistance;
    (void)ent;
    (void)adin;
    if (ctx == NULL || ctx->state != EVP_RAND_STATE_READY) {
        if (ctx != NULL)
            QUANTIS_RAISE(ctx->provctx, QUANTIS_R_INVALID_STATE,
                "generator is not ready");
        return 0;
    }
    if (ent_len != 0 || adin_len != 0) {
        QUANTIS_RAISE(ctx->provctx, QUANTIS_R_INVALID_INPUT,
            "external entropy and additional input are not supported");
        return 0;
    }
    return 1;
}

static int quantis_rand_enable_locking(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;

    return ctx != NULL && ctx->lock != NULL;
}

static int quantis_rand_lock(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;

    return ctx != NULL && ctx->lock != NULL
        && CRYPTO_THREAD_write_lock(ctx->lock);
}

static void quantis_rand_unlock(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;

    if (ctx != NULL && ctx->lock != NULL)
        CRYPTO_THREAD_unlock(ctx->lock);
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *quantis_rand_gettable_ctx_params(void *ctx,
    void *provctx)
{
    (void)ctx;
    (void)provctx;
    return known_gettable_ctx_params;
}

static int quantis_rand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    QUANTIS_RAND_CTX *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, QUANTIS_RAND_MAX_REQUEST))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, QUANTIS_RAND_STRENGTH))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->state))
        return 0;
    return 1;
}

const OSSL_DISPATCH quantis_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))quantis_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))quantis_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))quantis_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))quantis_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))quantis_rand_generate },
    { OSSL_FUNC_RAND_RESEED, (void (*)(void))quantis_rand_reseed },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))quantis_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))quantis_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))quantis_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))quantis_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))quantis_rand_get_ctx_params },
    { 0, NULL }
};
