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
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
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
static OSSL_FUNC_rand_enable_locking_fn quantis_rand_enable_locking;
static OSSL_FUNC_rand_lock_fn quantis_rand_lock;
static OSSL_FUNC_rand_unlock_fn quantis_rand_unlock;
static OSSL_FUNC_rand_gettable_ctx_params_fn quantis_rand_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn quantis_rand_get_ctx_params;

static void *quantis_rand_newctx(void *provctx, void *parent,
    const OSSL_DISPATCH *parent_calls)
{
    QUANTIS_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    (void)provctx;
    (void)parent;
    (void)parent_calls;
    if (ctx == NULL)
        return NULL;

    ctx->state = EVP_RAND_STATE_UNINITIALISED;
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
        goto done;
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
    if (!measure_random_numbers(outlen))
        fprintf(stderr, "QRNG_WARNING: failed to update generated-byte counter\n");
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
        if (read_bytes < 0) {
            fprintf(stderr, "QRNG_ERROR: QuantisRead failed: %s\n",
                QuantisStrError(read_bytes));
            return 0;
        }
        if ((size_t)read_bytes != chunk) {
            fprintf(stderr, "QRNG_ERROR: short read from Quantis device\n");
            return 0;
        }
        offset += chunk;
    }
    return 1;
}
#else
static int quantis_source_read(unsigned char *out, size_t outlen)
{
    char path[sizeof(QUANTIS_DEVICE_PATTERN) + 32];
    size_t offset = 0;
    int fd;

    if (snprintf(path, sizeof(path), QUANTIS_DEVICE_PATTERN, device_number)
        >= (int)sizeof(path))
        return 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        fprintf(stderr, "QRNG_ERROR: failed to open %s: %s\n", path,
            strerror(errno));
        return 0;
    }
    while (offset < outlen) {
        ssize_t n = read(fd, out + offset, outlen - offset);

        if (n > 0) {
            offset += (size_t)n;
            continue;
        }
        if (n == -1 && errno == EINTR)
            continue;
        fprintf(stderr, "QRNG_ERROR: short read from %s\n", path);
        close(fd);
        return 0;
    }
    close(fd);
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

    (void)prediction_resistance;
    (void)adin;
    (void)adinlen;
    if (ctx == NULL || ctx->state != EVP_RAND_STATE_READY || out == NULL)
        return 0;
    if (outlen > QUANTIS_RAND_MAX_REQUEST || strength > QUANTIS_RAND_STRENGTH)
        return 0;
    if (outlen == 0)
        return 1;

#ifdef XOR_RANDOM
    {
        unsigned char *quantis_out = OPENSSL_malloc(outlen);

        if (quantis_out == NULL)
            return 0;
        source_ok = quantis_source_read(quantis_out, outlen);
        if (source_ok) {
            size_t i;

            if (!os_random_bytes(out, outlen)) {
                OPENSSL_clear_free(quantis_out, outlen);
                OPENSSL_cleanse(out, outlen);
                return 0;
            }
            for (i = 0; i < outlen; ++i)
                out[i] ^= quantis_out[i];
        }
        OPENSSL_clear_free(quantis_out, outlen);
    }
#else
    source_ok = quantis_source_read(out, outlen);
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
    return 0;
#else
    OPENSSL_cleanse(out, outlen);
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
    (void)pstr;
    (void)pstr_len;
    (void)params;
    if (ctx == NULL || strength > QUANTIS_RAND_STRENGTH)
        return 0;
    ctx->state = EVP_RAND_STATE_READY;
    return 1;
}

static int quantis_rand_uninstantiate(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;

    if (ctx == NULL)
        return 0;
    ctx->state = EVP_RAND_STATE_UNINITIALISED;
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
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))quantis_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))quantis_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))quantis_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))quantis_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))quantis_rand_get_ctx_params },
    { 0, NULL }
};
