#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/random.h>
#include "Quantis.h"
#include "quantis_qrng_provider_rand.h"

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

/* Quantis QRNG hardware device parameters:*/
#ifdef DEVICE_USB
    QuantisDeviceType deviceType = QUANTIS_DEVICE_USB;
#elif defined(DEVICE_PCIE)
    QuantisDeviceType deviceType = QUANTIS_DEVICE_PCI;
#endif
int deviceNumber = DEVICE_NUMBER;

static int DEFAULT_QUANTIS_LOCK = 1;

#ifdef READ_HANDLE
    QuantisDeviceHandle *handle;
#endif

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

#ifdef DEBUG
    void printDeviceInfo() {
        #ifdef DEVICE_USB
            printf("Device type: USB\n");
        #elif defined(DEVICE_PCIE)
            printf("Device type: PCIE\n");
        #endif
    }
#endif

static void *
quantis_rand_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls)
{
    QUANTIS_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;

    ctx->state = EVP_RAND_STATE_UNINITIALISED;
    if ( DEFAULT_QUANTIS_LOCK == 1 ) {
        ctx->lock = CRYPTO_THREAD_lock_new();
        if (ctx->lock == NULL) {
            OPENSSL_clear_free(ctx, sizeof(QUANTIS_RAND_CTX));
            return NULL;
        }
    }

    return ctx;
}

static void
quantis_rand_freectx(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;
    if (ctx->lock != NULL) {
        CRYPTO_THREAD_lock_free(ctx->lock);
    }
    OPENSSL_clear_free(ctx, sizeof(QUANTIS_RAND_CTX));
}

static int fallback_rand_bytes(unsigned char *out, int count) {
    ssize_t n = getrandom(out, count, 0);

    if (n != count) {
        fprintf(stderr, "Error: read only %zd bytes out of %d\n", n, count);
        return 0;
    }

    return 1;
}

#ifdef READ_HANDLE
    static int quantis_read_handled(unsigned char *out, size_t outlen) {
        int quantisOpening = QuantisOpen(deviceType, deviceNumber, &handle);
        if (quantisOpening != QUANTIS_SUCCESS) {
            fprintf(stderr, "QRNG_ERROR: quantis_read_handled: QuantisOpen failed with error: %s\n", QuantisStrError(quantisOpening));
            return fallback_rand_bytes(out, outlen);
        }

        int readBytes = QuantisReadHandled(handle, out, outlen);
        if (readBytes < 0 || readBytes != outlen) {
            fprintf(stderr, "QRNG_ERROR: quantis_read_handled: An error occurred when reading random bytes: %s\n", QuantisStrError(readBytes));
            if (handle != NULL) {
                QuantisClose(handle);
            }
            return fallback_rand_bytes(out, outlen);
        }

        if (handle != NULL) {
            QuantisClose(handle);
        }

        return 1;
    }
#endif

#ifdef USE_DEV_QRANDOM
    static int quantis_dev_qrandom0(unsigned char *out, size_t outlen) {
        char quantis_device_file[20];
        snprintf(quantis_device_file, sizeof(quantis_device_file), "/dev/qrandom%d", deviceNumber);

        FILE* qrandom0 = fopen(quantis_device_file, "r");
        if (qrandom0 == NULL) {
            fprintf(stderr, "QRNG_ERROR: quantis_dev_qrandom0: Failed to open %s, errno=%d\n", quantis_device_file, errno);
            return fallback_rand_bytes(out, outlen);
        }
        size_t readBytes = fread(out, 1, outlen, qrandom0);
        fclose(qrandom0);
        if (readBytes < outlen) {
            fprintf(stderr, "QRNG_ERROR: quantis_dev_qrandom0: Failed to read enough bytes from %s, read %zu out of %zu\n", quantis_device_file, readBytes, outlen);

            return fallback_rand_bytes(out, outlen);
        }

        return 1;
    }
#endif

static int quantis_read(unsigned char *out, size_t outlen) {
    int readBytes = QuantisRead(deviceType, deviceNumber, out, outlen);
    if (readBytes < 0) {
        fprintf(stderr, "QRNG_ERROR:quantis_read: An error occurred when reading random bytes: %s\n", QuantisStrError(readBytes));
        return fallback_rand_bytes(out, outlen);
    } else if ((size_t)readBytes != outlen) {
        fprintf(stderr, "QRNG_ERROR:quantis_read: Asked to read %zu bytes but %d bytes have been returned\n", outlen, readBytes);
        return fallback_rand_bytes(out, outlen);
    }

    return 1;
}

static int quantis_rand_generate(void *vctx, unsigned char *out, size_t outlen,
                                 unsigned int strength, int prediction_resistance,
                                 const unsigned char *adin, size_t adinlen)
{
    #ifdef XOR_RANDOM
        unsigned char *temp_out = OPENSSL_malloc(outlen);
        if (temp_out == NULL)
            return 0;
        #ifdef USE_QUANTIS_READ
            if (!quantis_read(temp_out, outlen)) {
                OPENSSL_clear_free(temp_out, outlen);
                return 0;
            }
        #else
            if (!quantis_dev_qrandom0(temp_out, outlen)) {
                OPENSSL_clear_free(temp_out, outlen);
                return 0;
            }
        #endif

        if (!fallback_rand_bytes(out, outlen)) {
            OPENSSL_clear_free(temp_out, outlen);
            return 0;
        }

        for (size_t i = 0; i < outlen; i++) {
            out[i] ^= temp_out[i];
        }
        OPENSSL_clear_free(temp_out, outlen);
    #else
        #ifdef USE_QUANTIS_READ
            if (!quantis_read(out, outlen)) {
                return 0;
            }
        #else
            if (!quantis_dev_qrandom0(out, outlen)) {
                return 0;
            }
        #endif
    #endif
    return 1;
}

static int
quantis_rand_instantiate(void *vctx, unsigned int strength,
                         int prediction_resistance,
                         const unsigned char *pstr, size_t pstr_len,
                         const OSSL_PARAM params[])
{
    
    #ifdef DEBUG
        printDeviceInfo();
    #endif

    QUANTIS_RAND_CTX *ctx = vctx;

    ctx->state = EVP_RAND_STATE_READY;

    return 1;
}

static int
quantis_rand_uninstantiate(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;

    ctx->state = EVP_RAND_STATE_UNINITIALISED;

    return 1;
}

static int
quantis_rand_enable_locking(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;
    if (ctx == NULL) {
        return 0;  
    }
    if(ctx->lock == NULL && DEFAULT_QUANTIS_LOCK == 1) {
        ctx->lock = CRYPTO_THREAD_lock_new();
    }
    return 1;
}

static int
quantis_rand_lock(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;
    if (ctx == NULL) {
        return 0;  
    }
    if(ctx->lock == NULL) {
        return 0;
    }

    return CRYPTO_THREAD_write_lock(ctx->lock);
}

static void
quantis_rand_unlock(void *vctx)
{
    QUANTIS_RAND_CTX *ctx = vctx;
    if (ctx == NULL) {
        return;  
    }
    if(ctx->lock != NULL) {
        CRYPTO_THREAD_unlock(ctx->lock);
    }
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *quantis_rand_gettable_ctx_params(void *ctx, void *provctx)
{
    return known_gettable_ctx_params;
}

static int quantis_rand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    QUANTIS_RAND_CTX *ctx = (QUANTIS_RAND_CTX *)vctx;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, QUANTIS_MAX_READ_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, 8*QUANTIS_MAX_READ_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->state))
        return 0;

    return 1;
}

const OSSL_DISPATCH quantis_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))quantis_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))quantis_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void))quantis_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))quantis_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))quantis_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void(*)(void))quantis_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void(*)(void))quantis_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void(*)(void))quantis_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))quantis_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))quantis_rand_get_ctx_params },
    { 0, NULL }
};
