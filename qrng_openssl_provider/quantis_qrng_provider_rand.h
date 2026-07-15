#ifndef QUANTIS_QRNG_PROVIDER_RAND_H
#define QUANTIS_QRNG_PROVIDER_RAND_H

#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <stdint.h>

#define QUANTIS_RAND_STRENGTH 256U
#define QUANTIS_RAND_MAX_REQUEST (1024U * 1024U)

typedef struct quantis_prov_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_FUNC_core_new_error_fn *new_error;
    OSSL_FUNC_core_set_error_debug_fn *set_error_debug;
    OSSL_FUNC_core_vset_error_fn *vset_error;
} QUANTIS_PROV_CTX;

typedef struct quantis_rand_ctx_st {
    QUANTIS_PROV_CTX *provctx;
    CRYPTO_RWLOCK *lock;
    int state;
    int fd;
} QUANTIS_RAND_CTX;

enum {
    QUANTIS_R_INVALID_INPUT = 1,
    QUANTIS_R_DEVICE_UNAVAILABLE,
    QUANTIS_R_RANDOM_SOURCE_FAILURE,
    QUANTIS_R_INVALID_STATE
};

void quantis_raise_error(QUANTIS_PROV_CTX *ctx, uint32_t reason,
    const char *file, int line, const char *func, const char *fmt, ...);

#define QUANTIS_RAISE(ctx, reason, ...)                                \
    quantis_raise_error((ctx), (reason), __FILE__, __LINE__, __func__, \
        __VA_ARGS__)

extern const OSSL_DISPATCH quantis_rand_functions[];

#endif
