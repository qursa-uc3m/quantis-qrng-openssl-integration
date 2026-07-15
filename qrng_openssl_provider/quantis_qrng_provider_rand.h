#ifndef QUANTIS_QRNG_PROVIDER_RAND_H
#define QUANTIS_QRNG_PROVIDER_RAND_H

#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>

#define QUANTIS_RAND_STRENGTH 256U
#define QUANTIS_RAND_MAX_REQUEST (1024U * 1024U)

typedef struct quantis_rand_ctx_st {
    CRYPTO_RWLOCK *lock;
    int state;
} QUANTIS_RAND_CTX;

extern const OSSL_DISPATCH quantis_rand_functions[];

#endif
