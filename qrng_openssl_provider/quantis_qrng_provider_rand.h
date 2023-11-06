#ifndef QUANTIS_QRNG_PROVIDER_RAND_H
#define QUANTIS_QRNG_PROVIDER_RAND_H

#include <openssl/provider.h>

typedef struct quantis_rand_ctx_st {
    CRYPTO_RWLOCK *lock;
    int state;
    char* device;
} QUANTIS_RAND_CTX;

extern const OSSL_DISPATCH quantis_rand_functions[];

#endif