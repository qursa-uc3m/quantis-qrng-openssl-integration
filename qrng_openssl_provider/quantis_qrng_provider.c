#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include "quantis_qrng_provider_rand.h"

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

#define QUANTIS_PROV_NAME "Quantis QRNG Provider"
#define QUANTIS_PROV_VERSION QUANTIS_PROV_PKG_VERSION
#define QUANTIS_PROV_BUILD_INFO "Quantis QRNG Provider v." QUANTIS_PROV_PKG_VERSION

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *quantis_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END
    };

    return param_types;
}

static int quantis_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QUANTIS_PROV_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QUANTIS_PROV_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QUANTIS_PROV_BUILD_INFO))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* always in running state */
        return 0;

    return 1;
}

static void
quantis_qrng_teardown(void *provctx)
{
    QUANTIS_RAND_CTX *ctx = provctx;

    OPENSSL_clear_free(ctx, sizeof(QUANTIS_RAND_CTX));
}

static const OSSL_ALGORITHM quantis_rand_algorithm[] = {
    { "CTR-DRBG", NULL, quantis_rand_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *quantis_operation_query(OSSL_PROVIDER *prov, int operation_id, int *no_cache)
{
    *no_cache = 0;

    switch(operation_id) {
        case OSSL_OP_RAND:
            return quantis_rand_algorithm;
        default:
            return NULL;
    }
    return NULL;
}

static const OSSL_DISPATCH quantis_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void(*)(void))quantis_operation_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void(*)(void))quantis_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void(*)(void))quantis_get_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))quantis_qrng_teardown },
    { 0, NULL }
};

int __attribute__((visibility("default"))) 
OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    *out = quantis_provider_dispatch_table;
    
    return 1;
}