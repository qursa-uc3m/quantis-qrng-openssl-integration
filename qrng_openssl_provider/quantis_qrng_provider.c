#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "quantis_qrng_provider_rand.h"

#include <stdarg.h>

#define QUANTIS_PROV_NAME "Quantis QRNG Provider"
#define QUANTIS_PROV_VERSION QUANTIS_PROV_PKG_VERSION
#define QUANTIS_PROV_BUILD_INFO "Quantis QRNG Provider v." QUANTIS_PROV_PKG_VERSION

static const OSSL_PARAM *quantis_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;
    return param_types;
}

static int quantis_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    (void)provctx;

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
    OPENSSL_clear_free(provctx, sizeof(QUANTIS_PROV_CTX));
}

void quantis_raise_error(QUANTIS_PROV_CTX *ctx, uint32_t reason,
    const char *file, int line, const char *func, const char *fmt, ...)
{
    va_list args;

    if (ctx == NULL || ctx->new_error == NULL || ctx->set_error_debug == NULL
        || ctx->vset_error == NULL)
        return;
    ctx->new_error(ctx->handle);
    ctx->set_error_debug(ctx->handle, file, line, func);
    va_start(args, fmt);
    ctx->vset_error(ctx->handle, reason, fmt, args);
    va_end(args);
}

static const OSSL_ITEM *quantis_get_reason_strings(void *provctx)
{
    static const OSSL_ITEM reasons[] = {
        { QUANTIS_R_INVALID_INPUT, "unsupported random-generator input" },
        { QUANTIS_R_DEVICE_UNAVAILABLE, "Quantis device unavailable" },
        { QUANTIS_R_RANDOM_SOURCE_FAILURE, "random source failure" },
        { QUANTIS_R_INVALID_STATE, "random generator in invalid state" },
        { 0, NULL }
    };

    (void)provctx;
    return reasons;
}

static const OSSL_ALGORITHM quantis_rand_algorithm[] = {
    { "QUANTIS-QRNG", NULL,
        quantis_rand_functions, "Quantis hardware random number generator" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *quantis_operation_query(void *provctx,
    int operation_id,
    int *no_cache)
{
    (void)provctx;
    if (no_cache != NULL)
        *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_RAND:
        return quantis_rand_algorithm;
    default:
        return NULL;
    }
}

static const OSSL_DISPATCH quantis_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))quantis_operation_query },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))quantis_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))quantis_get_params },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
        (void (*)(void))quantis_get_reason_strings },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))quantis_qrng_teardown },
    { 0, NULL }
};

int __attribute__((visibility("default")))
OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    QUANTIS_PROV_CTX *ctx;
    const OSSL_DISPATCH *dispatch;

    if (out == NULL || provctx == NULL)
        return 0;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;
    ctx->handle = handle;
    for (dispatch = in; dispatch != NULL && dispatch->function_id != 0;
        ++dispatch) {
        switch (dispatch->function_id) {
        case OSSL_FUNC_CORE_NEW_ERROR:
            ctx->new_error = OSSL_FUNC_core_new_error(dispatch);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            ctx->set_error_debug = OSSL_FUNC_core_set_error_debug(dispatch);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            ctx->vset_error = OSSL_FUNC_core_vset_error(dispatch);
            break;
        }
    }
    if (ctx->new_error == NULL || ctx->set_error_debug == NULL
        || ctx->vset_error == NULL) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return 0;
    }

    *out = quantis_provider_dispatch_table;
    *provctx = ctx;

    return 1;
}
