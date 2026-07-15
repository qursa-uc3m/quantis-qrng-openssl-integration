#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <string.h>

#define TEST_OUTPUT_SIZE 64U
#define EXPECTED_STRENGTH 256U
#define EXPECTED_MAX_REQUEST (1024U * 1024U)

#ifndef EXPECT_INSTANTIATE_FAILURE
static int buffer_is_all_zero(const unsigned char *buffer, size_t length)
{
    unsigned char aggregate = 0;
    size_t i;

    for (i = 0; i < length; ++i)
        aggregate |= buffer[i];
    return aggregate == 0;
}
#endif

static int consume_expected_error(const char *operation)
{
    if (ERR_peek_error() == 0) {
        fprintf(stderr, "%s did not report through the OpenSSL error stack\n",
            operation);
        return 0;
    }
    ERR_clear_error();
    return 1;
}

int main(void)
{
    unsigned char output[TEST_OUTPUT_SIZE] = { 0 };
    const unsigned char input[] = { 0x01 };
    unsigned int strength = 0;
    size_t max_request = 0;
    int state = -1;
    int result = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, &strength),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max_request),
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, &state),
        OSSL_PARAM_END
    };
    OSSL_PROVIDER *provider = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    EVP_RAND *rand = NULL;
    EVP_RAND *ctr_rand = NULL;
    EVP_RAND_CTX *ctx = NULL;

    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (default_provider == NULL) {
        fprintf(stderr, "failed to load the default provider\n");
        goto done;
    }
    provider = OSSL_PROVIDER_load(NULL, "libcustom_qrng_provider");
    if (provider == NULL) {
        fprintf(stderr, "failed to load libcustom_qrng_provider\n");
        goto done;
    }
    rand = EVP_RAND_fetch(NULL, "QUANTIS-QRNG", NULL);
    if (rand == NULL) {
        fprintf(stderr, "failed to fetch QUANTIS-QRNG\n");
        goto done;
    }
    ctr_rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    if (ctr_rand == NULL || EVP_RAND_get0_provider(ctr_rand) == provider) {
        fprintf(stderr, "custom provider captured CTR-DRBG\n");
        goto done;
    }
    ctx = EVP_RAND_CTX_new(rand, NULL);
    if (ctx == NULL)
        goto done;

    if (!EVP_RAND_CTX_get_params(ctx, params)
        || strength != EXPECTED_STRENGTH
        || max_request != EXPECTED_MAX_REQUEST
        || state != EVP_RAND_STATE_UNINITIALISED) {
        fprintf(stderr, "unexpected initial RAND parameters\n");
        goto done;
    }
    if (EVP_RAND_instantiate(ctx, EXPECTED_STRENGTH, 0,
            input, sizeof(input), NULL)) {
        fprintf(stderr, "instantiation accepted a personalisation string\n");
        goto done;
    }
    if (!consume_expected_error("personalisation rejection"))
        goto done;
    if (!EVP_RAND_CTX_get_params(ctx, params)
        || state != EVP_RAND_STATE_UNINITIALISED) {
        fprintf(stderr, "rejected input changed the initial state\n");
        goto done;
    }
#ifdef EXPECT_INSTANTIATE_FAILURE
    if (EVP_RAND_instantiate(ctx, EXPECTED_STRENGTH, 0, NULL, 0, NULL)) {
        fprintf(stderr, "strict instantiation accepted an invalid device\n");
        goto done;
    }
    if (!consume_expected_error("invalid-device rejection"))
        goto done;
    if (!EVP_RAND_CTX_get_params(ctx, params)
        || state != EVP_RAND_STATE_ERROR) {
        fprintf(stderr, "strict instantiation did not enter error state\n");
        goto done;
    }
    result = 0;
    goto done;
#else
    if (!EVP_RAND_instantiate(ctx, EXPECTED_STRENGTH, 0, NULL, 0, NULL)) {
        fprintf(stderr, "failed to instantiate QUANTIS-QRNG\n");
        goto done;
    }
#ifdef EXPECT_GENERATE_SUCCESS
    if (!EVP_RAND_generate(ctx, output, sizeof(output), EXPECTED_STRENGTH,
            1, NULL, 0)
        || buffer_is_all_zero(output, sizeof(output))) {
        fprintf(stderr, "failed to generate fallback random bytes\n");
        goto done;
    }
#else
    if (!EVP_RAND_generate(ctx, output, sizeof(output), EXPECTED_STRENGTH,
            1, NULL, 0)) {
        if (!buffer_is_all_zero(output, sizeof(output))) {
            fprintf(stderr, "failed generation exposed partial output\n");
            goto done;
        }
        if (!consume_expected_error("source failure"))
            goto done;
        if (!EVP_RAND_CTX_get_params(ctx, params)
            || state != EVP_RAND_STATE_ERROR) {
            fprintf(stderr, "source failure did not enter error state\n");
            goto done;
        }
        result = 0;
        goto done;
    }
    if (buffer_is_all_zero(output, sizeof(output))) {
        fprintf(stderr, "successful source returned all-zero output\n");
        goto done;
    }
#endif
#endif
    if (!EVP_RAND_CTX_get_params(ctx, params)
        || state != EVP_RAND_STATE_READY) {
        fprintf(stderr, "RAND did not enter the ready state\n");
        goto done;
    }
    if (EVP_RAND_generate(ctx, output, sizeof(output),
            EXPECTED_STRENGTH + 1U, 0, NULL, 0)) {
        fprintf(stderr, "generation accepted excessive strength\n");
        goto done;
    }
    if (!consume_expected_error("excessive-strength rejection"))
        goto done;
    if (EVP_RAND_generate(ctx, output, sizeof(output), EXPECTED_STRENGTH,
            0, input, sizeof(input))) {
        fprintf(stderr, "generation accepted additional input\n");
        goto done;
    }
    if (!consume_expected_error("additional-input rejection"))
        goto done;
    if (!EVP_RAND_reseed(ctx, 1, NULL, 0, NULL, 0)) {
        fprintf(stderr, "live-source reseed failed\n");
        goto done;
    }
    if (EVP_RAND_reseed(ctx, 0, NULL, 0, input, sizeof(input))) {
        fprintf(stderr, "reseed accepted additional input\n");
        goto done;
    }
    if (!consume_expected_error("reseed-input rejection"))
        goto done;
    if (!EVP_RAND_uninstantiate(ctx))
        goto done;
    if (!EVP_RAND_CTX_get_params(ctx, params)
        || state != EVP_RAND_STATE_UNINITIALISED) {
        fprintf(stderr, "RAND did not leave the ready state\n");
        goto done;
    }
    if (EVP_RAND_generate(ctx, output, sizeof(output), EXPECTED_STRENGTH,
            0, NULL, 0)) {
        fprintf(stderr, "generation succeeded while uninstantiated\n");
        goto done;
    }
    if (!consume_expected_error("uninstantiated generation"))
        goto done;

    result = 0;

done:
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(ctr_rand);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(default_provider);
    return result;
}
