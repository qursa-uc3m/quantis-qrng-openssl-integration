#ifndef QUANTIS_QRNG_H
#define QUANTIS_QRNG_H


#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include "Quantis.h"

// Custom RAND_METHOD
static RAND_METHOD custom_rand_method;

// Engine ID and name
extern const char *engine_id;
extern const char *engine_name;

// Quantis QRNG hardware device parameters
extern QuantisDeviceType deviceType;
extern int cardNumber;
extern QuantisDeviceHandle *handle;

extern FILE *log_file;

static int fallback_rand_bytes(unsigned char *out, int count);
static int custom_rand_bytes(unsigned char *buf, int num);
static int custom_rand_status(void);
static int quantis_qrng_init(ENGINE *e);
static int quantis_qrng_finish(ENGINE *e);
int init_rand(ENGINE *e);
static int bind(ENGINE *e, const char *id);

#endif