# Quantis QRNG OpenSSL Integration

This repository contains the implementation of an OpenSSL provider that integrates *Quantis* quantum random number generators (QRNGs) into OpenSSL for random number generation. It provides an alternative to the default random number generation in OpenSSL, using the hardware-based quantum entropy source from the Quantis QRNG devices.

## Supported Devices

The provider has been tested with the following Quantis QRNG devices:

- *Quantis PCIe-240M*
- *Quantis USB-4M*

As of now, the provider does not support entropy extraction through the Quantis libraries. This is not necessary for the PCIe-240M QRNG, since it has integrated hardware entropy extraction. However, software-based entropy extraction might be a valuable addition for the USB-4M QRNG.

## Prerequisites

Before installing the provider, ensure you have the Quantis QRNG devices and/or drivers properly installed on your system, and that the Quantis library paths are included in `LD_LIBRARY_PATH`. For installation instructions and more details, visit [Quantis Software](https://www.idquantique.com/random-number-generation/products/quantis-software/).

## Installation

Build with

```console
cmake -DDEVICE_TYPE=<USB/PCIE> -DQUANTIS_LIB=<YES/NO> -DDEVICE_NUMBER=<number> [-DOPENSSL_ROOT_DIR=<openssl_3.0_dir>] [-DDEBUG=<ON/OFF>] [-DXOR_RANDOM=<ON/OFF>]
```

Parameter Breakdown:

- `-DDEVICE_TYPE`: Specifies the type of Quantis device you are using. Can be either USB for *Quantis USB-4M* or PCIE for *Quantis PCIe-240M*. The default is USB.
- `-DDEVICE_NUMBER`: Identifies the device number if you have multiple devices. It should be set to the corresponding device number, with a default of 0.
- `-DQUANTIS_LIB`: Determines whether to use the Quantis library (YES) or the device directly via `/dev/qrandom{DEVICE_NUMBER}` (NO). The default is YES.
- `-DQUANTIS_LIB_DIR`: Specifies the filesystem path to the Quantis library directory. This is necessary for the build process to locate and link the Quantis library for QRNG functionality. If you have installed the Quantis libraries in a custom directory, provide that path using this option. The default path is set to `/opt/quantis/Libs-Apps`. If your libraries are located in a different directory, you need to set this path accordingly. If not set, the build process will use the default path.
- `-DOPENSSL_ROOT_DIR`: (Optional) Sets the path to the OpenSSL 3.0 installation directory. If not provided, cmake will attempt to use the version of OpenSSL installed on the system.
- `-DDEBUG`: (Optional) Turns on (ON) or off (OFF) debugging features. The default is OFF.
- `-DXOR_RANDOM`: (Optional) Controls whether the output of the QRNG should be XORed with the output from `getrandom()`. This can be set to ON or OFF, with a default of ON.

For example:

```console
mkdir build
cd build
cmake -DDEVICE_TYPE=PCIE -DQUANTIS_LIB=NO -DOPENSSL_ROOT_DIR=/opt/oqs_openssl3/.local ..
make
```

Deploy the provider library:

```console
sudo mkdir -p /opt/quantis/providers/
sudo cp libcustom_qrng_provider.so /opt/quantis/providers/
```

Verify provider loading:

```console
openssl list -providers -verbose -provider-path <provider-lib-dir> -provider <provider_name>
```

For instance:

```console
openssl list -providers -verbose -provider-path /opt/quantis/providers/ -provider libcustom_qrng_provider
```

*Note*: Don't forget to add the custom OpenSSL 3.* path to the `~/.bashrc` file, for example:

```text
## OQS OPENSSL3 -liboqs PROVIDER-
export LD_LIBRARY_PATH="/opt/oqs_openssl3/.local/lib64:$LD_LIBRARY_PATH"
```

## Testing

Generate random bytes:

```console
openssl rand -provider-path <provider-lib-dir> -provider <provider_name> -base64 32
```

For example:

```console
openssl rand -provider-path /opt/quantis/providers/ -provider libcustom_qrng_provider -base64 32
```

## Adding the Provider to `openssl.cnf`

The provider can be added to the OpenSSL `openssl.cnf`. Check the location of the OpenSSL `openssl.cnf` configuration file with

```console
openssl version -d
```

We have included a sample configuration file in the `config` directory for illustration purposes.