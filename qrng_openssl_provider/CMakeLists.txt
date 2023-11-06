cmake_minimum_required(VERSION 3.10)

project(custom_rng_provider VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(DEBUG "Build with debug information" OFF)

add_definitions(-DQUANTIS_PROV_PKG_VERSION="${custom_rng_provider_VERSION}")

if(DEBUG)
    message(STATUS "Debug mode enabled")
    add_definitions(-DDEBUG)
endif()

option(XOR_RANDOM "Enable XOR Random functionality" ON)

if(XOR_RANDOM)
    message(STATUS "XOR Random functionality enabled")
    add_definitions(-DXOR_RANDOM)
else()
    message(STATUS "XOR Random functionality disabled")
endif()

set(DEVICE_TYPE "USB" CACHE STRING "Select the device type (USB or PCIE)")

if(DEVICE_TYPE STREQUAL "USB")
    add_definitions(-DDEVICE_USB)
    message(STATUS "USB device selected")
elseif(DEVICE_TYPE STREQUAL "PCIE")
    add_definitions(-DDEVICE_PCIE)
    message(STATUS "PCIe device selected")
else()
    message(FATAL_ERROR "Invalid value for DEVICE. Allowed values are 'USB' and 'PCIE'.")
endif()

set(QUANTIS_LIB "NO" CACHE STRING "Use the Quantis library instead of reading directly from /dev/qrandom{i}")

if(QUANTIS_LIB STREQUAL "YES")
    add_definitions(-DUSE_QUANTIS_READ)
    message(STATUS "Using Quantis library")
elseif(QUANTIS_LIB STREQUAL "NO")
    add_definitions(-DUSE_DEV_QRANDOM)
    message(STATUS "Using /dev/qrandom{i} where i is the device number")
else()
    message(FATAL_ERROR "Invalid value for QUANTIS_LIB. Allowed values are 'YES' and 'NO'.")
endif()

set(DEVICE_NUMBER "0" CACHE STRING "Number of the Quantis device. Device numbering starts at 0. Default value is 0.")
add_definitions(-DDEVICE_NUMBER=${DEVICE_NUMBER})
message(STATUS "Device number: ${DEVICE_NUMBER}")

set(TARGET custom_qrng_provider)
find_package(OpenSSL REQUIRED)

if (OPENSSL_ROOT_DIR)
  include_directories(${OPENSSL_ROOT_DIR}/include)
  message(STATUS "Using custom OpenSSL installation at ${OPENSSL_ROOT_DIR}")
else()
    message(STATUS "Searching LOCAL OpenSSL installation")
    message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
endif()

link_directories(${OPENSSL_ROOT_DIR}/lib)

set(QUANTIS_LIB_DIR "/opt/quantis/Libs-Apps" CACHE PATH "Path to the Quantis library")
set(LIB_AND_APPS_PATH "${QUANTIS_LIB_DIR}")
set(QUANTIS_INCLUDE_DIR "${LIB_AND_APPS_PATH}/Quantis")
include_directories(${QUANTIS_INCLUDE_DIR})
find_library(QUANTIS_LIBRARY NAMES Quantis HINTS "${LIB_AND_APPS_PATH}/build/Quantis")
if(NOT QUANTIS_LIBRARY)
    message(FATAL_ERROR "Quantis library not found in ${QUANTIS_LIBRARY_DIR}")
else()
    message(STATUS "QUANTIS_LIB_DIR: ${QUANTIS_LIB_DIR}")
    message(STATUS "Quantis Library: ${QUANTIS_LIBRARY}")
endif()

add_library(${TARGET} SHARED quantis_qrng_provider.c quantis_qrng_provider_rand.c)
target_link_libraries(${TARGET} PRIVATE OpenSSL::Crypto ${QUANTIS_LIBRARY})
install(TARGETS ${TARGET} LIBRARY DESTINATION lib)

set(CPACK_PACKAGE_VENDOR "QURSA project, Telematics Engineering Department, GAST Group, UC3M")
set(CPACK_PACKAGE_VERSION ${project_VERSION})
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "QURSA project, Telematics Engineering Department, GAST Group, UC3M")
include(CPack)