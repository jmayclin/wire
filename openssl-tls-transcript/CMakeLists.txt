cmake_minimum_required(VERSION 3.10)
project(openssl_tls_transcript C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(ExternalProject)

# Set download extract timestamp policy to avoid warnings
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

# Create resources directories
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/resources/openssl_1_0_2)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/resources/openssl_1_1_1)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/resources/openssl_3_0)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/resources/openssl_3_5)

# OpenSSL 1.0.2 (last version was 1.0.2u)
set(OPENSSL_1_0_2_PREFIX ${CMAKE_BINARY_DIR}/openssl_1_0_2)
set(OPENSSL_1_0_2_INCLUDE_DIR ${OPENSSL_1_0_2_PREFIX}/include)
set(OPENSSL_1_0_2_LIBRARY_DIR ${OPENSSL_1_0_2_PREFIX}/lib)

ExternalProject_Add(
    openssl_1_0_2_external
    URL https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz
    PREFIX ${OPENSSL_1_0_2_PREFIX}
    CONFIGURE_COMMAND <SOURCE_DIR>/config --prefix=${OPENSSL_1_0_2_PREFIX} --openssldir=${OPENSSL_1_0_2_PREFIX} no-shared
    BUILD_COMMAND make
    INSTALL_COMMAND make install_sw
    BUILD_IN_SOURCE 1
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# OpenSSL 1.1.1 (using 1.1.1w)
set(OPENSSL_1_1_1_PREFIX ${CMAKE_BINARY_DIR}/openssl_1_1_1)
set(OPENSSL_1_1_1_INCLUDE_DIR ${OPENSSL_1_1_1_PREFIX}/include)
set(OPENSSL_1_1_1_LIBRARY_DIR ${OPENSSL_1_1_1_PREFIX}/lib)

ExternalProject_Add(
    openssl_1_1_1_external
    URL https://www.openssl.org/source/openssl-1.1.1w.tar.gz
    PREFIX ${OPENSSL_1_1_1_PREFIX}
    CONFIGURE_COMMAND <SOURCE_DIR>/config --prefix=${OPENSSL_1_1_1_PREFIX} --openssldir=${OPENSSL_1_1_1_PREFIX} no-shared
    BUILD_COMMAND make
    INSTALL_COMMAND make install_sw
    BUILD_IN_SOURCE 1
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# OpenSSL 3.0 (using 3.0.0)
set(OPENSSL_3_0_PREFIX ${CMAKE_BINARY_DIR}/openssl_3_0)
set(OPENSSL_3_0_INCLUDE_DIR ${OPENSSL_3_0_PREFIX}/include)
set(OPENSSL_3_0_LIBRARY_DIR ${OPENSSL_3_0_PREFIX}/lib)

ExternalProject_Add(
    openssl_3_0_external
    URL https://www.openssl.org/source/openssl-3.0.17.tar.gz
    PREFIX ${OPENSSL_3_0_PREFIX}
    CONFIGURE_COMMAND <SOURCE_DIR>/config --prefix=${OPENSSL_3_0_PREFIX} --openssldir=${OPENSSL_3_0_PREFIX} no-shared
    BUILD_COMMAND make
    INSTALL_COMMAND make install_sw
    BUILD_IN_SOURCE 1
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# OpenSSL 3.5 (using 3.0.0)
set(OPENSSL_3_5_PREFIX ${CMAKE_BINARY_DIR}/openssl_3_5)
set(OPENSSL_3_5_INCLUDE_DIR ${OPENSSL_3_5_PREFIX}/include)
set(OPENSSL_3_5_LIBRARY_DIR ${OPENSSL_3_5_PREFIX}/lib)

ExternalProject_Add(
    openssl_3_5_external
    URL https://www.openssl.org/source/openssl-3.5.2.tar.gz
    PREFIX ${OPENSSL_3_5_PREFIX}
    CONFIGURE_COMMAND <SOURCE_DIR>/config --prefix=${OPENSSL_3_5_PREFIX} --openssldir=${OPENSSL_3_5_PREFIX} no-shared
    BUILD_COMMAND make
    INSTALL_COMMAND make install_sw
    BUILD_IN_SOURCE 1
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# Create imported targets for OpenSSL 1.0.2 libraries
add_library(ssl_1_0_2 STATIC IMPORTED)
add_library(crypto_1_0_2 STATIC IMPORTED)

set_property(TARGET ssl_1_0_2 PROPERTY IMPORTED_LOCATION ${OPENSSL_1_0_2_LIBRARY_DIR}/libssl.a)
set_property(TARGET crypto_1_0_2 PROPERTY IMPORTED_LOCATION ${OPENSSL_1_0_2_LIBRARY_DIR}/libcrypto.a)

add_dependencies(ssl_1_0_2 openssl_1_0_2_external)
add_dependencies(crypto_1_0_2 openssl_1_0_2_external)

# Create imported targets for OpenSSL 1.1.1 libraries
add_library(ssl_1_1_1 STATIC IMPORTED)
add_library(crypto_1_1_1 STATIC IMPORTED)

set_property(TARGET ssl_1_1_1 PROPERTY IMPORTED_LOCATION ${OPENSSL_1_1_1_LIBRARY_DIR}/libssl.a)
set_property(TARGET crypto_1_1_1 PROPERTY IMPORTED_LOCATION ${OPENSSL_1_1_1_LIBRARY_DIR}/libcrypto.a)

add_dependencies(ssl_1_1_1 openssl_1_1_1_external)
add_dependencies(crypto_1_1_1 openssl_1_1_1_external)

# Create imported targets for OpenSSL 3.0 libraries
add_library(ssl_3_0 STATIC IMPORTED)
add_library(crypto_3_0 STATIC IMPORTED)

set_property(TARGET ssl_3_0 PROPERTY IMPORTED_LOCATION ${OPENSSL_3_0_LIBRARY_DIR}/libssl.a)
set_property(TARGET crypto_3_0 PROPERTY IMPORTED_LOCATION ${OPENSSL_3_0_LIBRARY_DIR}/libcrypto.a)

add_dependencies(ssl_3_0 openssl_3_0_external)
add_dependencies(crypto_3_0 openssl_3_0_external)

# Create imported targets for OpenSSL 3.5 libraries
add_library(ssl_3_5 STATIC IMPORTED)
add_library(crypto_3_5 STATIC IMPORTED)

set_property(TARGET ssl_3_5 PROPERTY IMPORTED_LOCATION ${OPENSSL_3_5_LIBRARY_DIR}/libssl.a)
set_property(TARGET crypto_3_5 PROPERTY IMPORTED_LOCATION ${OPENSSL_3_5_LIBRARY_DIR}/libcrypto.a)

add_dependencies(ssl_3_5 openssl_3_5_external)
add_dependencies(crypto_3_5 openssl_3_5_external)

# Create executables for each OpenSSL version
add_executable(client_hello_1_0_2 client_hello.c)
add_executable(client_hello_1_1_1 client_hello.c)
add_executable(client_hello_3_0 client_hello.c)
add_executable(client_hello_3_5 client_hello.c)

# Configure OpenSSL 1.0.2 executable
target_include_directories(client_hello_1_0_2 PRIVATE ${OPENSSL_1_0_2_INCLUDE_DIR})
target_compile_definitions(client_hello_1_0_2 PRIVATE OPENSSL_1_0_2)
target_link_libraries(client_hello_1_0_2 ssl_1_0_2 crypto_1_0_2)
add_dependencies(client_hello_1_0_2 openssl_1_0_2_external)

# Configure OpenSSL 1.1.1 executable
target_include_directories(client_hello_1_1_1 PRIVATE ${OPENSSL_1_1_1_INCLUDE_DIR})
target_compile_definitions(client_hello_1_1_1 PRIVATE OPENSSL_1_1_1)
target_link_libraries(client_hello_1_1_1 ssl_1_1_1 crypto_1_1_1)
add_dependencies(client_hello_1_1_1 openssl_1_1_1_external)

# Configure OpenSSL 3.0 executable
target_include_directories(client_hello_3_0 PRIVATE ${OPENSSL_3_0_INCLUDE_DIR})
target_compile_definitions(client_hello_3_0 PRIVATE OPENSSL_3_0)
target_link_libraries(client_hello_3_0 ssl_3_0 crypto_3_0)
add_dependencies(client_hello_3_0 openssl_3_0_external)

# Configure OpenSSL 3.5 executable
target_include_directories(client_hello_3_5 PRIVATE ${OPENSSL_3_5_INCLUDE_DIR})
target_compile_definitions(client_hello_3_5 PRIVATE OPENSSL_3_5)
target_link_libraries(client_hello_3_5 ssl_3_5 crypto_3_5)
add_dependencies(client_hello_3_5 openssl_3_5_external)

# On Unix-like systems, we may need additional libraries
if(UNIX)
    target_link_libraries(client_hello_1_0_2 dl pthread)
    target_link_libraries(client_hello_1_1_1 dl pthread)
    target_link_libraries(client_hello_3_0 dl pthread)
    target_link_libraries(client_hello_3_5 dl pthread)
endif()
