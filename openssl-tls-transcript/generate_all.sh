#!/bin/bash
# Script to build and run all OpenSSL versions to generate client hello binaries

set -e  # Exit on error

echo "=== OpenSSL TLS Transcript Generator ==="
echo "This script will build and run client hello generators for OpenSSL 1.0.2, 1.1.1, and 3.x"
echo

# Create build directory if it doesn't exist
mkdir -p build
cd build

# Configure with CMake
echo "=== Configuring with CMake ==="
cmake ..

# Build all targets
echo
echo "=== Building all targets ==="
echo "This will take some time as it downloads and builds three OpenSSL versions..."
# Use all available cores for faster building
cmake --build . --parallel

# Create resources directories if they don't exist
cd ..
mkdir -p resources/openssl_1_0_2
mkdir -p resources/openssl_1_1_1
mkdir -p resources/openssl_3

# Run all client hello generators
echo
echo "=== Generating client hello for OpenSSL 1.0.2 ==="
build/client_hello_1_0_2

echo
echo "=== Generating client hello for OpenSSL 1.1.1 ==="
build/client_hello_1_1_1

echo
echo "=== Generating client hello for OpenSSL 3.x ==="
build/client_hello_3

echo
echo "=== All client hello binaries generated ==="
echo "Files are located in:"
echo "  - resources/openssl_1_0_2/client_hello.bin"
echo "  - resources/openssl_1_1_1/client_hello.bin"
echo "  - resources/openssl_3/client_hello.bin"
