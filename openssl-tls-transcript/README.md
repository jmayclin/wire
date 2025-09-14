# OpenSSL TLS Transcript Generator

This tool captures the raw bytes of OpenSSL client hello messages from multiple OpenSSL versions and dumps them to binary files. The implementation uses CMake's ExternalProject functionality to provision OpenSSL, avoiding the use of system libcrypto/openssl.

## Supported OpenSSL Versions

The tool generates client hello messages for three different OpenSSL versions:

1. **OpenSSL 1.0.2** (specifically 1.0.2u, the last release in the 1.0.2 series)
2. **OpenSSL 1.1.1** (specifically 1.1.1w)
3. **OpenSSL 3.x** (specifically 3.1.0)

## Requirements

- CMake (version 3.10 or higher)
- C compiler (gcc or clang)
- Make
- Standard build tools (typically provided by packages like build-essential on Debian/Ubuntu)

## Quick Start

The easiest way to generate all client hello binaries is to use the provided script:

```bash
# Make the script executable (if not already)
chmod +x generate_all.sh

# Run the script to build and generate all client hello binaries
./generate_all.sh
```

This will:
1. Configure and build all three OpenSSL versions
2. Generate client hello binaries for each version
3. Save the binaries to their respective directories

## Manual Building

If you prefer to build manually or only need a specific OpenSSL version:

```bash
cmake -B build .
cmake --build build --parallel

# Run the specific executable
./client_hello_1_0_2         # Generate OpenSSL 1.0.2 client hello
./client_hello_1_1_1         # Generate OpenSSL 1.1.1 client hello
./client_hello_3             # Generate OpenSSL 3.x client hello
```

## Output Files

The client hello binaries are saved to:

- `resources/openssl_1_0_2/client_hello.bin` - OpenSSL 1.0.2 client hello
- `resources/openssl_1_1_1/client_hello.bin` - OpenSSL 1.1.1 client hello
- `resources/openssl_3/client_hello.bin` - OpenSSL 3.x client hello

## Implementation Details

### Project Structure

```
openssl-tls-transcript/
├── CMakeLists.txt        # CMake configuration for all OpenSSL versions
├── client_hello.c        # Main C implementation with version-specific code
├── generate_all.sh       # Script to build and run all versions
├── resources/            # Output directory for client hello binaries
│   ├── openssl_1_0_2/    # OpenSSL 1.0.2 output
│   ├── openssl_1_1_1/    # OpenSSL 1.1.1 output
│   └── openssl_3/        # OpenSSL 3.x output
└── README.md            # This file
```

### How It Works

The implementation:

1. Uses CMake's ExternalProject to download and build each OpenSSL version
2. Creates a separate executable for each version, linked against its respective OpenSSL library
3. Uses preprocessor directives to handle API differences between OpenSSL versions
4. Creates a pair of connected BIOs to simulate a network connection
5. Initiates (but does not complete) a TLS handshake
6. Captures the raw client hello message from the BIO
7. Writes the captured bytes to version-specific output files

### Build Time Considerations

Building all three OpenSSL versions can take significant time, especially on slower systems. The first build will be the longest as it needs to download and compile all three OpenSSL versions.

By default, the build will use all available CPU cores to speed up compilation. If you want to limit the number of cores used, you can set the `CMAKE_BUILD_PARALLEL_LEVEL` environment variable before running the build:

```bash
# Limit to 4 cores
export CMAKE_BUILD_PARALLEL_LEVEL=4
./generate_all.sh

# Or for manual building
export CMAKE_BUILD_PARALLEL_LEVEL=4
cmake --build build/
```

## Notes

- The handshake is intentionally not completed since we only need to capture the client hello message.
- The raw bytes include the TLS record layer header, which will be handled by the Rust side.
- OpenSSL is built statically to avoid dependencies on the system's OpenSSL installation.
- Each client hello will have different characteristics based on the OpenSSL version used.
