/**
 * client_hello.c - Captures raw bytes of an OpenSSL client hello message
 * 
 * This program initializes an OpenSSL client, begins a TLS handshake,
 * captures the raw client hello message, and writes it to client_hello.bin.
 * 
 * Supports multiple OpenSSL versions:
 * - OpenSSL 1.0.2 (compile with -DOPENSSL_1_0_2)
 * - OpenSSL 1.1.1 (compile with -DOPENSSL_1_1_1)
 * - OpenSSL 3.x (compile with -DOPENSSL_3)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// Version-specific output directories
#if defined(OPENSSL_1_0_2)
    #define VERSION_STR "1.0.2"
    #define OUTPUT_DIR "resources/openssl_1_0_2"
#elif defined(OPENSSL_1_1_1)
    #define VERSION_STR "1.1.1"
    #define OUTPUT_DIR "resources/openssl_1_1_1"
#elif defined(OPENSSL_3_0)
    #define VERSION_STR "3.1"
    #define OUTPUT_DIR "resources/openssl_3_0"
#else
    #define VERSION_STR "3.5"
    #define OUTPUT_DIR "resources/openssl_3_5"
#endif

// Error handling helper function
void handle_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Hex dump function for debugging
void hex_dump(const unsigned char *data, size_t len) {
    printf("Data length: %zu bytes\n", len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    if (len % 16 != 0) {
        printf("\n");
    }
}

// Write buffer to file
void write_to_file(const char *filename, const unsigned char *data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("Failed to open output file");
        exit(EXIT_FAILURE);
    }
    
    if (fwrite(data, 1, len, f) != len) {
        perror("Failed to write data to file");
        fclose(f);
        exit(EXIT_FAILURE);
    }
    
    fclose(f);
    printf("Successfully wrote %zu bytes to %s\n", len, filename);
}

// Initialize OpenSSL libraries
void initialize_openssl(void) {
    printf("Initializing OpenSSL %s...\n", VERSION_STR);
    
#if defined(OPENSSL_1_0_2) || defined(OPENSSL_1_1_1)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#else
    // OpenSSL 3.x initialization
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) == 0) {
        handle_error("Failed to initialize OpenSSL");
    }
#endif
    
    printf("OpenSSL initialized\n");
}

// Clean up OpenSSL resources
void cleanup_openssl(void) {
#if defined(OPENSSL_1_0_2) || defined(OPENSSL_1_1_1)
    EVP_cleanup();
    ERR_free_strings();
#endif
    // OpenSSL 3.x automatically cleans up at program exit
}

int main(int argc, char *argv[]) {
    printf("Starting OpenSSL %s client hello capture...\n", VERSION_STR);
    
    // Initialize OpenSSL
    initialize_openssl();
    
    // Create SSL context
#if defined(OPENSSL_1_0_2)
    const SSL_METHOD *method = TLSv1_2_client_method();
#else
    // OpenSSL 1.1.1 and 3.x can use TLS_client_method()
    const SSL_METHOD *method = TLS_client_method();
#endif

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_error("Failed to create SSL context");
    }
    
    printf("SSL context created\n");
    
    // Set TLS version (use TLS 1.2 or higher)
#if !defined(OPENSSL_1_0_2)
    // OpenSSL 1.1.1 and 3.x support this function
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        handle_error("Failed to set minimum TLS version");
    }
    printf("TLS version set to minimum TLS 1.2\n");
#else
    // OpenSSL 1.0.2 doesn't have SSL_CTX_set_min_proto_version
    // We're already using TLSv1_2_client_method() so no need to set it
    printf("Using TLS 1.2 client method\n");
#endif
    
    // Create a pair of connected BIOs to simulate network connection
    BIO *client_bio = NULL, *server_bio = NULL;
    if (BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) != 1) {
        handle_error("Failed to create BIO pair");
    }
    
    printf("BIO pair created\n");
    
    // Create SSL object
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        handle_error("Failed to create SSL object");
    }
    
    printf("SSL object created\n");
    
    // Set server name indication (SNI)
    if (!SSL_set_tlsext_host_name(ssl, "example.com")) {
        handle_error("Failed to set SNI");
    }
    
    printf("SNI set to example.com\n");
    
    // Connect SSL to client BIO
    SSL_set_connect_state(ssl);
    SSL_set_bio(ssl, client_bio, client_bio);
    
    printf("SSL connected to client BIO\n");
    
    // Begin handshake - this will write the client hello to the BIO
    printf("Starting SSL handshake...\n");
    int ret = SSL_do_handshake(ssl);
    
    // We expect the handshake to fail since we're not actually connecting to a server
    printf("SSL_do_handshake returned: %d\n", ret);
    
    // Get error code
    int err = SSL_get_error(ssl, ret);
    printf("SSL error code: %d\n", err);
    
    if (err != SSL_ERROR_WANT_READ) {
        // If the error is not SSL_ERROR_WANT_READ, something unexpected happened
        fprintf(stderr, "Unexpected error: %d\n", err);
        ERR_print_errors_fp(stderr);
    } else {
        printf("Got expected SSL_ERROR_WANT_READ\n");
    }
    
    // Read data from the server BIO (which contains the client hello)
    printf("Reading data from server BIO...\n");
    
    // Allocate a buffer for the client hello
    // TLS messages can be up to 16KB, but client hello is typically much smaller
    size_t buffer_size = 16384;
    unsigned char *buffer = malloc(buffer_size);
    if (!buffer) {
        handle_error("Memory allocation failed");
    }
    
    // Read from the server BIO (which contains what the client sent)
    int bytes_read = BIO_read(server_bio, buffer, buffer_size);
    
    if (bytes_read <= 0) {
        printf("BIO_read returned %d\n", bytes_read);
        handle_error("Failed to read client hello from BIO");
    }
    
    printf("Read %d bytes from server BIO\n", bytes_read);
    
    // Print the first few bytes for debugging
    printf("First 32 bytes (or fewer if message is shorter):\n");
    hex_dump(buffer, bytes_read < 32 ? bytes_read : 32);
    
    // Ensure output directory exists
    char output_path[256];
    snprintf(output_path, sizeof(output_path), "%s/client_hello.bin", OUTPUT_DIR);
    
    // Write the client hello to file
    write_to_file(output_path, buffer, bytes_read);
    
    // Clean up
    free(buffer);
    SSL_free(ssl);  // This also frees the client_bio
    BIO_free(server_bio);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    
    printf("Cleanup complete\n");
    
    return 0;
}
