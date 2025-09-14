#!/bin/bash

# Script to generate TLS client hello messages for multiple Java versions using Podman

# Set the Java versions to test
JAVA_VERSIONS=("8" "11" "17" "21")

# Get the absolute path to the project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"  # Parent directory of the script directory
JAVA_TLS_DIR="$SCRIPT_DIR"  # The java-tls-transcript directory

echo "=== TLS Client Hello Generation for Multiple Java Versions ==="
echo "Project directory: $PROJECT_DIR"
echo ""

# Create resources directory if it doesn't exist
mkdir -p "$JAVA_TLS_DIR/resources"

# Function to run for a specific Java version
run_for_version() {
    local java_version=$1
    
    echo "=== Generating client hello for Java $java_version ==="
    
    # Create version-specific directory
    mkdir -p "$JAVA_TLS_DIR/resources/$java_version"
    
    # Determine the appropriate Docker image based on Java version
    local docker_image="docker.io/eclipse-temurin:$java_version-jdk"
    
    # Run the Java program in the container
    # Mount the project directory to /app in the container
    podman run --rm \
        -v "$PROJECT_DIR:/app:Z" \
        "$docker_image" \
        bash -c "cd /app/java-tls-transcript && mkdir -p resources/$java_version && javac src/main/java/ClientHelloGenerator.java && java -cp src/main/java ClientHelloGenerator"
    
    # Check if the client hello was generated
    if [ -f "$JAVA_TLS_DIR/resources/$java_version/client_hello.bin" ]; then
        echo "✅ Client hello generated successfully for Java $java_version"
        echo "📁 Saved to $JAVA_TLS_DIR/resources/$java_version/client_hello.bin"
    else
        echo "❌ Failed to generate client hello for Java $java_version"
    fi
    
    echo ""
}

# Main execution
echo "Will generate client hello messages for the following Java versions: ${JAVA_VERSIONS[*]}"
echo ""

# Run for each Java version
for version in "${JAVA_VERSIONS[@]}"; do
    run_for_version "$version"
done

echo "=== All client hello messages generated ==="
