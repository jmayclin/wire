#!/bin/bash

# generate_go_artifacts.sh
# Script to generate TLS artifacts for multiple Go versions using Podman

# Set the Go versions to test
# Currently we only support 1.16 -> 1.25, because we rely on os.ReadFile which was 
# only added in 1.16 https://pkg.go.dev/os#ReadFile
GO_VERSIONS=("1.16" "1.17" "1.18" "1.19" "1.20" "1.21" "1.22" "1.23" "1.24" "1.25")

# Get the absolute path to the project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"  # Parent directory of the script directory
GO_TLS_DIR="$SCRIPT_DIR"  # The go-tls-transcript directory

echo "=== TLS Artifact Generation for Multiple Go Versions ==="
echo "Project directory: $PROJECT_DIR"
echo ""

# Create a results directory to track the run
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="$GO_TLS_DIR/multi_version_results_$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

# Function to run tests for a specific Go version
run_tests_for_version() {
    local go_version=$1
    
    echo "=== Generating artifacts for Go $go_version ==="
    
    # Run the tests in the container
    # Mount the project directory to /app in the container
    # We need to mount the whole project directory because it contains the certs
    
    # For Go versions 1.21 and above, run go mod tidy with -go flag to update the Go version
    if [[ $(echo "$go_version >= 1.21" | bc -l) -eq 1 ]]; then
        echo "Go version $go_version >= 1.21, running go mod tidy -go=$go_version"
        podman run --rm \
            -v "$PROJECT_DIR:/app:Z" \
            "docker.io/golang:$go_version" \
            bash -c "cd /app/go-tls-transcript && go mod tidy -go=$go_version && go test -v"
    else
        echo "Go version $go_version < 1.21, skipping go mod tidy"
        podman run --rm \
            -v "$PROJECT_DIR:/app:Z" \
            "docker.io/golang:$go_version" \
            bash -c "cd /app/go-tls-transcript && go test -v"
    fi
    
    # Check if the tests were successful
    if [ $? -eq 0 ]; then
        echo "✅ Tests completed successfully for Go $go_version"
        
        # Copy the generated artifacts to the results directory for safekeeping
        mkdir -p "$RESULTS_DIR/go$go_version"
        cp -r "$GO_TLS_DIR/resources/go$go_version"/* "$RESULTS_DIR/go$go_version/" 2>/dev/null || true
        echo "📁 Artifacts copied to $RESULTS_DIR/go$go_version/"
    else
        echo "❌ Tests failed for Go $go_version"
    fi
    
    echo ""
}

# Main execution
echo "Will generate artifacts for the following Go versions: ${GO_VERSIONS[*]}"
echo "Results will be saved to: $RESULTS_DIR"
echo ""

# Run tests for each Go version
for version in "${GO_VERSIONS[@]}"; do
    run_tests_for_version "$version"
done
