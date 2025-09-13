#!/bin/bash

GO_VERSION="1.25"

# Get the absolute path to the project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
# Mount the project directory to /app in the container
# We need to mount the whole project directory because it contains the certs
podman run --rm \
    -v "$PROJECT_DIR:/app:Z" \
    "docker.io/golang:$GO_VERSION" \
    bash -c "cd /app/go-tls-transcript && go test -v"
    
# Check if the tests were successful
if [ $? -eq 0 ]; then
    echo "✅ Tests completed successfully for Go $GO_VERSION"
else
    echo "❌ Tests failed for Go $GO_VERSION"
fi

echo ""
