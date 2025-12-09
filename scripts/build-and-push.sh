#!/bin/bash
set -e

# Build and push Docker image for Wasabi S3 Operator

IMAGE_NAME="kenchrcum/fluxcd-helm-upgrader"
VERSION="${1:-latest}"

echo "Building Docker image: ${IMAGE_NAME}:${VERSION}"

# Build the image
docker build -t "${IMAGE_NAME}:${VERSION}" .

# Tag as latest if not already
if [ "$VERSION" != "latest" ]; then
    docker tag "${IMAGE_NAME}:${VERSION}" "${IMAGE_NAME}:latest"
fi

echo "Build complete!"
echo ""
echo "Pushing image to Docker Hub: ${IMAGE_NAME}:${VERSION}"
docker push ${IMAGE_NAME}:${VERSION}
if [ "$VERSION" != "latest" ] && [ "$VERSION" != "dev" ]; then
    echo "Pushing image to Docker Hub: ${IMAGE_NAME}:latest"
    docker push ${IMAGE_NAME}:latest
fi

