#!/usr/bin/env bash
set -euo pipefail

IMAGE="ghcr.io/kenchrcum/fluxcd-helm-upgrader:${1:-latest}"

docker build -t "$IMAGE" .

echo "Built $IMAGE"
