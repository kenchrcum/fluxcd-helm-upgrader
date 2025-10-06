#!/usr/bin/env bash
set -euo pipefail

IMAGE="kenchrcum/fluxcd-helm-upgrader:${1:-latest}"

docker build -t "$IMAGE" .

echo "Built $IMAGE"
