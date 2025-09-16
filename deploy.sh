#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${1:-default}"
RELEASE_NAME="${2:-fluxcd-helm-upgrader}"

helm upgrade -i "$RELEASE_NAME" ./helm/fluxcd-helm-upgrader -n "$NAMESPACE" --create-namespace
