# fluxcd-helm-upgrader

A small Kubernetes app that runs in-cluster (FluxCD-managed) and periodically scans Flux `HelmRelease` objects. For each release, it resolves the associated `HelmChart` and `HelmRepository`, checks the upstream chart index for the chart’s latest version, and logs when a newer chart version is available than the one currently running.

This repo mirrors the structure and deployment style of [`grafana-dashboard-converter`](https://github.com/kenchrcum/grafana-dashboard-converter).

## Features
- Detects newer Helm chart versions for FluxCD `HelmRelease`s
- Handles multiple CRD versions for compatibility (`v2`, `v2beta2`, `v2beta1` for HelmRelease; `v1`, `v1beta2`, `v1beta1` for sources)
- Works in-cluster and with local kubeconfig
- Helm chart with RBAC and raw k8s manifests

## Configuration
Environment variables:
- `LOG_LEVEL` (default `INFO`)
- `INTERVAL_SECONDS` (default `300`)
- `INCLUDE_PRERELEASE` (default `false`)

## Build
```bash
./build.sh              # builds ghcr.io/kenchrcum/fluxcd-helm-upgrader:latest
```

## Run locally
Assuming kubeconfig is configured:
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Install via Helm
```bash
./deploy.sh default fluxcd-helm-upgrader
# or with values
helm upgrade -i fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader -n default -f ./examples/sample-values.yaml
```

## Raw manifests
```bash
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/deployment.yaml
```

## Notes
- OCI HelmRepository types are currently skipped.
- Creating PRs/merges to bump versions is out of scope for now, but the code is structured to extend later.
