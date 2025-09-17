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
 - `REPO_URL` (Flux repo to scan, e.g. `https://github.com/org/flux-infra.git`)
 - `REPO_BRANCH` (optional branch, default repo default)
 - `REPO_SEARCH_PATTERN` (glob with placeholders; default `/components/{namespace}/helmrelease*.y*ml`)
 - `REPO_CLONE_DIR` (default `/tmp/fluxcd-repo`)

### SSH Key Authentication (Required for Private Repositories)
For private repositories, SSH keys are required:
- `SSH_PRIVATE_KEY_PATH` (default `/etc/ssh-keys/private_key`)
- `SSH_PUBLIC_KEY_PATH` (default `/etc/ssh-keys/public_key`)
- `SSH_KNOWN_HOSTS_PATH` (default `/etc/ssh-keys/known_hosts`)

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

### Helm values for repo configuration

#### SSH Key Authentication (Required for Private Repositories)
```yaml
repo:
  url: https://github.com/your-org/flux-infra.git
  branch: main
  searchPattern: "/components/{namespace}/helmrelease*.y*ml"
  cloneDir: /tmp/fluxcd-repo
  sshKeySecret:
    enabled: true
    name: fluxcd-helm-upgrader-ssh
    privateKey: id_rsa
    publicKey: id_rsa.pub
    knownHosts: known_hosts
```

### Creating SSH Key Secret
```bash
# Create the SSH key secret from your deploy key
kubectl create secret generic fluxcd-helm-upgrader-ssh \
  --from-file=id_rsa=/path/to/your/deploy-key \
  --from-file=id_rsa.pub=/path/to/your/deploy-key.pub \
  --from-literal=known_hosts="github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
```


## Notes
- OCI HelmRepository types are currently skipped.
- Creating PRs/merges to bump versions is out of scope for now, but the code is structured to extend later.
 - When an update is detected and `repo.url` is configured, the app logs the relative manifest path to change (under repo root) based on `repo.searchPattern`.
