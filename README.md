# FluxCD Helm Upgrader

A Kubernetes application that automatically detects and reports Helm chart updates for FluxCD `HelmRelease` objects, helping you stay current with upstream chart versions.

## Overview

This project provides automated monitoring of Helm chart versions used in your FluxCD-managed Kubernetes clusters. The upgrader periodically scans all `HelmRelease` objects, resolves their associated `HelmChart` and `HelmRepository` resources, and checks for newer versions of the charts in their upstream repositories.

When updates are available, it provides clear logging with the exact manifest file paths that need to be modified, making it easy to keep your deployments up-to-date.

## Architecture

- **Upgrader Application**: Python application that monitors Kubernetes HelmRelease objects
- **Docker Container**: Optimized Alpine-based container with SSH support
- **Kubernetes Deployment**: Includes RBAC, health checks, and security best practices
- **Helm Chart**: Easy deployment and configuration management

## Quick Start

### Prerequisites

- Kubernetes cluster with FluxCD installed
- Helm 3.x
- SSH deploy key for private Git repositories (optional, for private repos)

### 1. Deploy with Helm (Recommended)

The easiest way to deploy the FluxCD Helm Upgrader is using Helm:

#### From Public Helm Repository

```bash
# Add the public Helm repository
helm repo add fluxcd-helm-upgrader https://kenchrcum.github.io/fluxcd-helm-upgrader/

# Update your local Helm chart repository cache
helm repo update

# Install the chart
helm install fluxcd-helm-upgrader fluxcd-helm-upgrader/fluxcd-helm-upgrader
```

#### From Local Directory (Development)

```bash
# Install the chart from local directory
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader
```

#### With Repository Configuration

```bash
# Install with repository scanning enabled
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set repo.url=https://github.com/your-org/flux-infra.git \
  --set repo.sshKeySecret.enabled=true \
  --set repo.sshKeySecret.name=fluxcd-helm-upgrader-ssh
```

### 2. Alternative: Build and Deploy Docker Image

If you prefer to build your own Docker image:

```bash
# Build the image
docker build -t your-registry/fluxcd-helm-upgrader:latest .

# Push to your registry
docker push your-registry/fluxcd-helm-upgrader:latest

# Then deploy using Helm with your custom image
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set image.repository=your-registry/fluxcd-helm-upgrader \
  --set image.tag=latest
```

### 3. Configure Repository Scanning

You can configure the upgrader to scan a Git repository for HelmRelease manifests:

#### Basic Repository Configuration

```yaml
repo:
  url: https://github.com/your-org/flux-infra.git
  branch: main
  searchPattern: "/components/{namespace}/*/helmrelease*.y*ml"
  cloneDir: /tmp/fluxcd-repo
```

#### With SSH Key Authentication (Required for Private Repositories)

```yaml
repo:
  url: https://github.com/your-org/flux-infra.git
  branch: main
  searchPattern: "/components/{namespace}/*/helmrelease*.y*ml"
  cloneDir: /tmp/fluxcd-repo
  sshKeySecret:
    enabled: true
    name: fluxcd-helm-upgrader-ssh
    privateKey: id_rsa
    publicKey: id_rsa.pub
    knownHosts: known_hosts
```

### 4. Create SSH Key Secret

For private repositories, you'll need to create an SSH key secret:

```bash
# Create the SSH key secret from your deploy key
kubectl create secret generic fluxcd-helm-upgrader-ssh \
  --from-file=id_rsa=/path/to/your/deploy-key \
  --from-file=id_rsa.pub=/path/to/your/deploy-key.pub \
  --from-literal=known_hosts="github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
```

### 5. Verify Operation

The upgrader will automatically start monitoring HelmReleases:

```bash
# Check deployment status
kubectl get pods -l app.kubernetes.io/name=fluxcd-helm-upgrader

# View logs
kubectl logs -l app.kubernetes.io/name=fluxcd-helm-upgrader
```

**Expected Output:**
```
🚀 Starting FluxCD Helm upgrader (interval: 300s)
📂 Repository: https://github.com/your-org/flux-infra
🔑 SSH Keys: /home/kenneth/.ssh/fluxcd-helm-upgrader, /home/kenneth/.ssh/fluxcd-helm-upgrader.pub

🔄 Starting new check cycle...
📈 Update available: authentik/authentik (2025.8.1 -> 2025.8.3)
📄 authentik/authentik -> components/authentik/your-cluster/helmrelease-authentik.yaml
✅ Check cycle completed
⏰ Sleeping for 300 seconds...
```

## Project Structure

```
.
├── main.py                             # Main upgrader application
├── requirements.txt                    # Python dependencies
├── Dockerfile                          # Alpine-based container build
├── .dockerignore                       # Docker build exclusions
├── .gitignore                          # Git ignore patterns
├── k8s/                                # Raw Kubernetes manifests
│   ├── rbac.yaml                       # Cluster-wide RBAC configuration
│   └── deployment.yaml                 # Deployment manifest
├── helm/                               # Helm chart
│   └── fluxcd-helm-upgrader/
│       ├── Chart.yaml                  # Helm chart metadata
│       ├── values.yaml                 # Default configuration values
│       ├── charts/                     # Chart dependencies (empty)
│       ├── templates/                  # Kubernetes resource templates
│       │   ├── _helpers.tpl            # Helm template helpers
│       │   ├── serviceaccount.yaml     # Service account template
│       │   ├── clusterrole.yaml        # Cluster role template
│       │   ├── clusterrolebinding.yaml # Cluster role binding template
│       │   ├── role.yaml               # Namespaced role template
│       │   ├── rolebinding.yaml        # Namespaced role binding template
│       │   └── deployment.yaml         # Deployment template
│       └── README.md                   # Helm chart documentation
├── examples/                           # Sample configurations
│   └── sample-values.yaml              # Sample Helm values
├── build.sh                           # Build script for Docker images
└── deploy.sh                         # Deployment script
```

## Configuration

### Helm Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Docker image repository | `ghcr.io/kenchrcum/fluxcd-helm-upgrader` |
| `image.tag` | Docker image tag | `0.1.1` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of replicas | `1` |
| `repo.url` | Git repository URL to scan for manifests | `""` |
| `repo.branch` | Git branch to scan | `""` |
| `repo.searchPattern` | Glob pattern for finding HelmRelease manifests | `/components/{namespace}/*/helmrelease*.y*ml` |
| `repo.cloneDir` | Local directory for repository cloning | `/tmp/fluxcd-repo` |
| `repo.sshKeySecret.enabled` | Enable SSH key authentication | `false` |
| `repo.sshKeySecret.name` | Name of the SSH key secret | `""` |
| `repo.sshKeySecret.privateKey` | Key name for private key in secret | `id_rsa` |
| `repo.sshKeySecret.publicKey` | Key name for public key in secret | `id_rsa.pub` |
| `repo.sshKeySecret.knownHosts` | Key name for known_hosts in secret | `known_hosts` |
| `logLevel` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `intervalSeconds` | Check interval in seconds | `300` |
| `includePrerelease` | Include pre-release versions in checks | `false` |
| `resources.limits.cpu` | CPU limit | `200m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `50m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `rbac.create` | Create RBAC resources | `true` |
| `rbac.clusterWide` | Create cluster-wide RBAC | `true` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.name` | Service account name | `""` |
| `nodeSelector` | Node labels for pod assignment | `{}` |
| `tolerations` | Tolerations for pod assignment | `[]` |
| `affinity` | Affinity rules for pod assignment | `{}` |
| `podLabels` | Additional labels for pods | `{}` |
| `podAnnotations` | Additional annotations for pods | `{}` |

### Environment Variables

- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR) (default: INFO)
- `INTERVAL_SECONDS`: Check interval in seconds (default: 300)
- `INCLUDE_PRERELEASE`: Include pre-release versions in checks (default: false)
- `REPO_URL`: Git repository URL to scan for manifests
- `REPO_BRANCH`: Git branch to scan (optional)
- `REPO_SEARCH_PATTERN`: Glob pattern for finding HelmRelease manifests
- `REPO_CLONE_DIR`: Local directory for repository cloning
- `SSH_PRIVATE_KEY_PATH`: Path to SSH private key file
- `SSH_PUBLIC_KEY_PATH`: Path to SSH public key file
- `SSH_KNOWN_HOSTS_PATH`: Path to SSH known_hosts file

## Development

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally (requires kubeconfig)
python main.py

# Or run with custom kubeconfig
KUBECONFIG=~/.kube/config python main.py

# Run with environment variables
REPO_URL=https://github.com/your-org/repo \
SSH_PRIVATE_KEY_PATH=/path/to/private/key \
SSH_PUBLIC_KEY_PATH=/path/to/public/key \
python main.py
```

### Building for Production

```bash
# Build Docker image
docker build -t ghcr.io/kenchrcum/fluxcd-helm-upgrader:latest .

# Push to registry
docker push ghcr.io/kenchrcum/fluxcd-helm-upgrader:latest

# Or use the provided build script
./build.sh                                    # Build only
TAG=v1.0.0 ./build.sh                         # Build with specific tag
```

## CI/CD

This project includes GitHub Actions workflows for automated testing and deployment.

### Workflows

#### Build and Test (`build.yml`)
Builds and tests the Docker image on every push:

- **Triggers**: Changes to `main.py`, `Dockerfile`, `requirements.txt`
- **Features**:
  - Docker image building
  - Basic validation tests
  - Registry push on main branch

## Security

The application follows Kubernetes security best practices:

- Non-root user execution (user ID 1001)
- Read-only root filesystem
- Minimal RBAC permissions
- Resource limits and requests
- SSH key-based authentication for private repositories

## Troubleshooting

### Check Logs

```bash
# Get deployment logs
kubectl logs -l app.kubernetes.io/name=fluxcd-helm-upgrader

# Check pod status
kubectl get pods -l app.kubernetes.io/name=fluxcd-helm-upgrader
```

### Common Issues

1. **SSH Key Permissions**: Ensure SSH keys have correct permissions (600 for private key)
2. **Repository Access**: Verify SSH key has read access to the repository
3. **RBAC Permissions**: Ensure the service account can read HelmRelease and related resources
4. **Image Pull**: Verify the Docker image is accessible from your cluster
5. **Repository URL**: Ensure the repository URL is accessible and correct

### Debug Mode

Enable debug logging to see more detailed information:

```yaml
logLevel: DEBUG
```

This will show manifest paths for all HelmReleases, not just those with updates.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
