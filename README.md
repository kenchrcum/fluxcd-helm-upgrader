# FluxCD Helm Upgrader

A Kubernetes application that automatically detects and reports Helm chart updates for FluxCD `HelmRelease` objects, helping you stay current with upstream chart versions.

## Overview

This project provides automated monitoring of Helm chart versions used in your FluxCD-managed Kubernetes clusters. The upgrader periodically scans all `HelmRelease` objects, resolves their associated `HelmChart` and `HelmRepository` resources, and checks for newer versions of the charts in their upstream repositories.

When updates are available, it provides clear logging with the exact manifest file paths that need to be modified, making it easy to keep your deployments up-to-date.

### GitHub Integration

The upgrader can automatically create GitHub Pull Requests when new versions are detected. When configured with a GitHub token and repository information, it will:

1. Create a new branch for the update
2. Update the HelmRelease manifest with the new version
3. Commit and push the changes to GitHub
4. Create a pull request with detailed information about the update

This feature enables automated, reviewable updates to your FluxCD manifests.

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

### 5. Configure GitHub Pull Request Creation (Optional)

To enable automatic GitHub Pull Request creation when updates are detected:

#### Create GitHub Token

1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Create a new token with the following **minimum required permissions**:
   - **Pull requests**: Read and write (to create and manage PRs)
   - **Contents**: Read (to read repository content and branches)
   - **Metadata**: Read (automatically included, for basic repository access)
3. For **classic tokens**, use the `repo` scope (includes all necessary permissions)
4. Store the token securely

**Note**: The "Not all refs are readable" error occurs when the token lacks **Contents (read)** permission.

#### GitHub Token Types

**Fine-grained Personal Access Tokens (Recommended):**
- More secure, repository-specific access
- Required permissions:
  - **Pull requests**: Read and write
  - **Contents**: Read
  - **Metadata**: Read (automatically included)

**Classic Personal Access Tokens:**
- Broader access scope
- Required permissions:
  - **repo**: Full control of private repositories (includes all necessary permissions)

#### Configure GitHub Integration

```yaml
# Add to your Helm values
github:
  token: "your-github-token-here"
  repository: "your-org/your-repo"  # Format: owner/repo
  defaultBranch: "main"             # Override if your repo uses a different default branch

# Git configuration for commits (optional)
git:
  userName: "fluxcd-helm-upgrader"           # Git user name for commits
  userEmail: "fluxcd-helm-upgrader@noreply.local"  # Git user email for commits

# Or set environment variables
env:
  - name: GITHUB_TOKEN
    value: "your-github-token-here"
  - name: GITHUB_REPOSITORY
    value: "your-org/your-repo"
  - name: GITHUB_DEFAULT_BRANCH
    value: "main"                           # Override if your repo uses a different default branch
  - name: GIT_USER_NAME
    value: "fluxcd-helm-upgrader"
  - name: GIT_USER_EMAIL
    value: "fluxcd-helm-upgrader@noreply.local"
```

#### Example Helm Install with GitHub PRs

```bash
# Install with GitHub PR creation enabled
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set repo.url=https://github.com/your-org/flux-infra.git \
  --set repo.sshKeySecret.enabled=true \
  --set repo.sshKeySecret.name=fluxcd-helm-upgrader-ssh \
  --set github.token=your-github-token \
  --set github.repository=your-org/flux-infra \
  --set git.userName="FluxCD Helm Upgrader" \
  --set git.userEmail="fluxcd-helm-upgrader@your-org.com"
```

**Note**: The SSH key used for repository access must also have push permissions to create branches and push commits.

### 6. Verify Operation

The upgrader will automatically start monitoring HelmReleases:

```bash
# Check deployment status
kubectl get pods -l app.kubernetes.io/name=fluxcd-helm-upgrader

# View logs
kubectl logs -l app.kubernetes.io/name=fluxcd-helm-upgrader
```

**Expected Output:**

**Fresh Run (New Branch):**
```
🚀 Starting FluxCD Helm upgrader (interval: 300s)
📂 Repository: https://github.com/your-org/flux-infra
🔑 SSH Keys: /home/kenneth/.ssh/fluxcd-helm-upgrader, /home/kenneth/.ssh/fluxcd-helm-upgrader.pub
🐙 GitHub PRs enabled for: your-org/flux-infra

🔄 Starting new check cycle...
📈 Update available: authentik/authentik (2025.8.1 -> 2025.8.3)
🔄 Processing GitHub PR creation for authentik/authentik
✅ Connected to GitHub as: flux-upgrader-bot
Creating new branch: update-authentik-authentik-2025-8-3
✅ Successfully created branch: update-authentik-authentik-2025-8-3
✅ Successfully updated manifest with version 2025.8.3
✅ Changes committed with message: Update authentik in namespace authentik from 2025.8.1 to 2025.8.3
✅ Successfully pushed branch: update-authentik-authentik-2025-8-3
✅ Head branch update-authentik-authentik-2025-8-3 is accessible
✅ Base branch main is accessible
🎉 Successfully created PR for authentik/authentik: https://github.com/your-org/flux-infra/pull/123
✅ Check cycle completed
⏰ Sleeping for 300 seconds...
```

**Existing Remote Branch:**
```
🚀 Starting FluxCD Helm upgrader (interval: 300s)
📂 Repository: https://github.com/your-org/flux-infra
🔑 SSH Keys: /home/kenneth/.ssh/fluxcd-helm-upgrader, /home/kenneth/.ssh/fluxcd-helm-upgrader.pub
🐙 GitHub PRs enabled for: your-org/flux-infra

🔄 Starting new check cycle...
📈 Update available: authentik/authentik (2025.8.1 -> 2025.8.3)
🔄 Processing GitHub PR creation for authentik/authentik
✅ Connected to GitHub as: flux-upgrader-bot
🔄 Remote branch update-authentik-authentik-2025-8-3 already exists, checking it out
✅ Checked out existing remote branch: update-authentik-authentik-2025-8-3
✅ Successfully updated manifest with version 2025.8.3 (preserving original formatting)
✅ Changes committed with message: Update authentik in namespace authentik from 2025.8.1 to 2025.8.3
🔄 Force pushing to existing remote branch update-authentik-authentik-2025-8-3 for latest commit reference
✅ Successfully pushed branch: update-authentik-authentik-2025-8-3
✅ Head branch update-authentik-authentik-2025-8-3 is accessible
✅ Base branch main is accessible
🎉 Successfully created PR for authentik/authentik: https://github.com/your-org/flux-infra/pull/123
✅ Check cycle completed
⏰ Sleeping for 300 seconds...
```

**Existing PR Example:**
```
🔄 Processing GitHub PR creation for harbor/harbor
🎯 PR already exists for harbor/harbor: https://github.com/your-org/flux-infra/pull/31
✅ Skipping file operations since PR is already created
```

**Already Up-to-Date Example:**
```
🔄 Processing GitHub PR creation for harbor/harbor
✅ Connected to GitHub as: flux-upgrader-bot
🔄 Remote branch update-harbor-harbor-1-18-0 already exists, checking it out
✅ Checked out existing remote branch: update-harbor-harbor-1-18-0
✅ Manifest already contains target version 1.18.0, no update needed
No changes to commit (manifest may already be up to date)
✅ Successfully pushed branch: update-harbor-harbor-1-18-0
✅ Head branch update-harbor-harbor-1-18-0 is accessible
✅ Base branch main is accessible
🎉 Successfully created PR for harbor/harbor: https://github.com/your-org/flux-infra/pull/123
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
| `image.tag` | Docker image tag | `0.2.0` |
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
| `github.token` | GitHub personal access token for PR creation | `""` |
| `github.repository` | GitHub repository in format 'owner/repo' | `""` |
| `github.defaultBranch` | Override default branch detection | `""` |
| `git.userName` | Git user name for commits | `fluxcd-helm-upgrader` |
| `git.userEmail` | Git user email for commits | `fluxcd-helm-upgrader@noreply.local` |
| `git.forcePush` | Force push existing branches | `false` |
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
- `GITHUB_TOKEN`: GitHub personal access token for PR creation
- `GITHUB_REPOSITORY`: GitHub repository in format 'owner/repo' for PR creation
- `GITHUB_DEFAULT_BRANCH`: Override the default branch detection (optional, defaults to auto-detection)
- `GIT_USER_NAME`: Git user name for commits (default: fluxcd-helm-upgrader)
- `GIT_USER_EMAIL`: Git user email for commits (default: fluxcd-helm-upgrader@noreply.local)
- `GIT_FORCE_PUSH`: Force push branches when they already exist (default: false)

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

### GitHub Integration Issues

1. **GitHub Token Permissions**: Ensure the token has the correct permissions:
   - **Fine-grained tokens**: Pull requests (read-write) + Contents (read) + Metadata (read)
   - **Classic tokens**: `repo` scope (includes all necessary permissions)
2. **"Not all refs are readable" Error**: This error occurs when the token lacks **Contents (read)** permission. Add this permission to your GitHub token.
3. **Repository Access**: Verify the token can access the repository and has push permissions
4. **Default Branch Detection**: If PR creation fails due to branch detection issues, set `GITHUB_DEFAULT_BRANCH=main` (or `master`)
5. **Repository Visibility**: For private repositories, ensure the token has access to private repositories

**Troubleshooting GitHub Token Issues:**

```bash
# Test token permissions (requires PyGitHub)
python -c "
from github import Github, Auth
g = Github(auth=Auth.Token('your-token-here'))
user = g.get_user()
print(f'User: {user.login}')
repo = g.get_repo('owner/repo')
print(f'Default branch: {repo.default_branch}')
print('✅ Token has basic access')
"
```

**Example with permission overrides:**
```bash
# If your repository uses 'master' as default branch
export GITHUB_DEFAULT_BRANCH=master
python main.py

# Or via Helm
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set github.defaultBranch=master
```

### Branch and PR Conflicts

1. **Existing Remote Branch**: If a remote branch already exists, the tool will checkout that branch and force push to ensure latest commit reference
2. **Existing PR**: If a PR already exists for the same update, the tool will skip creating a duplicate
3. **Local Branch Recovery**: If a branch exists locally but not on remote, the tool will switch to it and continue
4. **Force Push**: Set `GIT_FORCE_PUSH=true` to force push branches when conflicts occur (now automatic for existing remote branches)
5. **YAML Formatting**: Only the version field is updated - all other formatting, indentation, and quotes are preserved
6. **Already Up-to-Date**: If the manifest already contains the target version, the tool skips the update but still proceeds with PR creation if needed

**Example with force push:**
```bash
# Force push existing branches
export GIT_FORCE_PUSH=true
python main.py

# Or via Helm
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set git.forcePush=true
```

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