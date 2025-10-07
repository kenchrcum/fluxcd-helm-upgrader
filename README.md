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
  --from-literal=known_hosts="$(ssh-keyscan -t rsa github.com)"
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

First, create a secret containing your GitHub token:

```bash
kubectl create secret generic github-token \
  --from-literal=token="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -n flux-system
```

```yaml
# Add to your Helm values
github:
  tokenSecret:
    enabled: true
    name: "github-token"
    key: "token"
  repository: "your-org/your-repo"  # Format: owner/repo
  defaultBranch: "main"             # Override if your repo uses a different default branch

# Git configuration for commits (optional)
git:
  userName: "fluxcd-helm-upgrader"           # Git user name for commits
  userEmail: "fluxcd-helm-upgrader@noreply.local"  # Git user email for commits

# Or set environment variables
env:
  - name: GITHUB_TOKEN
    valueFrom:
      secretKeyRef:
        name: github-token
        key: token
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
  --set github.tokenSecret.enabled=true \
  --set github.tokenSecret.name=github-token \
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

## Deployment Modes

The FluxCD Helm Upgrader supports two deployment modes:

### Deployment Mode (Default)

In deployment mode, the upgrader runs continuously as a Kubernetes Deployment with a configurable interval between checks. This is the default mode and is suitable for most use cases.

```yaml
# values.yaml
mode: deployment
replicaCount: 1
intervalSeconds: 300  # Check every 5 minutes
```

### CronJob Mode

In CronJob mode, the upgrader runs as scheduled Kubernetes Jobs, which is more resource-efficient as pods are only created when needed. This mode is ideal for environments where:

- Resources are constrained
- Updates are needed less frequently
- You prefer scheduled execution over continuous monitoring

#### Using CronJob Mode with Helm

```bash
# Install with CronJob mode (runs every 6 hours)
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set mode=cronjob \
  --set cronjob.schedule="0 */6 * * *" \
  --set repo.url="git@github.com:your-org/flux-config.git" \
  --set github.tokenSecret.enabled=true \
  --set github.tokenSecret.name="github-token" \
  --set github.repository="your-org/flux-config"
```

#### CronJob Configuration Options

```yaml
# values.yaml
mode: cronjob

cronjob:
  # Schedule in cron format (every 6 hours at minute 0)
  schedule: "0 */6 * * *"
  
  # Concurrency policy: Forbid, Allow, or Replace
  concurrencyPolicy: Forbid
  
  # Job history limits
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
  
  # Deadlines and timeouts
  startingDeadlineSeconds: 300    # 5 minutes to start
  activeDeadlineSeconds: 3600     # 1 hour max execution
  
  # Retry configuration
  backoffLimit: 3                 # Retry up to 3 times
  
  # Optional: Suspend the cron job
  suspend: false
```

#### Using Standalone CronJob Manifest

For environments not using Helm, you can deploy the CronJob directly:

```bash
# Apply the standalone CronJob manifest
kubectl apply -f k8s/cronjob.yaml

# Don't forget to create the required secrets:
# 1. SSH key secret (if using private repositories)
kubectl create secret generic flux-ssh-key \
  --from-file=identity=/path/to/private/key \
  --from-file=identity.pub=/path/to/public/key \
  --from-file=known_hosts=/path/to/known_hosts \
  -n flux-system

# 2. GitHub token secret (if using GitHub integration)
kubectl create secret generic github-token \
  --from-literal=token=your-github-token \
  -n flux-system

## Complete Deployment Walkthrough

This section provides a complete end-to-end example of deploying FluxCD Helm Upgrader with a real-world scenario.

### Scenario: Monitor Helm Charts in a FluxCD Repository

Let's assume you have a FluxCD repository at `https://github.com/my-org/flux-infrastructure` that contains HelmRelease manifests in the following structure:

```
flux-infrastructure/
├── clusters/
│   └── production/
│       └── flux-system/
│           └── helmrelease.yaml
└── apps/
    ├── monitoring/
    │   └── helmrelease.yaml
    └── ingress/
        └── helmrelease.yaml
```

### Step 1: Prepare Secrets

```bash
# Create namespace for FluxCD Helm Upgrader
kubectl create namespace flux-system

# Generate SSH key for repository access (if private repo)
ssh-keygen -t rsa -b 4096 -C "fluxcd-helm-upgrader" -f ~/.ssh/fluxcd-helm-upgrader -N ""

# Add the public key to your repository's deploy keys
echo "Add this public key to your GitHub repository deploy keys:"
cat ~/.ssh/fluxcd-helm-upgrader.pub

# Create SSH secret
kubectl create secret generic fluxcd-helm-upgrader-ssh \
  --from-file=id_rsa=~/.ssh/fluxcd-helm-upgrader \
  --from-file=id_rsa.pub=~/.ssh/fluxcd-helm-upgrader.pub \
  --from-literal=known_hosts="$(ssh-keyscan -t rsa github.com)" \
  -n flux-system

# Create GitHub token (follow the GitHub token creation steps above)
kubectl create secret generic github-token \
  --from-literal=token="ghp_your_github_token_here" \
  -n flux-system
```

### Step 2: Deploy with Helm

```bash
# Deploy FluxCD Helm Upgrader with complete configuration
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --namespace flux-system \
  --create-namespace \
  --set repo.url=https://github.com/my-org/flux-infrastructure.git \
  --set repo.branch=main \
  --set repo.searchPattern="/clusters/*/flux-system/helmrelease*.yaml;/apps/*/*/helmrelease*.yaml" \
  --set repo.sshKeySecret.enabled=true \
  --set repo.sshKeySecret.name=fluxcd-helm-upgrader-ssh \
  --set github.tokenSecret.enabled=true \
  --set github.tokenSecret.name=github-token \
  --set github.repository=my-org/flux-infrastructure \
  --set git.userName="FluxCD Helm Upgrader Bot" \
  --set git.userEmail="fluxcd-helm-upgrader@my-org.com" \
  --set logLevel=INFO \
  --set intervalSeconds=600
```

### Step 3: Verify Deployment

```bash
# Check deployment status
kubectl get pods -n flux-system -l app.kubernetes.io/name=fluxcd-helm-upgrader

# View logs to see scanning activity
kubectl logs -n flux-system -l app.kubernetes.io/name=fluxcd-helm-upgrader -f

# Expected output should show:
# 🚀 Starting FluxCD Helm upgrader (interval: 600s)
# 📂 Repository: https://github.com/my-org/flux-infrastructure
# 🔑 SSH Keys: /home/app/.ssh/id_rsa, /home/app/.ssh/id_rsa.pub
# 🐙 GitHub PRs enabled for: my-org/flux-infrastructure
```

### Step 4: Monitor Updates

The upgrader will now:

1. **Scan every 10 minutes** for HelmRelease manifests
2. **Check for newer chart versions** in the configured repositories
3. **Create GitHub branches** for updates (e.g., `update-production-prometheus-15.3.0`)
4. **Update manifest files** with new versions while preserving formatting
5. **Create Pull Requests** with detailed descriptions

Example log output for an update:
```
📈 Update available: prometheus/prometheus (2.45.0 -> 2.46.0)
🔄 Processing GitHub PR creation for prometheus/prometheus
✅ Connected to GitHub as: fluxcd-helm-upgrader-bot
Creating new branch: update-production-prometheus-2-46-0
✅ Successfully created branch: update-production-prometheus-2-46-0
✅ Successfully updated manifest with version 2.46.0
✅ Changes committed with message: Update prometheus in namespace monitoring from 2.45.0 to 2.46.0
✅ Successfully pushed branch: update-production-prometheus-2-46-0
🎉 Successfully created PR for prometheus/prometheus: https://github.com/my-org/flux-infrastructure/pull/42
```

### Step 5: Customize Configuration

For different repository structures, adjust the `searchPattern`:

```yaml
# For repositories with different structures
repo:
  searchPattern: "/infrastructure/*/helmrelease*.yaml;/applications/*/*/helmrelease*.yaml"

# For multiple patterns (will be tried in order)
repo:
  searchPattern: "/clusters/{namespace}/flux-system/helmrelease*.yaml;/tenants/{namespace}/helmrelease*.yaml"
```

### Alternative: CronJob Mode for Production

For production environments, consider using CronJob mode to reduce resource usage:

```bash
helm upgrade fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set mode=cronjob \
  --set cronjob.schedule="0 */4 * * *" \
  --set cronjob.successfulJobsHistoryLimit=5 \
  --set cronjob.failedJobsHistoryLimit=3 \
  --reuse-values
```

This runs the upgrader every 4 hours instead of continuously, which is more suitable for stable production environments.
```

#### Common CronJob Schedules

- `"0 */6 * * *"` - Every 6 hours
- `"0 0 * * *"` - Daily at midnight
- `"0 0 * * 1"` - Weekly on Mondays at midnight
- `"0 9,17 * * 1-5"` - Twice daily (9 AM and 5 PM) on weekdays
- `"*/30 * * * *"` - Every 30 minutes

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
│   ├── deployment.yaml                 # Deployment manifest
│   └── cronjob.yaml                    # CronJob manifest
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
│       │   ├── deployment.yaml         # Deployment template
│       │   └── cronjob.yaml            # CronJob template
│       └── README.md                   # Helm chart documentation
├── examples/                           # Sample configurations
│   ├── sample-values.yaml              # Sample Helm values
│   └── cronjob-values.yaml             # Sample CronJob configuration
├── build.sh                           # Build script for Docker images
└── deploy.sh                         # Deployment script
```

## Configuration

### Helm Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Docker image repository | `kenchrcum/fluxcd-helm-upgrader` |
| `image.tag` | Docker image tag | `0.4.1` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `mode` | Deployment mode: `deployment` or `cronjob` | `deployment` |
| `replicaCount` | Number of replicas (deployment mode only) | `1` |
| `cronjob.schedule` | Cron schedule for job execution | `0 */6 * * *` |
| `cronjob.concurrencyPolicy` | How to handle concurrent executions | `Forbid` |
| `cronjob.successfulJobsHistoryLimit` | Number of successful jobs to retain | `3` |
| `cronjob.failedJobsHistoryLimit` | Number of failed jobs to retain | `1` |
| `cronjob.startingDeadlineSeconds` | Deadline for starting missed jobs | `300` |
| `cronjob.suspend` | Suspend the cron job | `false` |
| `cronjob.activeDeadlineSeconds` | Maximum job execution time | `3600` |
| `cronjob.backoffLimit` | Number of retries on failure | `3` |
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
| `github.tokenSecret.enabled` | Enable GitHub token from secret | `false` |
| `github.tokenSecret.name` | Name of secret containing GitHub token | `""` |
| `github.tokenSecret.key` | Key name in secret containing token | `"token"` |
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

- `RUN_MODE`: Execution mode: `continuous` (default) or `once` for single-run mode
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
docker build -t kenchrcum/fluxcd-helm-upgrader:latest .

# Push to registry
docker push kenchrcum/fluxcd-helm-upgrader:latest

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

### CronJob Mode Issues

1. **Jobs Not Starting**: Check CronJob status and logs
   ```bash
   kubectl get cronjobs -l app.kubernetes.io/name=fluxcd-helm-upgrader
   kubectl logs -l job-name=fluxcd-helm-upgrader --previous
   ```

2. **Jobs Failing**: Review pod logs and resource limits
   ```bash
   kubectl get jobs -l app.kubernetes.io/name=fluxcd-helm-upgrader
   kubectl logs job/fluxcd-helm-upgrader-xxxxx
   ```

3. **Resource Constraints**: Increase resource limits for CronJob pods
   ```yaml
   resources:
     limits:
       cpu: 500m
       memory: 512Mi
     requests:
       cpu: 100m
       memory: 128Mi
   ```

4. **Schedule Conflicts**: If jobs overlap, use `concurrencyPolicy: Forbid`
   ```yaml
   cronjob:
     concurrencyPolicy: Forbid  # Prevent overlapping executions
     schedule: "0 */6 * * *"    # Run every 6 hours
   ```

5. **Missed Schedules**: Check `startingDeadlineSeconds` and cluster load
   ```yaml
   cronjob:
     startingDeadlineSeconds: 600  # Allow 10 minutes for missed schedules
   ```

### Multi-Repository Scenarios

1. **No Manifests Found**: Verify search patterns match your repository structure
   ```bash
   # Test pattern matching locally
   find /path/to/repo -name "helmrelease*.yaml" -type f | head -10
   ```

2. **Permission Denied**: Check SSH key access to all configured repositories
   ```bash
   # Test each repository URL
   git ls-remote https://github.com/org/repo1.git HEAD
   git ls-remote https://github.com/org/repo2.git HEAD
   ```

3. **Mixed Repository Types**: Some repos use SSH, others HTTPS
   ```yaml
   # Configure different authentication per repository if needed
   # Note: Currently only supports single repository configuration
   repo:
     url: https://github.com/org/main-repo.git  # Primary repository
   ```

### Resource and Performance Issues

1. **High Memory Usage**: Monitor pod resources and adjust limits
   ```bash
   kubectl top pods -l app.kubernetes.io/name=fluxcd-helm-upgrader
   ```

2. **Slow Repository Cloning**: Use shallow clones and optimize patterns
   ```yaml
   repo:
     cloneDir: /tmp/fluxcd-repo  # Ensure sufficient space
   ```

3. **Network Timeouts**: Increase timeout values for large repositories
   ```yaml
   # Adjust in application configuration if needed
   # REQUEST_TIMEOUT = (10, 30)  # connect, read timeouts in seconds
   ```

### FluxCD Integration Issues

1. **HelmRelease CRD Not Found**: Ensure FluxCD is properly installed
   ```bash
   kubectl get crd helmreleases.helm.toolkit.fluxcd.io
   kubectl get crd helmrepositories.source.toolkit.fluxcd.io
   kubectl get crd helmcharts.source.toolkit.fluxcd.io
   ```

2. **Version Compatibility**: Check FluxCD version compatibility
   ```bash
   kubectl get deployment -n flux-system -l app.kubernetes.io/name=helm-controller
   # Ensure FluxCD version supports HelmRelease v2beta2/v2
   ```

3. **Namespace Isolation**: Verify upgrader can access Flux resources
   ```bash
   # Check if HelmReleases exist in expected namespaces
   kubectl get helmreleases --all-namespaces | head -10
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.