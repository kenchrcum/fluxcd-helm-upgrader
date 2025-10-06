# FluxCD Helm Upgrader Helm Chart

This Helm chart deploys the FluxCD Helm Upgrader application, which automatically monitors HelmRelease objects in your FluxCD-managed Kubernetes clusters and helps you stay current with upstream chart versions.

## Features

- **Automated Monitoring**: Periodically scans all HelmRelease objects for newer chart versions
- **GitHub Integration**: Automatically creates Pull Requests when updates are detected
- **Multiple Deployment Modes**:
  - **Deployment Mode**: Continuous monitoring with configurable intervals
  - **CronJob Mode**: Scheduled execution for resource-constrained environments
- **Security-First**: Non-root execution, read-only filesystem, minimal RBAC permissions
- **Flexible Configuration**: Support for private repositories via SSH keys and multiple search patterns

## Prerequisites

- Kubernetes 1.19+
- FluxCD installed and configured
- Helm 3.x

## Installation

### Quick Install

```bash
# Add the Helm repository (if available)
helm repo add fluxcd-helm-upgrader https://kenchrcum.github.io/fluxcd-helm-upgrader/
helm repo update

# Install with default configuration
helm install fluxcd-helm-upgrader fluxcd-helm-upgrader/fluxcd-helm-upgrader
```

### Install from Local Directory

```bash
# Install the chart from the local directory
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader
```

## Configuration

The following table lists the configurable parameters of the FluxCD Helm Upgrader chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Docker image repository | `ghcr.io/kenchrcum/fluxcd-helm-upgrader` |
| `image.tag` | Docker image tag | `0.3.1` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `mode` | Deployment mode: `deployment` or `cronjob` | `deployment` |
| `replicaCount` | Number of replicas (deployment mode only) | `1` |
| `cronjob.schedule` | Cron schedule for job execution | `0 */6 * * *` |
| `cronjob.concurrencyPolicy` | How to handle concurrent executions | `Forbid` |
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
| `repo.url` | Git repository URL to scan for manifests | `""` |
| `repo.branch` | Git branch to scan | `""` |
| `repo.searchPattern` | Glob pattern for finding HelmRelease manifests | `/components/{namespace}/*/helmrelease*.y*ml` |
| `repo.cloneDir` | Local directory for repository cloning | `/tmp/fluxcd-repo` |
| `repo.sshKeySecret.enabled` | Enable SSH key authentication | `false` |
| `repo.sshKeySecret.name` | Name of the SSH key secret | `""` |
| `github.tokenSecret.enabled` | Enable GitHub token from secret | `false` |
| `github.tokenSecret.name` | Name of secret containing GitHub token | `""` |
| `github.repository` | GitHub repository in format 'owner/repo' | `""` |
| `github.defaultBranch` | Override default branch detection | `""` |
| `git.userName` | Git user name for commits | `fluxcd-helm-upgrader` |
| `git.userEmail` | Git user email for commits | `fluxcd-helm-upgrader@noreply.local` |

## Deployment Modes

### Deployment Mode (Default)

In deployment mode, the upgrader runs continuously as a Kubernetes Deployment with a configurable interval between checks.

```yaml
mode: deployment
replicaCount: 1
intervalSeconds: 300  # Check every 5 minutes
```

### CronJob Mode

In CronJob mode, the upgrader runs as scheduled Kubernetes Jobs, which is more resource-efficient as pods are only created when needed.

```yaml
mode: cronjob
cronjob:
  schedule: "0 */6 * * *"  # Every 6 hours
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
```

## Examples

### Basic Deployment with Repository Scanning

```bash
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set repo.url=https://github.com/your-org/flux-infra.git \
  --set repo.branch=main
```

### Deployment with SSH Key Authentication

```bash
# Create SSH key secret first
kubectl create secret generic fluxcd-helm-upgrader-ssh \
  --from-file=id_rsa=/path/to/your/deploy-key \
  --from-file=id_rsa.pub=/path/to/your/deploy-key.pub \
  --from-literal=known_hosts="github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="

# Install with SSH configuration
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set repo.url=git@github.com:your-org/flux-infra.git \
  --set repo.sshKeySecret.enabled=true \
  --set repo.sshKeySecret.name=fluxcd-helm-upgrader-ssh
```

### Deployment with GitHub PR Creation

```bash
# Create GitHub token secret
kubectl create secret generic github-token \
  --from-literal=token="ghp_your_github_token_here" \
  -n flux-system

# Install with GitHub integration
helm install fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader \
  --set repo.url=https://github.com/your-org/flux-infra.git \
  --set github.tokenSecret.enabled=true \
  --set github.tokenSecret.name=github-token \
  --set github.repository=your-org/flux-infra \
  --set git.userName="FluxCD Helm Upgrader" \
  --set git.userEmail="fluxcd-helm-upgrader@your-org.com"
```

## Security Considerations

### RBAC

By default, this chart creates cluster-wide RBAC resources to access HelmRelease objects across all namespaces. For enhanced security in multi-tenant clusters, consider:

```yaml
rbac:
  create: true
  clusterWide: false  # Use namespace-scoped RBAC
```

### Service Account

The chart creates a dedicated service account with minimal required permissions:

- `helmreleases` (get, list, watch) in `helm.toolkit.fluxcd.io` API group
- `helmcharts` and `helmrepositories` (get, list, watch) in `source.toolkit.fluxcd.io` API group

### Security Context

The application runs with:
- Non-root user (UID 10001)
- Read-only root filesystem
- Minimal resource limits

## Monitoring

### Logs

View application logs:

```bash
# For Deployment mode
kubectl logs -l app.kubernetes.io/name=fluxcd-helm-upgrader

# For CronJob mode (check recent jobs)
kubectl logs -l job-name=fluxcd-helm-upgrader
```

### Metrics

Currently, the application does not expose Prometheus metrics. This is planned for a future release.

## Troubleshooting

### Common Issues

#### SSH Authentication Failures

1. **Verify SSH key permissions**: Ensure the private key has 600 permissions
2. **Check deploy key**: Verify the SSH key is added to your repository's deploy keys
3. **Validate known_hosts**: Ensure GitHub.com is in the known_hosts file

#### GitHub Integration Issues

1. **Token permissions**: Ensure the GitHub token has `repo` scope (or Contents + Pull requests + Metadata for fine-grained tokens)
2. **Repository access**: Verify the token can access the specified repository
3. **Branch detection**: If PR creation fails, explicitly set `github.defaultBranch`

#### RBAC Issues

1. **Missing permissions**: Ensure the HelmRelease and HelmRepository CRDs are installed
2. **Namespace scope**: If using namespace-scoped RBAC, ensure the upgrader runs in the same namespace as your Flux resources

### Debug Mode

Enable debug logging for detailed information:

```yaml
logLevel: DEBUG
```

This will show manifest paths for all HelmReleases, not just those with updates.

## Upgrading

### From Previous Versions

```bash
helm upgrade fluxcd-helm-upgrader ./helm/fluxcd-helm-upgrader
```

### Breaking Changes

- **v0.3.0**: Added support for CronJob mode. Existing deployments using Deployment mode are unaffected.
- **v0.2.0**: Changed default image repository to use GitHub Container Registry.

## Support

For issues and questions:

1. Check the [troubleshooting section](#troubleshooting) above
2. Review the [main project documentation](../../README.md)
3. Open an issue on [GitHub](https://github.com/kenchrcum/fluxcd-helm-upgrader/issues)

## License

This Helm chart is part of the FluxCD Helm Upgrader project and is licensed under the MIT License.
