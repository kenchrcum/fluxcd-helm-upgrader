# FluxCD Helm Upgrader Helm Repository

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Helm](https://img.shields.io/badge/Helm-3-blue.svg)](https://helm.sh/)

Welcome to the official Helm chart repository for the **FluxCD Helm Upgrader**! This repository provides automated Helm chart upgrades within your FluxCD-managed Kubernetes clusters.

## 🚀 Quick Start

### Add the Helm Repository

Add this repository to your Helm client:

```bash
helm repo add fluxcd-helm-upgrader https://kenchrcum.github.io/fluxcd-helm-upgrader
helm repo update
```

### Install the FluxCD Helm Upgrader Chart

Install the chart with default values:

```bash
helm install fluxcd-helm-upgrader fluxcd-helm-upgrader/fluxcd-helm-upgrader
```

Or install in a specific namespace:

```bash
helm install fluxcd-helm-upgrader fluxcd-helm-upgrader/fluxcd-helm-upgrader \
  --namespace flux-system \
  --create-namespace
```

### Upgrade the Chart

To upgrade to the latest version:

```bash
helm repo update
helm upgrade fluxcd-helm-upgrader fluxcd-helm-upgrader/fluxcd-helm-upgrader
```

## 📋 What is FluxCD Helm Upgrader?

The FluxCD Helm Upgrader is a Kubernetes controller that automatically detects and creates pull requests for Helm chart upgrades in your GitOps repositories managed by FluxCD. It integrates seamlessly with your existing FluxCD setup to keep your Helm dependencies up-to-date.

### Key Features

- 🔄 **Automatic Detection**: Scans your FluxCD sources for outdated Helm charts
- 📝 **Pull Request Creation**: Generates GitHub pull requests with upgrade proposals
- 🔐 **Secure**: Supports SSH and GitHub token authentication
- 🕒 **Scheduled Runs**: Configurable cron-based execution
- 🎛️ **Flexible Configuration**: Deployment or CronJob modes
- 📊 **Health Checks**: Built-in health endpoints for monitoring

## 📖 Documentation

For detailed installation instructions, configuration options, and examples, visit the [main repository](https://github.com/kenchrcum/fluxcd-helm-upgrader).

### Configuration Examples

#### Using GitHub Token Authentication

```bash
helm install fluxcd-helm-upgrader fluxcd-helm-upgrader/fluxcd-helm-upgrader \
  --set github.token=your-github-token \
  --set github.owner=your-org \
  --set github.repo=your-repo
```

#### Using SSH Authentication

```bash
# First, create the SSH secret
kubectl create secret generic fluxcd-helm-upgrader-ssh \
  --from-file=id_rsa=/path/to/your/deploy-key \
  --from-file=id_rsa.pub=/path/to/your/deploy-key.pub \
  --from-literal=known_hosts="$(ssh-keyscan -t rsa github.com)" \
  -n flux-system

# Then install the chart
helm install fluxcd-helm-upgrader fluxcd-helm-upgrader/fluxcd-helm-upgrader \
  --set ssh.enabled=true \
  --set github.owner=your-org \
  --set github.repo=your-repo
```

## Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| image.repository | Docker image repository | kenchrcum/fluxcd-helm-upgrader |
| image.tag | Docker image tag | "0.3.2" |
| image.pullPolicy | Image pull policy | IfNotPresent |
| mode | Deployment mode: "deployment" for continuous operation, "cronjob" for scheduled execution | deployment |
| replicaCount | Number of replicas for deployment mode | 1 |
| cronjob.schedule | Schedule in cron format (e.g., "0 */6 * * *" for every 6 hours) | "0 */6 * * *" |
| cronjob.concurrencyPolicy | How to handle concurrent executions | Forbid |
| cronjob.successfulJobsHistoryLimit | Number of successful jobs to retain | 3 |
| cronjob.failedJobsHistoryLimit | Number of failed jobs to retain | 1 |
| cronjob.startingDeadlineSeconds | Deadline in seconds for starting the job if missed | 300 |
| cronjob.suspend | Suspend the cron job | false |
| cronjob.activeDeadlineSeconds | Deadline in seconds for job execution | 3600 |
| cronjob.backoffLimit | Number of retries before marking job as failed | 3 |
| resources.limits.cpu | CPU limit for the pod | 200m |
| resources.limits.memory | Memory limit for the pod | 256Mi |
| resources.requests.cpu | CPU request for the pod | 50m |
| resources.requests.memory | Memory request for the pod | 64Mi |
| nodeSelector | Node selector for pod scheduling | {} |
| tolerations | Tolerations for pod scheduling | [] |
| affinity | Affinity rules for pod scheduling | {} |
| serviceAccount.create | Create a service account | true |
| serviceAccount.name | Name of the service account | "" |
| rbac.create | Create RBAC resources | true |
| rbac.clusterWide | Create cluster-wide RBAC | true |
| logLevel | Logging level | INFO |
| intervalSeconds | Interval between checks in seconds | 300 |
| includePrerelease | Include prerelease versions in upgrades | false |
| podAnnotations | Annotations for the pod | {} |
| repo.url | URL of the Git repository | "" |
| repo.branch | Branch to use | "" |
| repo.searchPattern | Pattern to search for HelmRelease manifests | "/components/{namespace}/*/helmrelease*.y*ml" |
| repo.cloneDir | Mount path for cloning the repo | "/tmp/fluxcd-repo" |
| repo.sshKeySecret.enabled | Enable SSH key authentication | false |
| repo.sshKeySecret.name | Name of the SSH secret | "" |
| repo.sshKeySecret.privateKey | Key name for private key in secret | "id_rsa" |
| repo.sshKeySecret.publicKey | Key name for public key in secret | "id_rsa.pub" |
| repo.sshKeySecret.knownHosts | Key name for known_hosts in secret | "known_hosts" |
| github.tokenSecret.enabled | Enable GitHub token secret | false |
| github.tokenSecret.name | Name of the token secret | "" |
| github.tokenSecret.key | Key name for token in secret | "token" |
| github.repository | GitHub repository in format 'owner/repo' | "" |
| github.defaultBranch | Override default branch detection | "" |
| git.userName | Git user name for commits | "fluxcd-helm-upgrader" |
| git.userEmail | Git user email for commits | "fluxcd-helm-upgrader@noreply.local" |
| git.forcePush | Force push branches when they exist | false |

## 📊 Available Charts

| Chart | Version | Description |
|-------|---------|-------------|
| fluxcd-helm-upgrader | Latest | Automated Helm chart upgrades for FluxCD |

## 🤝 Contributing

We welcome contributions! Please see the [contributing guidelines](https://github.com/kenchrcum/fluxcd-helm-upgrader/blob/master/CONTRIBUTING.md) in the main repository.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](https://github.com/kenchrcum/fluxcd-helm-upgrader/blob/master/LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://github.com/kenchrcum/fluxcd-helm-upgrader)
- 🐛 [Issues](https://github.com/kenchrcum/fluxcd-helm-upgrader/issues)
- 💬 [Discussions](https://github.com/kenchrcum/fluxcd-helm-upgrader/discussions)

---

*Keep your Helm charts fresh with FluxCD Helm Upgrader! 🌟*