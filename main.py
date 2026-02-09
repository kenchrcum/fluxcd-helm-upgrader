import os
import time
import logging
import subprocess
import shutil
import glob
import threading
import tempfile
import tarfile
from pathlib import Path
from urllib.parse import urlparse, urlunparse, quote
from typing import Any, Dict, List, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
from datetime import datetime

import requests
import yaml
import semver
import re
from kubernetes import client, config
from kubernetes.client import ApiException
from github import Github, GithubException
from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
from nova_integration import NovaIntegration


class Config:
    """Centralized configuration management."""
    
    # FluxCD API configuration
    HELM_RELEASE_GROUP = "helm.toolkit.fluxcd.io"
    SOURCE_GROUP = "source.toolkit.fluxcd.io"
    # Try newer versions first; gracefully fall back
    HELM_RELEASE_VERSIONS = ["v2", "v2beta2", "v2beta1"]
    SOURCE_VERSIONS = ["v1", "v1beta2", "v1beta1"]
    
    # Application configuration
    DEFAULT_INTERVAL_SECONDS = int(os.getenv("INTERVAL_SECONDS", "300"))
    INCLUDE_PRERELEASE = os.getenv("INCLUDE_PRERELEASE", "false").lower() in (
        "1", "true", "yes", "on"
    )
    REQUEST_TIMEOUT = (5, 20)  # connect, read
    DEFAULT_HEADERS = {
        "User-Agent": "fluxcd-helm-upgrader/0.7.0 (+https://github.com/kenchrcum/fluxcd-helm-upgrader)",
        "Accept": "application/x-yaml, text/yaml, text/plain;q=0.9, */*;q=0.8",
    }
    
    # Health check configuration
    HEALTH_CHECK_PORT = int(os.getenv("HEALTH_CHECK_PORT", "8080"))
    HEALTH_CHECK_HOST = os.getenv("HEALTH_CHECK_HOST", "0.0.0.0")
    
    # Metrics configuration
    METRICS_PORT = int(os.getenv("METRICS_PORT", "8081"))
    METRICS_HOST = os.getenv("METRICS_HOST", "0.0.0.0")

    # Git repository configuration
    REPO_URL = os.getenv("REPO_URL", "").strip()
    REPO_BRANCH = os.getenv("REPO_BRANCH", "").strip()
    REPO_SEARCH_PATTERN = os.getenv(
        "REPO_SEARCH_PATTERN",
        "/components/{namespace}/*/helmrelease*.y*ml",
    ).strip()
    REPO_CLONE_DIR = os.getenv("REPO_CLONE_DIR", "/tmp/fluxcd-repo").strip()
    
    # SSH configuration
    SSH_PRIVATE_KEY_PATH = os.getenv(
        "SSH_PRIVATE_KEY_PATH", "/home/app/.ssh/private_key"
    ).strip()
    SSH_PUBLIC_KEY_PATH = os.getenv(
        "SSH_PUBLIC_KEY_PATH", "/home/app/.ssh/public_key"
    ).strip()
    SSH_KNOWN_HOSTS_PATH = os.getenv(
        "SSH_KNOWN_HOSTS_PATH", "/home/app/.ssh/known_hosts"
    ).strip()
    
    # GitHub configuration
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
    GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "").strip()
    GITHUB_DEFAULT_BRANCH = os.getenv("GITHUB_DEFAULT_BRANCH", "").strip()
    GIT_FORCE_PUSH = os.getenv("GIT_FORCE_PUSH", "false").lower() in (
        "1", "true", "yes", "on"
    )

    # GitHub assignee configuration
    GITHUB_DEFAULT_ASSIGNEE = os.getenv("GITHUB_DEFAULT_ASSIGNEE", "").strip()
    GITHUB_ASSIGNEES_BY_NAMESPACE = os.getenv("GITHUB_ASSIGNEES_BY_NAMESPACE", "").strip()
    GITHUB_ASSIGNEES_BY_HELMRELEASE = os.getenv("GITHUB_ASSIGNEES_BY_HELMRELEASE", "").strip()
    
    @classmethod
    def get_boolean_env(cls, key: str, default: bool = False) -> bool:
        """Helper to parse boolean environment variables."""
        return os.getenv(key, str(default)).lower() in ("1", "true", "yes", "on")
    
    @classmethod
    def validate_configuration(cls) -> Tuple[bool, List[str]]:
        """Validate configuration and return (is_valid, error_messages)."""
        errors = []
        
        # Validate required environment variables
        if not cls.REPO_URL and not cls.GITHUB_TOKEN:
            errors.append("Either REPO_URL or GITHUB_TOKEN must be configured")
            # Continue with other validations even if this fails
        
        # Validate REPO_URL format if provided
        if cls.REPO_URL:
            if not cls.REPO_URL.startswith(('http://', 'https://', 'git@')):
                errors.append("REPO_URL must start with http://, https://, or git@")
            if cls.REPO_URL.startswith('git@') and not cls.REPO_URL.endswith('.git'):
                errors.append("SSH REPO_URL should end with .git")
        
        # Validate GITHUB_REPOSITORY format if provided
        if cls.GITHUB_REPOSITORY:
            if '/' not in cls.GITHUB_REPOSITORY:
                errors.append("GITHUB_REPOSITORY must be in format 'owner/repo'")
            elif cls.GITHUB_REPOSITORY.count('/') != 1:
                errors.append("GITHUB_REPOSITORY must contain exactly one '/' separator")
        
        # Validate SSH key paths if REPO_URL is provided
        if cls.REPO_URL and cls.REPO_URL.startswith('git@'):
            if not os.path.exists(cls.SSH_PRIVATE_KEY_PATH):
                errors.append(f"SSH private key not found: {cls.SSH_PRIVATE_KEY_PATH}")
            elif not os.access(cls.SSH_PRIVATE_KEY_PATH, os.R_OK):
                errors.append(f"SSH private key not readable: {cls.SSH_PRIVATE_KEY_PATH}")
        
        # Validate interval
        if cls.DEFAULT_INTERVAL_SECONDS < 60:
            errors.append("INTERVAL_SECONDS should be at least 60 seconds")
        elif cls.DEFAULT_INTERVAL_SECONDS > 86400:
            errors.append("INTERVAL_SECONDS should not exceed 86400 seconds (24 hours)")
        
        # Validate ports
        if cls.HEALTH_CHECK_PORT < 1024 or cls.HEALTH_CHECK_PORT > 65535:
            errors.append("HEALTH_CHECK_PORT must be between 1024 and 65535")
        if cls.METRICS_PORT < 1024 or cls.METRICS_PORT > 65535:
            errors.append("METRICS_PORT must be between 1024 and 65535")
        if cls.HEALTH_CHECK_PORT == cls.METRICS_PORT:
            errors.append("HEALTH_CHECK_PORT and METRICS_PORT must be different")
        
        # Validate search pattern
        if cls.REPO_SEARCH_PATTERN:
            if not cls.REPO_SEARCH_PATTERN.startswith('/'):
                errors.append("REPO_SEARCH_PATTERN should start with '/'")

        # Validate GitHub assignee configurations
        if cls.GITHUB_DEFAULT_ASSIGNEE and not cls.GITHUB_DEFAULT_ASSIGNEE.replace('-', '').replace('_', '').isalnum():
            errors.append("GITHUB_DEFAULT_ASSIGNEE should contain only alphanumeric characters, hyphens, and underscores")

        if cls.GITHUB_ASSIGNEES_BY_NAMESPACE:
            try:
                import json
                namespace_assignees = json.loads(cls.GITHUB_ASSIGNEES_BY_NAMESPACE)
                if not isinstance(namespace_assignees, dict):
                    errors.append("GITHUB_ASSIGNEES_BY_NAMESPACE must be a valid JSON object mapping namespaces to GitHub usernames")
                else:
                    for ns, assignee in namespace_assignees.items():
                        if not isinstance(assignee, str) or not assignee.strip():
                            errors.append(f"Invalid assignee '{assignee}' for namespace '{ns}' in GITHUB_ASSIGNEES_BY_NAMESPACE")
                        elif not assignee.replace('-', '').replace('_', '').isalnum():
                            errors.append(f"Assignee '{assignee}' for namespace '{ns}' should contain only alphanumeric characters, hyphens, and underscores")
            except json.JSONDecodeError as e:
                errors.append(f"GITHUB_ASSIGNEES_BY_NAMESPACE must be valid JSON: {str(e)}")

        if cls.GITHUB_ASSIGNEES_BY_HELMRELEASE:
            try:
                import json
                helmrlease_assignees = json.loads(cls.GITHUB_ASSIGNEES_BY_HELMRELEASE)
                if not isinstance(helmrlease_assignees, dict):
                    errors.append("GITHUB_ASSIGNEES_BY_HELMRELEASE must be a valid JSON object mapping HelmRelease names to GitHub usernames")
                else:
                    for hr, assignee in helmrlease_assignees.items():
                        if not isinstance(assignee, str) or not assignee.strip():
                            errors.append(f"Invalid assignee '{assignee}' for HelmRelease '{hr}' in GITHUB_ASSIGNEES_BY_HELMRELEASE")
                        elif not assignee.replace('-', '').replace('_', '').isalnum():
                            errors.append(f"Assignee '{assignee}' for HelmRelease '{hr}' should contain only alphanumeric characters, hyphens, and underscores")
            except json.JSONDecodeError as e:
                errors.append(f"GITHUB_ASSIGNEES_BY_HELMRELEASE must be valid JSON: {str(e)}")

        # Validate clone directory
        if cls.REPO_CLONE_DIR:
            clone_path = Path(cls.REPO_CLONE_DIR)
            if not clone_path.parent.exists():
                errors.append(f"Parent directory of REPO_CLONE_DIR does not exist: {clone_path.parent}")
            elif not os.access(clone_path.parent, os.W_OK):
                errors.append(f"Parent directory of REPO_CLONE_DIR is not writable: {clone_path.parent}")
        
        return len(errors) == 0, errors


# Prometheus metrics
METRICS = {
    'helm_releases_total': Gauge('fluxcd_helm_upgrader_helm_releases_total', 'Total number of HelmReleases scanned'),
    'helm_releases_outdated': Gauge('fluxcd_helm_upgrader_helm_releases_outdated', 'Number of HelmReleases with updates available'),
    'helm_releases_up_to_date': Gauge('fluxcd_helm_upgrader_helm_releases_up_to_date', 'Number of HelmReleases that are up to date'),
    'updates_processed_total': Counter('fluxcd_helm_upgrader_updates_processed_total', 'Total number of updates processed', ['namespace', 'name', 'status']),
    'pull_requests_created_total': Counter('fluxcd_helm_upgrader_pull_requests_created_total', 'Total number of pull requests created', ['namespace', 'name']),
    'git_operations_total': Counter('fluxcd_helm_upgrader_git_operations_total', 'Total number of git operations', ['operation', 'status']),
    'kubernetes_api_calls_total': Counter('fluxcd_helm_upgrader_kubernetes_api_calls_total', 'Total number of Kubernetes API calls', ['operation', 'status']),
    'github_api_calls_total': Counter('fluxcd_helm_upgrader_github_api_calls_total', 'Total number of GitHub API calls', ['operation', 'status']),
    'repository_index_fetches_total': Counter('fluxcd_helm_upgrader_repository_index_fetches_total', 'Total number of repository index fetches', ['status']),
    'check_cycle_duration_seconds': Histogram('fluxcd_helm_upgrader_check_cycle_duration_seconds', 'Duration of check cycles in seconds'),
    'last_successful_check_timestamp': Gauge('fluxcd_helm_upgrader_last_successful_check_timestamp', 'Timestamp of last successful check'),
    'application_info': Info('fluxcd_helm_upgrader_info', 'Application information'),
    'errors_total': Counter('fluxcd_helm_upgrader_errors_total', 'Total number of errors', ['error_type', 'component']),
}


class HealthCheckHandler(BaseHTTPRequestHandler):
    """HTTP handler for health check endpoints."""
    
    def do_GET(self):
        """Handle GET requests for health check endpoints."""
        if self.path == "/health":
            self.handle_health()
        elif self.path == "/ready":
            self.handle_readiness()
        elif self.path == "/metrics":
            self.handle_metrics()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
    
    def handle_health(self):
        """Handle liveness probe - basic application health."""
        try:
            # Basic health check - application is running
            response = {
                "status": "healthy",
                "timestamp": time.time(),
                "version": "0.7.0"
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        except Exception as e:
            logging.error("Health check failed: %s", e)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
    
    def handle_readiness(self):
        """Handle readiness probe - application is ready to serve requests."""
        try:
            # Check if Kubernetes client is available
            try:
                config.load_incluster_config()
                client.CustomObjectsApi()
                k8s_ready = True
            except Exception:
                k8s_ready = False
            
            response = {
                "status": "ready" if k8s_ready else "not_ready",
                "timestamp": time.time(),
                "version": "0.7.0",
                "kubernetes": k8s_ready
            }
            
            status_code = 200 if k8s_ready else 503
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        except Exception as e:
            logging.error("Readiness check failed: %s", e)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
    
    def handle_metrics(self):
        """Handle Prometheus metrics endpoint."""
        try:
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(generate_latest())
        except Exception as e:
            logging.error("Metrics endpoint failed: %s", e)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
    
    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        pass


def initialize_metrics():
    """Initialize Prometheus metrics with application information."""
    try:
        # Set application info
        METRICS['application_info'].info({
            'version': '0.7.0',
            'component': 'fluxcd-helm-upgrader',
            'description': 'FluxCD Helm Release Upgrader'
        })
        
        # Initialize counters to 0
        METRICS['helm_releases_total'].set(0)
        METRICS['helm_releases_outdated'].set(0)
        METRICS['helm_releases_up_to_date'].set(0)
        METRICS['last_successful_check_timestamp'].set(0)
        
        logging.info("Prometheus metrics initialized", extra={"metrics_port": Config.METRICS_PORT})
    except Exception as e:
        logging.error("Failed to initialize metrics: %s", e, extra={"error_type": "metrics_init", "component": "metrics"})


def start_health_server():
    """Start the health check HTTP server in a background thread."""
    try:
        server = HTTPServer((Config.HEALTH_CHECK_HOST, Config.HEALTH_CHECK_PORT), HealthCheckHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        logging.info("🏥 Health check server started on %s:%d", Config.HEALTH_CHECK_HOST, Config.HEALTH_CHECK_PORT)
        return server
    except Exception as e:
        logging.error("Failed to start health check server: %s", e)
        return None


# Legacy global constants for backward compatibility
HELM_RELEASE_GROUP = Config.HELM_RELEASE_GROUP
SOURCE_GROUP = Config.SOURCE_GROUP
HELM_RELEASE_VERSIONS = Config.HELM_RELEASE_VERSIONS
SOURCE_VERSIONS = Config.SOURCE_VERSIONS
DEFAULT_INTERVAL_SECONDS = Config.DEFAULT_INTERVAL_SECONDS
INCLUDE_PRERELEASE = Config.INCLUDE_PRERELEASE
REQUEST_TIMEOUT = Config.REQUEST_TIMEOUT
DEFAULT_HEADERS = Config.DEFAULT_HEADERS
REPO_URL = Config.REPO_URL
REPO_BRANCH = Config.REPO_BRANCH
REPO_SEARCH_PATTERN = Config.REPO_SEARCH_PATTERN
REPO_CLONE_DIR = Config.REPO_CLONE_DIR
SSH_PRIVATE_KEY_PATH = Config.SSH_PRIVATE_KEY_PATH
SSH_PUBLIC_KEY_PATH = Config.SSH_PUBLIC_KEY_PATH
SSH_KNOWN_HOSTS_PATH = Config.SSH_KNOWN_HOSTS_PATH
GITHUB_TOKEN = Config.GITHUB_TOKEN
GITHUB_REPOSITORY = Config.GITHUB_REPOSITORY
GITHUB_DEFAULT_BRANCH = Config.GITHUB_DEFAULT_BRANCH
GIT_FORCE_PUSH = Config.GIT_FORCE_PUSH
GITHUB_DEFAULT_ASSIGNEE = Config.GITHUB_DEFAULT_ASSIGNEE
GITHUB_ASSIGNEES_BY_NAMESPACE = Config.GITHUB_ASSIGNEES_BY_NAMESPACE
GITHUB_ASSIGNEES_BY_HELMRELEASE = Config.GITHUB_ASSIGNEES_BY_HELMRELEASE


# Helper functions for common patterns
def get_home_directory() -> Path:
    """Get the appropriate home directory based on environment."""
    return Path("/home/app") if os.path.exists("/home/app") else Path.home()


def get_git_ssh_command() -> str:
    """Get the standardized Git SSH command."""
    return (
        f"ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile={SSH_KNOWN_HOSTS_PATH} "
        f"-i {SSH_PRIVATE_KEY_PATH} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=30"
    )


def parse_github_repository(repo_str: str) -> Tuple[str, str]:
    """Parse GitHub repository string into owner and repo name."""
    if "/" not in repo_str:
        raise ValueError("GITHUB_REPOSITORY must be in format 'owner/repo'")
    parts = repo_str.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("GITHUB_REPOSITORY must be in format 'owner/repo'")
    return parts[0], parts[1]


def safe_run_command(cmd: List[str], **kwargs) -> Tuple[int, str, str]:
    """Safely run a subprocess command with error handling."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            **kwargs
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        logging.error("Failed to run command %s: %s", " ".join(cmd), str(e))
        return 1, "", str(e)


def handle_github_exception(e: GithubException, context: str) -> None:
    """Standardized GitHub exception handling."""
    error_message = str(e).lower()
    if e.status == 403:
        logging.error("❌ GitHub permission denied in %s: %s", context, str(e))
        logging.error("   Please ensure the token has 'repo' permissions")
    elif e.status == 404:
        logging.error("❌ GitHub resource not found in %s: %s", context, str(e))
    elif "pull request already exists" in error_message:
        logging.info("✅ Pull request already exists for %s", context)
    elif "validation failed" in error_message:
        logging.error("❌ GitHub validation error in %s: %s", context, str(e))
        logging.error("   This often indicates permission or branch accessibility issues")
    else:
        logging.error("❌ GitHub error in %s: %s", context, str(e))


def validate_ssh_key_loading(private_key_path: str) -> bool:
    """Test if SSH private key can be loaded by ssh-keygen."""
    try:
        # First check if ssh-keygen is available
        returncode, _, _ = safe_run_command(["which", "ssh-keygen"])
        if returncode != 0:
            logging.warning("ssh-keygen not found, skipping key validation")
            return True

        # Check file permissions and existence
        if not os.path.exists(private_key_path):
            logging.error("SSH private key file does not exist: %s", private_key_path)
            return False

        # Check if file is readable
        try:
            with open(private_key_path, "r") as f:
                content = f.read()
                if not content.strip():
                    logging.error("SSH private key file is empty: %s", private_key_path)
                    return False
        except PermissionError:
            logging.error(
                "Cannot read SSH private key file (permission denied): %s",
                private_key_path,
            )
            return False
        except Exception as e:
            logging.error("Error reading SSH private key file: %s", str(e))
            return False

        # Try to validate with ssh-keygen
        returncode, _, stderr = safe_run_command(
            ["ssh-keygen", "-l", "-f", private_key_path],
            timeout=10
        )

        if returncode == 0:
            logging.debug("SSH key loading validation passed")
            return True
        else:
            stderr_msg = stderr.strip()
            logging.warning("SSH key validation warning: %s", stderr_msg)

            # If it's just a warning about not being able to print key, but the command succeeded partially, continue
            if "not a key file" not in stderr_msg.lower():
                logging.info("SSH key validation passed despite warnings")
                return True
            else:
                logging.error("SSH key loading failed: %s", stderr_msg)
                return False

    except FileNotFoundError:
        logging.warning("ssh-keygen not found, skipping key validation")
        return True
    except Exception as e:
        logging.error("Error testing SSH key loading: %s", str(e))
        return False


def setup_ssh_config() -> bool:
    """Setup SSH configuration for git operations."""
    try:
        home_dir = get_home_directory()
        ssh_dir = home_dir / ".ssh"
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        logging.debug("SSH directory ready: %s", ssh_dir)

        # Use SSH keys directly from their mounted paths
        private_key_path = Path(SSH_PRIVATE_KEY_PATH)
        public_key_path = Path(SSH_PUBLIC_KEY_PATH)
        known_hosts_path = Path(SSH_KNOWN_HOSTS_PATH)

        # Check if SSH keys exist
        if not private_key_path.exists():
            logging.error("SSH private key not found at %s", SSH_PRIVATE_KEY_PATH)
            logging.error(
                "Make sure the SSH private key file exists and the path is correct"
            )
            return False

        # Validate SSH private key format
        try:
            with open(private_key_path, "r") as f:
                key_content = f.read().strip()
                if not key_content:
                    logging.error("SSH private key file is empty")
                    return False

                # Check if it's a valid SSH private key format
                if not (
                    key_content.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
                    or key_content.startswith("-----BEGIN RSA PRIVATE KEY-----")
                    or key_content.startswith("-----BEGIN EC PRIVATE KEY-----")
                    or key_content.startswith("-----BEGIN PRIVATE KEY-----")
                ):
                    logging.error("SSH private key is not in a recognized format")
                    logging.error("Supported formats: OpenSSH, RSA, ECDSA, or PKCS#8")
                    logging.error(
                        "You may need to convert your key using: ssh-keygen -p -f key_file -m pem"
                    )
                    return False

                if not (
                    key_content.endswith("-----END OPENSSH PRIVATE KEY-----\n")
                    or key_content.endswith("-----END RSA PRIVATE KEY-----\n")
                    or key_content.endswith("-----END EC PRIVATE KEY-----\n")
                    or key_content.endswith("-----END PRIVATE KEY-----\n")
                    or key_content.endswith("-----END OPENSSH PRIVATE KEY-----")
                    or key_content.endswith("-----END RSA PRIVATE KEY-----")
                    or key_content.endswith("-----END EC PRIVATE KEY-----")
                    or key_content.endswith("-----END PRIVATE KEY-----")
                ):
                    logging.warning("SSH private key may be missing trailing newline")
                    logging.warning("This can cause SSH authentication to fail")
                    logging.info(
                        "Consider adding a newline at the end of your SSH key in Vault"
                    )

            logging.debug("SSH private key format validation passed")

        except Exception as e:
            logging.error("Error validating SSH private key format: %s", str(e))
            return False

        # Test if SSH key can be loaded by ssh-keygen
        if not validate_ssh_key_loading(str(private_key_path)):
            return False

        # Set proper permissions on private key (if writable)
        try:
            private_key_path.chmod(0o600)
        except OSError:
            # File might be read-only due to mount, log but continue
            logging.debug(
                "Could not set permissions on private key (likely read-only mount)"
            )

        # Set proper permissions on public key if it exists (if writable)
        if public_key_path.exists():
            try:
                public_key_path.chmod(0o644)
            except OSError:
                logging.debug(
                    "Could not set permissions on public key (likely read-only mount)"
                )

        # Check known_hosts and add GitHub if needed
        if known_hosts_path.exists():
            try:
                known_hosts_path.chmod(0o644)
            except OSError:
                logging.debug(
                    "Could not set permissions on known_hosts (likely read-only mount)"
                )
        else:
            # Try to create known_hosts with GitHub entry using ssh-keyscan
            try:
                # Use ssh-keyscan to dynamically fetch GitHub's SSH host keys
                result = subprocess.run(
                    ["ssh-keyscan", "-t", "rsa", "github.com"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    github_known_hosts = result.stdout.strip()
                    with open(known_hosts_path, "w") as f:
                        f.write(github_known_hosts + "\n")
                    known_hosts_path.chmod(0o644)
                    logging.debug("Added GitHub to known hosts using ssh-keyscan")
                else:
                    # Fallback to hardcoded key if ssh-keyscan fails
                    logging.warning("ssh-keyscan failed, using fallback GitHub key")
                    github_known_hosts = "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
                    with open(known_hosts_path, "w") as f:
                        f.write(github_known_hosts + "\n")
                    known_hosts_path.chmod(0o644)
                    logging.debug("Added GitHub to known hosts using fallback key")
            except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                logging.warning(
                    f"Could not create known_hosts file: {e}. SSH connections to GitHub may fail."
                )

        # Configure git to use SSH with the correct key paths
        env = os.environ.copy()
        env.setdefault("GIT_SSH_COMMAND", get_git_ssh_command())

        return True

    except Exception as e:
        logging.exception("Error setting up SSH configuration")
        return False


def validate_ssh_access(repo_url: str) -> bool:
    """Validate SSH access to the repository."""
    if not repo_url:
        return False

    try:
        # Convert HTTPS URL to SSH URL if needed
        ssh_url = convert_to_ssh_url(repo_url)

        # Test SSH access with git ls-remote using the correct key paths
        env = os.environ.copy()
        env.setdefault("GIT_SSH_COMMAND", get_git_ssh_command())

        returncode, _, stderr = safe_run_command(
            ["git", "ls-remote", ssh_url, "HEAD"],
            env=env,
            timeout=30,
        )

        if returncode == 0:
            logging.debug("SSH access validated")
            return True
        else:
            stderr_output = stderr.strip()
            logging.error("SSH access validation failed: %s", stderr_output)

            # Provide specific guidance based on error type
            if "Load key" in stderr_output and "error in libcrypto" in stderr_output:
                logging.error("SSH key format issue detected. Common solutions:")
                logging.error(
                    "1. Convert PKCS#8 format to PEM: openssl rsa -in key.pem -out key.pem"
                )
                logging.error(
                    "2. Convert to OpenSSH format: ssh-keygen -p -f key_file -m pem"
                )
                logging.error(
                    "3. Regenerate key: ssh-keygen -t rsa -b 4096 -C 'flux-deploy-key'"
                )
            elif "Permission denied" in stderr_output:
                logging.error("SSH authentication failed. Check:")
                logging.error("1. SSH key has correct permissions in repository")
                logging.error("2. SSH key is added to repository deploy keys")
                logging.error("3. Repository URL format is correct")
            elif "Could not resolve hostname" in stderr_output:
                logging.error(
                    "DNS/Network issue. Check internet connectivity and DNS resolution"
                )

            return False

    except Exception as e:
        logging.exception("Error validating SSH access")
        return False


def convert_to_ssh_url(url: str) -> str:
    """Convert HTTPS GitHub URL to SSH URL."""
    if url.startswith("https://github.com/"):
        # Extract owner/repo from HTTPS URL
        path = url.replace("https://github.com/", "").rstrip("/")
        return f"git@github.com:{path}.git"
    elif url.startswith("git@github.com:"):
        return url
    else:
        # For other git hosts, try to convert if possible
        try:
            parsed = urlparse(url)
            if parsed.hostname and parsed.path:
                ssh_url = f"git@{parsed.hostname}:{parsed.path.lstrip('/')}"
                if not ssh_url.endswith(".git"):
                    ssh_url += ".git"
                return ssh_url
        except:
            pass
        return url


def configure_logging() -> None:
    """Configure structured logging with JSON format."""
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_format = os.getenv("LOG_FORMAT", "text").lower()
    
    if log_format == "json":
        # JSON structured logging
        import json
        import sys
        
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno,
                }
                
                # Add exception info if present
                if record.exc_info:
                    log_entry["exception"] = self.formatException(record.exc_info)
                
                # Add extra fields from record
                for key, value in record.__dict__.items():
                    if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                                 'filename', 'module', 'lineno', 'funcName', 'created', 'msecs',
                                 'relativeCreated', 'thread', 'threadName', 'processName', 'process',
                                 'getMessage', 'exc_info', 'exc_text', 'stack_info']:
                        log_entry[key] = value
                
                return json.dumps(log_entry)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_level))
        
        # Remove existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add console handler with JSON formatter
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(console_handler)
        
        logging.info("Structured JSON logging enabled", extra={"log_format": "json", "log_level": log_level})
    else:
        # Standard text logging
        logging.basicConfig(
            level=getattr(logging, log_level),
            format="%(asctime)s %(levelname)s [%(name)s:%(funcName)s:%(lineno)d] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        logging.info("Standard text logging enabled", extra={"log_format": "text", "log_level": log_level})


# Function removed - now part of GitHubManager class


class GitHubManager:
    """Manages GitHub operations and client creation."""
    
    def __init__(self):
        self.client: Optional[Github] = None
        self.owner: Optional[str] = None
        self.repo_name: Optional[str] = None
        
        if GITHUB_TOKEN and GITHUB_REPOSITORY:
            self.client = self._create_client()
            if self.client:
                try:
                    self.owner, self.repo_name = parse_github_repository(GITHUB_REPOSITORY)
                except ValueError as e:
                    logging.error("Invalid GitHub repository format: %s", str(e))
                    self.client = None
    
    def _create_client(self) -> Optional[Github]:
        """Create and return a GitHub client if token is available."""
        if not GITHUB_TOKEN:
            logging.debug("No GitHub token provided, GitHub integration disabled")
            return None

        try:
            from github import Auth

            # Use the new authentication method to avoid deprecation warning
            auth = Auth.Token(GITHUB_TOKEN)
            g = Github(auth=auth)
            # Test the connection by getting user info
            user = g.get_user()
            logging.info("✅ Connected to GitHub as: %s", user.login)

            # Validate GitHub setup
            if not self._validate_setup(g):
                logging.warning(
                    "⚠️  GitHub setup validation failed, PR creation may not work properly"
                )

            return g
        except GithubException as e:
            logging.error("❌ Failed to authenticate with GitHub: %s", str(e))
            return None
        except Exception as e:
            logging.error("❌ Unexpected error connecting to GitHub: %s", str(e))
            return None
    
    def _validate_setup(self, github_client: Github) -> bool:
        """Validate GitHub token permissions and repository access."""
        if not GITHUB_REPOSITORY:
            logging.warning("GITHUB_REPOSITORY not configured")
            return False

        try:
            owner, repo_name = parse_github_repository(GITHUB_REPOSITORY)
            repo = github_client.get_repo(f"{owner}/{repo_name}")
            logging.debug("✅ Repository access validated: %s/%s", owner, repo_name)

            # Check if we can read repository info
            default_branch = repo.default_branch
            if default_branch:
                logging.debug("✅ Can read repository default branch: %s", default_branch)
            else:
                logging.warning("⚠️  Cannot read repository default branch")

            # Check if we can read branches (this tests more permissions)
            try:
                branches = repo.get_branches()
                logging.debug("✅ Can read repository branches")
            except GithubException as e:
                if e.status == 403:
                    logging.warning(
                        "⚠️  GitHub token lacks permission to read repository branches"
                    )
                    logging.warning(
                        "   This may cause issues with PR creation, but will fallback to defaults"
                    )
                else:
                    logging.warning("⚠️  Cannot read repository branches: %s", str(e))

            return True
        except GithubException as e:
            if e.status == 403:
                logging.error(
                    "❌ GitHub token lacks permission to access repository %s",
                    GITHUB_REPOSITORY,
                )
                logging.error("   Please ensure the token has 'repo' permissions")
            elif e.status == 404:
                logging.error(
                    "❌ Repository %s not found or not accessible", GITHUB_REPOSITORY
                )
                logging.error("   Please verify the repository exists and is accessible")
            else:
                logging.error("❌ Failed to validate repository access: %s", str(e))
            return False
        except Exception as e:
            logging.error("❌ Unexpected error validating GitHub setup: %s", str(e))
            return False
    
    def is_available(self) -> bool:
        """Check if GitHub client is available."""
        return self.client is not None and self.owner is not None and self.repo_name is not None
    
    def get_repo(self):
        """Get the repository object."""
        if not self.is_available():
            return None
        return self.client.get_repo(f"{self.owner}/{self.repo_name}")


def create_github_client() -> Optional[Github]:
    """Legacy function for backward compatibility."""
    github_manager = GitHubManager()
    return github_manager.client


def determine_github_assignee(namespace: str, helmrelease_name: str) -> Optional[str]:
    """Determine which GitHub user should be assigned to a PR based on namespace and HelmRelease name.

    Priority order:
    1. Specific HelmRelease mapping (highest priority)
    2. Namespace mapping
    3. Default assignee (fallback)
    4. None (no assignee)

    Args:
        namespace: Kubernetes namespace
        helmrelease_name: HelmRelease name

    Returns:
        GitHub username to assign, or None if no assignee configured
    """
    import json

    # Check HelmRelease-specific mapping first (highest priority)
    if GITHUB_ASSIGNEES_BY_HELMRELEASE:
        try:
            helmrlease_assignees = json.loads(GITHUB_ASSIGNEES_BY_HELMRELEASE)
            # Try exact match first
            if helmrelease_name in helmrlease_assignees:
                assignee = helmrlease_assignees[helmrelease_name]
                if assignee and assignee.strip():
                    logging.debug("Assigned user '%s' for HelmRelease '%s' (exact match)", assignee, helmrelease_name)
                    return assignee.strip()

            # Try pattern matching (if helmrelease_name contains any key as substring)
            for pattern, assignee in helmrlease_assignees.items():
                if pattern in helmrelease_name and assignee and assignee.strip():
                    logging.debug("Assigned user '%s' for HelmRelease '%s' (pattern match: %s)", assignee, helmrelease_name, pattern)
                    return assignee.strip()
        except (json.JSONDecodeError, TypeError) as e:
            logging.warning("Failed to parse GITHUB_ASSIGNEES_BY_HELMRELEASE: %s", str(e))

    # Check namespace mapping
    if GITHUB_ASSIGNEES_BY_NAMESPACE:
        try:
            namespace_assignees = json.loads(GITHUB_ASSIGNEES_BY_NAMESPACE)
            # Try exact match first
            if namespace in namespace_assignees:
                assignee = namespace_assignees[namespace]
                if assignee and assignee.strip():
                    logging.debug("Assigned user '%s' for namespace '%s' (exact match)", assignee, namespace)
                    return assignee.strip()

            # Try pattern matching (if namespace contains any key as substring)
            for pattern, assignee in namespace_assignees.items():
                if pattern in namespace and assignee and assignee.strip():
                    logging.debug("Assigned user '%s' for namespace '%s' (pattern match: %s)", assignee, namespace, pattern)
                    return assignee.strip()
        except (json.JSONDecodeError, TypeError) as e:
            logging.warning("Failed to parse GITHUB_ASSIGNEES_BY_NAMESPACE: %s", str(e))

    # Fall back to default assignee
    if GITHUB_DEFAULT_ASSIGNEE and GITHUB_DEFAULT_ASSIGNEE.strip():
        logging.debug("Assigned default user '%s' for %s/%s", GITHUB_DEFAULT_ASSIGNEE, namespace, helmrelease_name)
        return GITHUB_DEFAULT_ASSIGNEE.strip()

    # No assignee configured
    logging.debug("No assignee configured for %s/%s", namespace, helmrelease_name)
    return None


def load_kube_config() -> client.CustomObjectsApi:
    try:
        config.load_incluster_config()
        logging.info("Loaded in-cluster Kubernetes config")
    except Exception:
        config.load_kube_config()
        logging.info("Loaded kubeconfig from local environment")
    return client.CustomObjectsApi()


def _run_git_command(
    args: List[str], cwd: Optional[str] = None
) -> Tuple[int, str, str]:
    """Run a git command with standardized environment setup."""
    env = os.environ.copy()
    # Disable terminal prompts entirely so we fail fast instead of hanging
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "true",
        "GIT_CONFIG_GLOBAL": "",
        "GIT_CONFIG_SYSTEM": "",
        "GIT_SSH_COMMAND": get_git_ssh_command(),
    })
    
    base_cmd = ["git", "-c", "credential.helper="]  # Disable credential helpers
    full_cmd = base_cmd + args

    logging.debug("Running git command: %s", " ".join(full_cmd))

    return safe_run_command(full_cmd, cwd=cwd, env=env)


def create_update_branch(
    repo_dir: str, namespace: str, name: str, new_version: str
) -> Optional[str]:
    """Create a new branch for the HelmRelease update, or reuse existing remote branch."""
    try:
        # Generate branch name
        branch_name = f"update-{namespace}-{name}-{new_version}".replace(".", "-")

        # First check if remote branch exists
        if check_branch_exists_on_remote(repo_dir, branch_name):
            logging.info(
                "🔄 Remote branch %s already exists, checking it out", branch_name
            )

            # Try multiple approaches to fetch and checkout the remote branch
            success = False

            # Approach 1: Fetch the specific branch directly
            code, out, err = _run_git_command(
                ["fetch", "origin", f"{branch_name}:{branch_name}"], cwd=repo_dir
            )
            if code == 0:
                logging.debug("Successfully fetched branch %s directly", branch_name)
                # Successfully fetched the branch, now we can checkout locally
                code, out, err = _run_git_command(
                    ["checkout", branch_name], cwd=repo_dir
                )
                if code == 0:
                    success = True
                    logging.debug(
                        "Successfully checked out fetched branch %s", branch_name
                    )
                else:
                    logging.debug(
                        "Failed to checkout fetched branch %s: %s",
                        branch_name,
                        err.strip(),
                    )
            else:
                logging.debug("Direct branch fetch failed: %s", err.strip())

            # Approach 2: If direct fetch failed, try general fetch + checkout
            if not success:
                code, out, err = _run_git_command(["fetch", "origin"], cwd=repo_dir)
                if code != 0:
                    logging.warning("Failed to fetch from origin: %s", err.strip())

                # Check if we already have a local branch with this name
                if check_branch_exists_locally(repo_dir, branch_name):
                    # Local branch exists, just checkout and pull latest
                    code, out, err = _run_git_command(
                        ["checkout", branch_name], cwd=repo_dir
                    )
                    if code == 0:
                        success = True
                        # Pull latest changes from remote
                        code, out, err = _run_git_command(
                            ["pull", "origin", branch_name], cwd=repo_dir
                        )
                        if code != 0:
                            logging.warning(
                                "Failed to pull latest changes for branch %s: %s",
                                branch_name,
                                err.strip(),
                            )
                            # Continue anyway, we're on the branch
                    else:
                        logging.debug(
                            "Failed to checkout existing local branch %s: %s",
                            branch_name,
                            err.strip(),
                        )

                # Approach 3: Create local branch from remote reference
                if not success:
                    # Try to checkout the remote branch using the remote reference directly
                    code, out, err = _run_git_command(
                        [
                            "checkout",
                            "-b",
                            branch_name,
                            f"remotes/origin/{branch_name}",
                        ],
                        cwd=repo_dir,
                    )
                    if code == 0:
                        success = True
                        logging.debug(
                            "Successfully created branch from remotes/origin/%s",
                            branch_name,
                        )
                    else:
                        logging.debug(
                            "Failed to checkout from remotes/origin/%s: %s",
                            branch_name,
                            err.strip(),
                        )

                        # Last resort: try with just origin/branch_name
                        code, out, err = _run_git_command(
                            ["checkout", "-b", branch_name, f"origin/{branch_name}"],
                            cwd=repo_dir,
                        )
                        if code == 0:
                            success = True
                            logging.debug(
                                "Successfully created branch from origin/%s",
                                branch_name,
                            )
                        else:
                            logging.debug(
                                "Failed to checkout from origin/%s: %s",
                                branch_name,
                                err.strip(),
                            )

            if not success:
                logging.error(
                    "All approaches failed to checkout remote branch %s", branch_name
                )
                return None

            logging.info("✅ Checked out existing remote branch: %s", branch_name)
            return branch_name

        # Check if branch already exists locally (but not on remote)
        elif check_branch_exists_locally(repo_dir, branch_name):
            logging.info(
                "🔄 Branch %s exists locally but not on remote, switching to it",
                branch_name,
            )

            # Switch to existing local branch
            code, out, err = _run_git_command(["checkout", branch_name], cwd=repo_dir)
            if code != 0:
                logging.error(
                    "Failed to checkout existing local branch %s: %s",
                    branch_name,
                    err.strip(),
                )
                return None

            logging.info("✅ Switched to existing local branch: %s", branch_name)
            return branch_name

        # Branch doesn't exist locally or remotely, create it
        logging.info("Creating new branch: %s", branch_name)

        # Checkout main/master branch first
        code, out, err = _run_git_command(["checkout", "main"], cwd=repo_dir)
        if code != 0:
            # Try master if main doesn't exist
            code, out, err = _run_git_command(["checkout", "master"], cwd=repo_dir)
            if code != 0:
                logging.error("Failed to checkout main/master branch: %s", err.strip())
                return None

        # Pull latest changes
        code, out, err = _run_git_command(["pull", "origin", "main"], cwd=repo_dir)
        if code != 0:
            # Try master if main doesn't exist
            code, out, err = _run_git_command(
                ["pull", "origin", "master"], cwd=repo_dir
            )
            if code != 0:
                logging.error("Failed to pull latest changes: %s", err.strip())
                return None

        # Create and checkout new branch
        code, out, err = _run_git_command(["checkout", "-b", branch_name], cwd=repo_dir)
        if code != 0:
            logging.error("Failed to create branch %s: %s", branch_name, err.strip())
            return None

        logging.info("✅ Successfully created branch: %s", branch_name)
        return branch_name

    except Exception as e:
        logging.exception("Error creating update branch")
        return None


def update_helm_release_manifest(
    repo_dir: str, manifest_path: str, new_version: str, current_version: str
) -> bool:
    """Update the HelmRelease manifest with the new version, preserving original formatting."""
    try:
        full_path = Path(repo_dir) / manifest_path
        logging.info("Updating manifest: %s", full_path)

        # Read the manifest file as text to preserve formatting
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check if the file already contains the target version
        import re

        # We need to check if the target version is present, potentially with or without 'v'
        # This prevents redundant updates if we run multiple times
        target_versions = [str(new_version)]
        if str(new_version).startswith("v"):
            target_versions.append(str(new_version)[1:])
        else:
            target_versions.append("v" + str(new_version))

        for t_ver in target_versions:
            target_version_patterns = [
                r"(^\s*version:\s*)" + re.escape(t_ver) + r"(\s*$)",
                r'(^\s*version:\s*["\'])' + re.escape(t_ver) + r'(["\']\s*$)',
            ]
            for pattern in target_version_patterns:
                if re.search(pattern, content, re.MULTILINE):
                    logging.info(
                        "✅ Manifest already contains target version %s (matched %s), no update needed",
                        new_version,
                        t_ver
                    )
                    return True

        # Generate variations of the current version to search for
        versions_to_search = [str(current_version)]
        if str(current_version).startswith("v"):
            versions_to_search.append(str(current_version)[1:])
        else:
            versions_to_search.append("v" + str(current_version))
        versions_to_search = list(dict.fromkeys(versions_to_search))

        logging.debug("Searching for current versions: %s", versions_to_search)

        updated = False
        for version_to_find in versions_to_search:
            # Pattern to match version field in chart spec
            patterns = [
                # Standard format: version: old_version
                r"(^\s*version:\s*)" + re.escape(version_to_find) + r"(\s*$)",
                # With quotes: version: "old_version"
                r'(^\s*version:\s*["\'])'
                + re.escape(version_to_find)
                + r'(["\']\s*$)',
            ]

            for pattern in patterns:
                if re.search(pattern, content, re.MULTILINE):
                    # Determine how to format the new version based on what we found to preserve convention
                    matched_has_v = version_to_find.startswith("v")
                    
                    final_new_version = str(new_version)
                    if matched_has_v and not final_new_version.startswith("v"):
                         final_new_version = "v" + final_new_version
                    elif not matched_has_v and final_new_version.startswith("v"):
                         final_new_version = final_new_version[1:]

                    # Use a lambda function to avoid backreference issues in the replacement string
                    def replacement(match):
                        return match.group(1) + final_new_version + match.group(2)

                    content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
                    updated = True
                    logging.info(
                        "Updated version from %s to %s in manifest (matched %s)",
                        current_version,
                        final_new_version,
                        version_to_find
                    )
                    break
            if updated:
                break

        if not updated:
            logging.warning(
                "No version field found to update in manifest (searched for: %s)",
                versions_to_search,
            )
            return False

        # Write back the content preserving original formatting
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

        logging.info("✅ Successfully updated manifest with version %s", new_version)
        return True

    except Exception as e:
        logging.exception("Error updating HelmRelease manifest")
        return False


def update_oci_repository_manifest(
    repo_dir: str, oci_repo_name: str, oci_repo_namespace: str, new_version: str, current_version: str
) -> bool:
    """Update the OCIRepository manifest with the new version, preserving original formatting."""
    try:
        # Find the OCIRepository manifest file
        # Look in common locations for FluxCD manifests
        possible_paths = [
            # Common FluxCD patterns
            f"clusters/*/helmrepositories/{oci_repo_namespace}/{oci_repo_name}.yaml",
            f"clusters/*/helmrepositories/helmrepository-{oci_repo_name}.yaml",
            f"clusters/*/helmrepositories/{oci_repo_name}.yaml",
            f"helmrepositories/{oci_repo_namespace}/{oci_repo_name}.yaml",
            f"helmrepositories/helmrepository-{oci_repo_name}.yaml",
            f"helmrepositories/{oci_repo_name}.yaml",
            # Generic searches
            f"**/{oci_repo_name}.yaml",
            f"**/helmrepository-{oci_repo_name}.yaml",
            f"**/*{oci_repo_name}*.yaml",
        ]

        logging.info("Searching for OCIRepository manifest %s/%s in repo: %s", oci_repo_namespace, oci_repo_name, repo_dir)

        manifest_path = None
        for path_pattern in possible_paths:
            try:
                logging.debug("Trying pattern: %s", path_pattern)
                matches = list(Path(repo_dir).glob(path_pattern))
                if matches:
                    manifest_path = matches[0].relative_to(repo_dir)
                    logging.info("✅ Found OCIRepository manifest: %s", manifest_path)
                    break
            except Exception as e:
                logging.debug("Error with pattern %s: %s", path_pattern, e)
                continue

        if not manifest_path:
            # Fallback: search for YAML files containing the OCIRepository by content
            logging.info("🔍 Fallback search: looking for YAML files containing OCIRepository %s/%s", oci_repo_namespace, oci_repo_name)
            try:
                for yaml_file in Path(repo_dir).rglob("*.yaml"):
                    try:
                        with open(yaml_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if f'kind: OCIRepository' in content and f'name: {oci_repo_name}' in content:
                                # Check if namespace matches (if specified in the file)
                                if f'namespace: {oci_repo_namespace}' in content or oci_repo_namespace in str(yaml_file):
                                    manifest_path = yaml_file.relative_to(repo_dir)
                                    logging.info("✅ Found OCIRepository manifest by content search: %s", manifest_path)
                                    break
                    except Exception:
                        continue
            except Exception as e:
                logging.debug("Content search failed: %s", e)

        if not manifest_path:
            logging.error("❌ Could not find OCIRepository manifest for %s/%s. Searched patterns: %s",
                         oci_repo_namespace, oci_repo_name, possible_paths)
            return False

        full_path = Path(repo_dir) / manifest_path
        logging.info("Updating OCIRepository manifest: %s", full_path)

        # Read the manifest file as text to preserve formatting
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check if the file already contains the target version
        import re

        # Check if the file already contains the target version
        import re

        # We need to check if the target version is present, potentially with or without 'v'
        target_versions = [str(new_version)]
        if str(new_version).startswith("v"):
            target_versions.append(str(new_version)[1:])
        else:
            target_versions.append("v" + str(new_version))

        for t_ver in target_versions:
            target_tag_patterns = [
                r"(^\s*tag:\s*)" + re.escape(t_ver) + r"(\s*$)",
                r'(^\s*tag:\s*["\'])' + re.escape(t_ver) + r'(["\']\s*$)',
            ]
            for pattern in target_tag_patterns:
                if re.search(pattern, content, re.MULTILINE):
                    logging.info(
                        "✅ OCIRepository already contains target tag %s (matched %s), no update needed",
                        new_version,
                        t_ver
                    )
                    return True

        # Generate variations of the current version to search for
        versions_to_search = [str(current_version)]
        if str(current_version).startswith("v"):
            versions_to_search.append(str(current_version)[1:])
        else:
            versions_to_search.append("v" + str(current_version))
        versions_to_search = list(dict.fromkeys(versions_to_search))

        logging.debug("Searching for current tags: %s", versions_to_search)

        updated = False
        for version_to_find in versions_to_search:
            # Update the tag field under spec.ref
            tag_patterns = [
                r"(^\s*tag:\s*)" + re.escape(version_to_find) + r"(\s*$)",
                r'(^\s*tag:\s*["\'])' + re.escape(version_to_find) + r'(["\']\s*$)',
            ]

            for pattern in tag_patterns:
                if re.search(pattern, content, re.MULTILINE):
                    # Determine how to format the new version based on what we found to preserve convention
                    matched_has_v = version_to_find.startswith("v")
                    
                    final_new_version = str(new_version)
                    if matched_has_v and not final_new_version.startswith("v"):
                         final_new_version = "v" + final_new_version
                    elif not matched_has_v and final_new_version.startswith("v"):
                         final_new_version = final_new_version[1:]

                    def replacement(match):
                        return match.group(1) + final_new_version + match.group(2)

                    content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
                    updated = True
                    logging.info(
                        "Updated OCIRepository tag from %s to %s (matched %s)",
                        current_version,
                        final_new_version,
                        version_to_find
                    )
                    break
            if updated:
                break

        if not updated:
            logging.warning(
                "No tag field found to update in OCIRepository (searched for: %s)",
                versions_to_search,
            )
            return False

        # Write back the content preserving original formatting
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

        logging.info("✅ Successfully updated OCIRepository with tag %s", new_version)
        return True

    except Exception as e:
        logging.exception("Error updating OCIRepository manifest")
        return False


def update_existing_pr_with_oci_info(
    github_client: Github, pr_url: str, oci_info: Dict[str, Any]
) -> bool:
    """
    Update an existing PR with OCI information if it's missing.

    Args:
        github_client: GitHub client
        pr_url: URL of the existing PR
        oci_info: Dictionary with OCI information (oci_url, app_version)

    Returns:
        True if PR was updated, False otherwise
    """
    try:
        if not GITHUB_REPOSITORY or not oci_info:
            return False

        owner, repo_name = parse_github_repository(GITHUB_REPOSITORY)
        repo = github_client.get_repo(f"{owner}/{repo_name}")

        # Extract PR number from URL
        pr_number = int(pr_url.split('/')[-1])
        pr = repo.get_pull(pr_number)

        current_body = pr.body or ""

        # Check if OCI information is already present
        has_oci_section = "### OCI Chart Information" in current_body
        has_app_version = oci_info.get('app_version') and f"**App Version:** {oci_info['app_version']}" in current_body

        if has_oci_section and (not oci_info.get('app_version') or has_app_version):
            logging.debug("PR %s already contains OCI information, skipping update", pr_url)
            return False

        # Build OCI information section
        oci_section = "\n### OCI Chart Information\n"
        if oci_info.get('oci_url'):
            oci_section += f"- **OCI Registry:** {oci_info['oci_url']}\n"
        if oci_info.get('app_version'):
            oci_section += f"- **App Version:** {oci_info['app_version']}\n"
            oci_section += "\n⚠️ **Important:** Please verify this app version meets your stability requirements before merging.\n"

        # Find where to insert OCI section (after the Changes section)
        if "### Changes" in current_body:
            # Insert after Changes section
            changes_end = current_body.find("\n### What this PR does")
            if changes_end == -1:
                changes_end = current_body.find("\n### Testing")
            if changes_end == -1:
                changes_end = len(current_body)

            new_body = current_body[:changes_end] + oci_section + current_body[changes_end:]
        else:
            # Append to end if no Changes section found
            new_body = current_body + oci_section

        # Update the PR
        pr.edit(body=new_body)
        logging.info("✅ Updated existing PR %s with OCI information", pr_url)
        return True

    except Exception as e:
        logging.exception("Failed to update existing PR %s with OCI info", pr_url)
        return False


def inspect_helm_chart_appversion(oci_url: str, version: str) -> Optional[str]:
    """
    Download and inspect a Helm chart to extract the appVersion from Chart.yaml.

    Args:
        oci_url: The OCI registry URL (e.g., "oci://ghcr.io/berriai/litellm-helm")
        version: The chart version to inspect

    Returns:
        The appVersion string if found, None otherwise
    """
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)

            # Pull the Helm chart
            chart_ref = f"{oci_url}:{version}"
            logging.debug("Pulling Helm chart: %s", chart_ref)

            pull_cmd = ["helm", "pull", chart_ref, "--destination", str(temp_dir_path)]
            result = subprocess.run(
                pull_cmd,
                capture_output=True,
                text=True,
                timeout=60  # 60 second timeout
            )

            if result.returncode != 0:
                logging.warning("Failed to pull Helm chart %s: %s", chart_ref, result.stderr)
                return None

            # Find the downloaded .tgz file
            tgz_files = list(temp_dir_path.glob("*.tgz"))
            if not tgz_files:
                logging.warning("No .tgz file found after pulling %s", chart_ref)
                return None

            chart_tgz = tgz_files[0]
            logging.debug("Downloaded chart: %s", chart_tgz)

            # Extract the Chart.yaml from the tarball
            with tarfile.open(chart_tgz, 'r:gz') as tar:
                # Look for Chart.yaml in the root of the tarball
                chart_yaml_member = None
                for member in tar.getmembers():
                    if member.name.endswith('/Chart.yaml') or member.name == 'Chart.yaml':
                        chart_yaml_member = member
                        break

                if not chart_yaml_member:
                    logging.warning("Chart.yaml not found in %s", chart_tgz)
                    return None

                # Extract Chart.yaml content
                chart_yaml_content = tar.extractfile(chart_yaml_member)
                if chart_yaml_content:
                    chart_data = yaml.safe_load(chart_yaml_content)
                    app_version = chart_data.get('appVersion')
                    if app_version:
                        logging.info("✅ Found appVersion '%s' in chart %s:%s", app_version, oci_url, version)
                        return str(app_version)

                logging.warning("appVersion not found in Chart.yaml of %s", chart_ref)
                return None

    except subprocess.TimeoutExpired:
        logging.warning("Timeout pulling Helm chart %s:%s", oci_url, version)
        return None
    except Exception as e:
        logging.exception("Error inspecting Helm chart %s:%s", oci_url, version)
        return None


def check_branch_exists_on_remote(repo_dir: str, branch_name: str) -> bool:
    """Check if a branch exists on the remote repository."""
    try:
        code, out, _ = _run_git_command(
            ["ls-remote", "--heads", "origin", branch_name], cwd=repo_dir
        )
        return code == 0 and bool(out.strip())
    except Exception:
        return False


def check_branch_exists_locally(repo_dir: str, branch_name: str) -> bool:
    """Check if a branch exists locally."""
    try:
        code, _, _ = _run_git_command(
            ["show-ref", "--verify", "--quiet", f"refs/heads/{branch_name}"],
            cwd=repo_dir,
        )
        return code == 0
    except Exception:
        return False


def check_if_pr_already_exists(
    github_client: Github, namespace: str, name: str, branch_name: str, new_version: str
) -> Optional[str]:
    """Check if a PR already exists for this update (open, closed, or merged)."""
    try:
        if not GITHUB_REPOSITORY:
            return None

        owner, repo_name = parse_github_repository(GITHUB_REPOSITORY)
        repo = github_client.get_repo(f"{owner}/{repo_name}")

        # Check both open and closed PRs
        for state in ["open", "closed"]:
            pulls = repo.get_pulls(state=state, head=f"{owner}:{branch_name}")

            # Check if any PR matches our update by branch name (most specific check)
            title_pattern = f"Update {name} in namespace {namespace}"
            for pr in pulls:
                if title_pattern in pr.title:
                    state_desc = "open" if state == "open" else ("merged" if pr.merged else "closed")
                    logging.info(
                        "✅ Found existing %s PR for %s/%s: %s", state_desc, namespace, name, pr.html_url
                    )
                    return pr.html_url

        # Also check for any PR with the same title pattern regardless of branch (broader check)
        # This catches cases where PRs were created with different branch names but same title
        for state in ["open", "closed"]:
            pulls = repo.get_pulls(state=state)

            for pr in pulls:
                if title_pattern in pr.title:
                    # Additional check: ensure the PR is for the same version
                    if f"to version {new_version}" in pr.body:
                        state_desc = "open" if state == "open" else ("merged" if pr.merged else "closed")
                        logging.info(
                            "✅ Found existing %s PR for %s/%s version %s: %s",
                            state_desc, namespace, name, new_version, pr.html_url
                        )
                        return pr.html_url

        return None
    except Exception as e:
        logging.debug("Error checking for existing PR: %s", str(e))
        return None


def commit_and_push_changes(
    repo_dir: str,
    branch_name: str,
    namespace: str,
    name: str,
    current_version: str,
    new_version: str,
    github_client: Optional[Github] = None,
) -> bool:
    """Commit the changes and push the branch to remote."""
    try:
        # Configure git user identity if not already set
        logging.debug("Configuring git user identity...")

        # Set git user name and email for commits
        git_user_name = os.getenv("GIT_USER_NAME", "fluxcd-helm-upgrader")
        git_user_email = os.getenv(
            "GIT_USER_EMAIL", "fluxcd-helm-upgrader@noreply.local"
        )

        # Configure git user identity
        code, out, err = _run_git_command(
            ["config", "user.name", git_user_name], cwd=repo_dir
        )
        if code != 0:
            logging.warning("Failed to set git user name: %s", err.strip())

        code, out, err = _run_git_command(
            ["config", "user.email", git_user_email], cwd=repo_dir
        )
        if code != 0:
            logging.warning("Failed to set git user email: %s", err.strip())

        # First, check if the branch already exists on remote and if PR already exists
        branch_exists_on_remote = check_branch_exists_on_remote(repo_dir, branch_name)

        if branch_exists_on_remote:
            logging.info(
                "🔄 Branch %s already exists on remote, will force push", branch_name
            )
            # Note: PR existence is now checked earlier in the flow to avoid unnecessary operations

        # Add the changed file
        code, out, err = _run_git_command(["add", "."], cwd=repo_dir)
        if code != 0:
            logging.error("Failed to add files to git: %s", err.strip(), extra={"operation": "add", "status": "failed"})
            METRICS['git_operations_total'].labels(operation="add", status="failed").inc()
            return False
        METRICS['git_operations_total'].labels(operation="add", status="success").inc()

        # Check if there are any changes to commit
        code, out, err = _run_git_command(["status", "--porcelain"], cwd=repo_dir)
        if code != 0:
            logging.error("Failed to check git status: %s", err.strip())
            return False

        if not out.strip():
            logging.info("No changes to commit (manifest may already be up to date)")
            return True  # Not an error, just nothing to do

        # Create commit message
        commit_message = f"Update {name} in namespace {namespace} from {current_version} to {new_version}"
        code, out, err = _run_git_command(
            ["commit", "-m", commit_message], cwd=repo_dir
        )
        if code != 0:
            logging.error("Failed to commit changes: %s", err.strip(), extra={"operation": "commit", "status": "failed"})
            METRICS['git_operations_total'].labels(operation="commit", status="failed").inc()
            return False
        METRICS['git_operations_total'].labels(operation="commit", status="success").inc()

        logging.info("✅ Changes committed with message: %s", commit_message)

        # Push the branch to remote
        push_args = ["push", "-u", "origin", branch_name]

        # Force push if the branch already exists on remote OR if GIT_FORCE_PUSH is set
        if branch_exists_on_remote or GIT_FORCE_PUSH:
            push_args.insert(1, "--force")
            if branch_exists_on_remote:
                logging.info(
                    "🔄 Force pushing to existing remote branch %s for latest commit reference",
                    branch_name,
                )
            else:
                logging.warning("Force pushing branch %s", branch_name)

        code, out, err = _run_git_command(push_args, cwd=repo_dir)
        if code != 0:
            logging.error("Failed to push branch %s: %s", branch_name, err.strip(), extra={"operation": "push", "status": "failed"})
            METRICS['git_operations_total'].labels(operation="push", status="failed").inc()
            if "non-fast-forward" in err or "Updates were rejected" in err:
                logging.info(
                    "💡 Tip: Set GIT_FORCE_PUSH=true to force push existing branches"
                )
            return False
        METRICS['git_operations_total'].labels(operation="push", status="success").inc()

        logging.info("✅ Successfully pushed branch: %s", branch_name)
        return True

    except Exception as e:
        logging.exception("Error committing and pushing changes")
        return False


def create_github_pull_request(
    github_client: Github,
    namespace: str,
    name: str,
    current_version: str,
    new_version: str,
    branch_name: str,
    manifest_path: str,
    oci_info: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Create a GitHub Pull Request for the HelmRelease update."""
    if not GITHUB_REPOSITORY:
        logging.error("GITHUB_REPOSITORY not configured")
        return None

    try:
        # Parse repository owner/repo
        try:
            owner, repo_name = parse_github_repository(GITHUB_REPOSITORY)
        except ValueError as e:
            logging.error(str(e))
            return None

        # Get the repository
        try:
            repo = github_client.get_repo(f"{owner}/{repo_name}")
        except GithubException as e:
            if e.status == 403:
                logging.error(
                    "❌ GitHub token lacks permission to access repository %s/%s",
                    owner,
                    repo_name,
                )
                logging.error(
                    "Please ensure the token has 'repo' permissions for this repository"
                )
                return None
            elif e.status == 404:
                logging.error(
                    "❌ Repository %s/%s not found or not accessible", owner, repo_name
                )
                logging.error("Please verify the GITHUB_REPOSITORY configuration")
                return None
            else:
                logging.error(
                    "❌ Failed to access repository %s/%s: %s", owner, repo_name, str(e)
                )
                return None

        # Determine base branch (main or master)
        # First check if user provided an override
        if GITHUB_DEFAULT_BRANCH:
            base_branch = GITHUB_DEFAULT_BRANCH
            logging.debug("Using user-specified default branch: %s", base_branch)
        else:
            # Try to get the default branch from repository info (this doesn't require branch read permissions)
            try:
                base_branch = repo.default_branch
                if base_branch:
                    logging.debug("Repository default branch: %s", base_branch)
                else:
                    # If default_branch is not available, use common default
                    base_branch = "main"
                    logging.debug(
                        "Repository default branch not available, using 'main'"
                    )
            except GithubException as e:
                if e.status == 403:
                    logging.debug(
                        "Cannot read repository info due to permissions, using 'main'"
                    )
                    base_branch = "main"
                else:
                    logging.warning(
                        "Error getting repository info: %s, using 'main'", str(e)
                    )
                    base_branch = "main"

        # Note: We skip branch validation via GitHub API since:
        # 1. We already know the head branch exists (we just pushed it)
        # 2. The base branch is the repository default (main/master)
        # 3. PR creation will fail with proper errors if branches don't exist
        # 4. This avoids requiring additional GitHub token permissions beyond PR creation
        logging.debug(
            "Using head branch: %s, base branch: %s", branch_name, base_branch
        )

        # Create PR title
        title = f"Update {name} in namespace {namespace} to version {new_version}"

        # Create PR body with detailed information
        # Build OCI information section if available
        oci_section = ""
        if oci_info:
            oci_url = oci_info.get('oci_url')
            app_version = oci_info.get('app_version')
            if oci_url or app_version:
                oci_section = "\n### OCI Chart Information\n"
                if oci_url:
                    oci_section += f"- **OCI Registry:** {oci_url}\n"
                if app_version:
                    oci_section += f"- **App Version:** {app_version}\n"
                    oci_section += "\n⚠️ **Important:** Please verify this app version meets your stability requirements before merging.\n"

        body = f"""## Helm Chart Update

**Application:** {name}
**Namespace:** {namespace}
**Current Version:** {current_version}
**New Version:** {new_version}

### Changes
- Updated HelmRelease manifest: `{manifest_path}`
- Version updated from `{current_version}` to `{new_version}`{oci_section}

### What this PR does
This pull request updates the HelmRelease for {name} in namespace {namespace} to the latest available version {new_version}.

The update was automatically generated by the FluxCD Helm upgrader tool.

### Testing
Please review the changes and test in a development environment before merging.
"""

        # Create the pull request with retry logic for specific errors
        max_retries = 3
        for attempt in range(max_retries):
            try:
                pr = repo.create_pull(
                    title=title, body=body, head=branch_name, base=base_branch
                )

                logging.info("✅ Successfully created Pull Request: %s", pr.html_url)
                METRICS['github_api_calls_total'].labels(operation="create_pull_request", status="success").inc()

                # Assign user to the PR if configured
                assignee = determine_github_assignee(namespace, name)
                if assignee:
                    try:
                        pr.add_to_assignees(assignee)
                        logging.info("✅ Successfully assigned user '%s' to PR: %s", assignee, pr.html_url)
                        METRICS['github_api_calls_total'].labels(operation="assign_pr", status="success").inc()
                    except GithubException as assign_error:
                        logging.warning("⚠️  Failed to assign user '%s' to PR: %s", assignee, str(assign_error))
                        METRICS['github_api_calls_total'].labels(operation="assign_pr", status="failed").inc()
                    except Exception as assign_error:
                        logging.warning("⚠️  Unexpected error assigning user '%s' to PR: %s", assignee, str(assign_error))
                        METRICS['github_api_calls_total'].labels(operation="assign_pr", status="error").inc()

                return pr.html_url

            except GithubException as e:
                error_message = str(e).lower()
                if "not all refs are readable" in error_message:
                    if attempt < max_retries - 1:
                        wait_time = (attempt + 1) * 2  # 2, 4, 6 seconds
                        logging.warning(
                            "⚠️  'Not all refs are readable' error, retrying in %d seconds... (attempt %d/%d)",
                            wait_time,
                            attempt + 1,
                            max_retries,
                        )
                        import time

                        time.sleep(wait_time)
                        continue
                    else:
                        logging.error(
                            "❌ 'Not all refs are readable' error persists after %d retries",
                            max_retries,
                        )
                        logging.error(
                            "This usually indicates a permission issue or GitHub indexing delay"
                        )
                        logging.error(
                            "Please ensure the GitHub token has 'repo' permissions and try again later"
                        )
                        METRICS['github_api_calls_total'].labels(operation="create_pull_request", status="failed").inc()
                        return None
                else:
                    # Re-raise other GitHub exceptions
                    raise e

    except GithubException as e:
        error_message = str(e).lower()
        if "pull request already exists" in error_message:
            # This is actually a success case - the PR already exists
            logging.info("✅ Pull request already exists for this update")
            logging.debug("GitHub response: %s", str(e))
            # Try to find the existing PR URL and return it
            try:
                existing_pr = check_if_pr_already_exists(
                    github_client, namespace, name, branch_name, new_version
                )
                if existing_pr:
                    logging.info("🎯 Found existing PR: %s", existing_pr)
                    return existing_pr
            except Exception:
                pass
            return "PR already exists"  # Return something to indicate success
        elif "validation failed" in error_message and "custom" in error_message:
            logging.error("❌ GitHub validation error: %s", str(e))
            logging.error(
                "This often indicates permission issues or branch accessibility problems"
            )
            logging.error("Please check that:")
            logging.error("1. The GitHub token has 'repo' permissions")
            logging.error("2. The repository URL is correct")
            logging.error("3. The branch was pushed successfully")
            METRICS['github_api_calls_total'].labels(operation="create_pull_request", status="validation_failed").inc()
        else:
            logging.error("❌ Failed to create GitHub Pull Request: %s", str(e))
            METRICS['github_api_calls_total'].labels(operation="create_pull_request", status="failed").inc()
        return None
    except Exception as e:
        logging.exception("❌ Unexpected error creating GitHub Pull Request")
        return None


def ensure_repo_cloned_or_updated() -> Optional[str]:
    if not REPO_URL:
        logging.debug("No REPO_URL configured, skipping repository operations")
        return None

    clone_dir_path = Path(REPO_CLONE_DIR)
    repo_url = convert_to_ssh_url(REPO_URL)

    # Setup SSH configuration
    if not setup_ssh_config():
        logging.error("Failed to setup SSH configuration")
        return None

    # Validate SSH access
    if not validate_ssh_access(repo_url):
        logging.error(
            "SSH access validation failed. Please check SSH key permissions and repository access."
        )
        return None

    try:
        if not clone_dir_path.exists():
            # Clone repository for the first time
            clone_dir_path.mkdir(parents=True, exist_ok=True)
            clone_args: List[str] = ["clone", "--depth", "1"]
            if REPO_BRANCH:
                clone_args += ["--branch", REPO_BRANCH, "--single-branch"]
            clone_args += [repo_url, str(clone_dir_path)]

            logging.info("Cloning repository from %s...", repo_url)
            code, out, err = _run_git_command(clone_args)
            if code != 0:
                sanitized_err = err.strip()
                logging.error("Failed to clone repository: %s", sanitized_err)
                logging.error(
                    "SSH authentication failed. Please check: 1) SSH private key is mounted correctly, 2) Deploy key has read access to repository, 3) SSH configuration is correct"
                )
                return None
            logging.info("✅ Repository cloned successfully")
        else:
            # Update existing repository
            git_dir = clone_dir_path / ".git"
            if not git_dir.exists():
                logging.warning(
                    "Repository directory exists but is not a git repository, removing and re-cloning..."
                )
                try:
                    shutil.rmtree(clone_dir_path)
                except FileNotFoundError:
                    pass
                clone_dir_path.mkdir(parents=True, exist_ok=True)
                clone_args = ["clone", "--depth", "1"]
                if REPO_BRANCH:
                    clone_args += ["--branch", REPO_BRANCH, "--single-branch"]
                clone_args += [repo_url, str(clone_dir_path)]

                code, out, err = _run_git_command(clone_args)
                if code != 0:
                    sanitized_err = err.strip()
                    logging.error("Failed to re-clone repository: %s", sanitized_err)
                    return None
                logging.info("✅ Repository re-cloned successfully")
            else:
                # Update existing repository
                logging.debug("Updating existing repository...")
                code, out, err = _run_git_command(
                    ["fetch", "--tags", "--prune", "origin"], cwd=str(clone_dir_path)
                )
                if code != 0:
                    logging.error("Failed to fetch repository updates: %s", err.strip())
                    return str(clone_dir_path)

                # Determine branch to reset to
                branch = REPO_BRANCH
                if not branch:
                    code, out, err = _run_git_command(
                        ["symbolic-ref", "refs/remotes/origin/HEAD"],
                        cwd=str(clone_dir_path),
                    )
                    if code == 0 and out.strip().startswith("origin/"):
                        branch = out.strip().split("/", 1)[1]
                    else:
                        branch = "main"

                # Reset hard to remote branch
                code, out, err = _run_git_command(
                    ["reset", "--hard", f"remotes/origin/{branch}"],
                    cwd=str(clone_dir_path),
                )
                if code != 0:
                    logging.error(
                        "Failed to reset repository to origin/%s: %s",
                        branch,
                        err.strip(),
                    )
                    return str(clone_dir_path)

                # Clean untracked files
                _run_git_command(["clean", "-fdx"], cwd=str(clone_dir_path))
                logging.debug("✅ Repository updated successfully")

    except Exception:
        logging.exception("Failed preparing repository at %s", clone_dir_path)
        return None
    return str(clone_dir_path)


# Cache for manifest paths to avoid repeated file system searches
_manifest_cache: Dict[str, Optional[str]] = {}

def resolve_manifest_path_for_release(
    repo_dir: str, namespace: str, name: str
) -> Optional[str]:
    """Resolve manifest path with caching for performance."""
    cache_key = f"{repo_dir}:{namespace}:{name}"
    
    # Check cache first
    if cache_key in _manifest_cache:
        return _manifest_cache[cache_key]
    
    try:
        # Allow multiple patterns separated by ';'
        patterns = [p.strip() for p in REPO_SEARCH_PATTERN.split(";") if p.strip()]
        if not patterns:
            patterns = ["**/helmrelease*.y*ml"]
        
        repo_root = Path(repo_dir)
        
        for pattern in patterns:
            try:
                substituted = pattern.format(namespace=namespace, name=name)
            except Exception:
                substituted = pattern
            
            substituted = substituted.lstrip("/")
            
            for path in glob.glob(str(repo_root / substituted), recursive=True):
                p = Path(path)
                if not p.is_file():
                    continue
                
                try:
                    content = p.read_text(encoding="utf-8")
                    for doc in yaml.safe_load_all(content):
                        if not isinstance(doc, dict):
                            continue
                        if str(doc.get("kind")) != "HelmRelease":
                            continue
                        
                        metadata = doc.get("metadata") or {}
                        if metadata.get("name") != name:
                            continue
                        
                        # If namespace is present in file, ensure it matches; otherwise accept
                        file_ns = metadata.get("namespace")
                        if file_ns and file_ns != namespace:
                            continue
                        
                        result = str(p.relative_to(repo_root))
                        _manifest_cache[cache_key] = result
                        return result
                        
                except Exception:
                    # Ignore YAML parse errors for non-HelmRelease files
                    continue
        
        # Cache negative result
        _manifest_cache[cache_key] = None
        return None
        
    except Exception:
        logging.exception(
            "Error searching for HelmRelease manifest for %s/%s", namespace, name
        )
        _manifest_cache[cache_key] = None
        return None


def list_helm_releases(
    coapi: client.CustomObjectsApi,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    for version in HELM_RELEASE_VERSIONS:
        try:
            resp = coapi.list_cluster_custom_object(
                group=HELM_RELEASE_GROUP, version=version, plural="helmreleases"
            )
            items = resp.get("items", [])
            if items:
                logging.debug("Found %d HelmReleases using %s", len(items), version)
            else:
                logging.debug("No HelmReleases found using %s", version)
            METRICS['kubernetes_api_calls_total'].labels(operation="list_helmreleases", status="success").inc()
            return items, version
        except ApiException as e:
            if e.status in (404, 403):
                METRICS['kubernetes_api_calls_total'].labels(operation="list_helmreleases", status="not_found").inc()
                continue
            logging.exception("Failed listing HelmReleases for %s", version)
            METRICS['kubernetes_api_calls_total'].labels(operation="list_helmreleases", status="error").inc()
            continue
        except Exception:
            logging.exception("Unexpected error listing HelmReleases for %s", version)
            METRICS['kubernetes_api_calls_total'].labels(operation="list_helmreleases", status="error").inc()
            continue
    logging.warning(
        "HelmRelease CRD not found under known versions: %s", HELM_RELEASE_VERSIONS
    )
    return [], None


def get_namespaced_obj(
    coapi: client.CustomObjectsApi,
    group: str,
    versions: List[str],
    namespace: str,
    plural: str,
    name: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    for version in versions:
        try:
            obj = coapi.get_namespaced_custom_object(
                group=group,
                version=version,
                namespace=namespace,
                plural=plural,
                name=name,
            )
            return obj, version
        except ApiException as e:
            if e.status in (404, 403):
                continue
            logging.exception("Error getting %s/%s %s", group, version, plural)
            continue
        except Exception:
            logging.exception(
                "Unexpected error getting %s/%s %s", group, version, plural
            )
            continue
    return None, None


def get_helm_chart_for_release(
    coapi: client.CustomObjectsApi, hr: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    hr_ns = hr["metadata"]["namespace"]
    hr_name = hr["metadata"]["name"]
    chart_spec = (hr.get("spec") or {}).get("chart") or {}
    inner_spec = chart_spec.get("spec") or {}
    src_ref = inner_spec.get("sourceRef") or {}
    chart_ns = src_ref.get("namespace") or hr_ns
    chart_name = f"{hr_ns}-{hr_name}"
    chart, version = get_namespaced_obj(
        coapi, SOURCE_GROUP, SOURCE_VERSIONS, chart_ns, "helmcharts", chart_name
    )
    return chart, version


def get_helm_repository(
    coapi: client.CustomObjectsApi, namespace: str, name: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    repo, version = get_namespaced_obj(
        coapi, SOURCE_GROUP, SOURCE_VERSIONS, namespace, "helmrepositories", name
    )
    return repo, version


def get_oci_repository(
    coapi: client.CustomObjectsApi, namespace: str, name: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    repo, version = get_namespaced_obj(
        coapi, SOURCE_GROUP, SOURCE_VERSIONS, namespace, "ocirepositories", name
    )
    return repo, version


def resolve_repo_for_release(
    coapi: client.CustomObjectsApi, hr: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    spec = hr.get("spec") or {}

    # Check for chartRef first (OCI repositories)
    chart_ref = spec.get("chartRef")
    if chart_ref and chart_ref.get("kind") == "OCIRepository":
        # For OCI repositories, we can't fetch index like Helm repos, so return None
        # Nova handles OCI scanning differently
        return None

    # Prefer resolving through HelmChart, then fallback to HR.spec.chart.spec.sourceRef
    chart, _ = get_helm_chart_for_release(coapi, hr)
    if chart:
        src_ref = (chart.get("spec") or {}).get("sourceRef") or {}
        if src_ref.get("kind") == "HelmRepository":
            repo, _ = get_helm_repository(
                coapi,
                src_ref.get("namespace") or chart["metadata"]["namespace"],
                src_ref.get("name"),
            )
            if repo:
                return repo
        elif src_ref.get("kind") == "OCIRepository":
            # For OCI repositories, we can't fetch index like Helm repos, so return None
            # Nova handles OCI scanning differently
            return None
    chart_spec = (hr.get("spec") or {}).get("chart") or {}
    inner_spec = chart_spec.get("spec") or {}
    src_ref = inner_spec.get("sourceRef") or {}
    if src_ref.get("kind") == "HelmRepository":
        repo, _ = get_helm_repository(
            coapi,
            src_ref.get("namespace") or hr["metadata"]["namespace"],
            src_ref.get("name"),
        )
        if repo:
            return repo
    elif src_ref.get("kind") == "OCIRepository":
        # For OCI repositories, we can't fetch index like Helm repos, so return None
        # Nova handles OCI scanning differently
        return None
    return None


def get_current_chart_name_and_version(
    coapi: client.CustomObjectsApi, hr: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    # Extract namespace and name for logging
    hr_ns = hr.get("metadata", {}).get("namespace", "unknown")
    hr_name = hr.get("metadata", {}).get("name", "unknown")

    spec = hr.get("spec") or {}

    # Check for chartRef first (used for OCI repositories)
    chart_ref = spec.get("chartRef")
    logging.info("%s/%s: checking chartRef: %s", hr_ns, hr_name, chart_ref)
    if chart_ref and chart_ref.get("kind") == "OCIRepository":
        # For OCI repositories with chartRef, extract chart name from OCIRepository
        try:
            oci_namespace = chart_ref.get("namespace") or hr["metadata"]["namespace"]
            oci_name = chart_ref.get("name")

            logging.debug("%s/%s: looking up OCIRepository %s/%s", hr_ns, hr_name, oci_namespace, oci_name)

            oci_repo, _ = get_oci_repository(coapi, oci_namespace, oci_name)
            if oci_repo:
                oci_spec = oci_repo.get("spec") or {}
                url = oci_spec.get("url", "")

                logging.debug("%s/%s: found OCIRepository with URL: %s", hr_ns, hr_name, url)

                if url.startswith("oci://"):
                    # Extract chart name from OCI URL like oci://ghcr.io/berriai/litellm-helm
                    path_parts = url.replace("oci://", "").split("/")
                    if len(path_parts) >= 2:
                        chart_name = path_parts[-1]
                        logging.debug("%s/%s: extracted chart name '%s' from OCI URL", hr_ns, hr_name, chart_name)
                    else:
                        chart_name = oci_name  # Fallback to OCIRepository name
                        logging.debug("%s/%s: using OCIRepository name '%s' as chart name", hr_ns, hr_name, chart_name)
                else:
                    chart_name = oci_name  # Fallback to OCIRepository name
                    logging.debug("%s/%s: URL doesn't start with oci://, using OCIRepository name '%s' as chart name", hr_ns, hr_name, chart_name)

                # Get version from OCIRepository spec.ref.tag or spec.ref.semver
                oci_ref = oci_spec.get("ref") or {}
                desired_version = oci_ref.get("tag") or oci_ref.get("semver")
                logging.debug("%s/%s: desired version from OCIRepository: %s", hr_ns, hr_name, desired_version)
            else:
                logging.debug("%s/%s: OCIRepository %s/%s not found", hr_ns, hr_name, oci_namespace, oci_name)
                chart_name = oci_name  # Fallback to OCIRepository name
                desired_version = None
        except Exception as e:
            logging.debug("Failed to resolve OCI repository for chartRef: %s", e)
            chart_name = chart_ref.get("name")  # Fallback to OCIRepository name
            desired_version = None

        # For chartRef, we need to get the current version from status
        status = hr.get("status") or {}
        applied = status.get("lastAppliedRevision") or status.get("lastAttemptedRevision")

        current_version: Optional[str]
        if applied:
            # Nova shows OCI versions with commit hashes like "0.1.805+94c7b2e9075a"
            # We need to extract just the version part
            if "+" in applied:
                # Split on "+" and take the first part (version)
                version_part = applied.split("+")[0]
                if parse_version(version_part):
                    current_version = version_part
                    logging.debug("%s/%s: extracted version '%s' from applied revision '%s'", hr_ns, hr_name, current_version, applied)
                else:
                    current_version = None
            elif parse_version(applied):
                current_version = applied
            else:
                # Try regex for OCI-style versions
                m = re.search(r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z\.-]+)?)", applied)
                if m:
                    candidate = m.group(1)
                    current_version = candidate if parse_version(candidate) else None
                    logging.debug("%s/%s: extracted version '%s' from applied revision '%s' using regex", hr_ns, hr_name, current_version, applied)
                else:
                    current_version = None
        else:
            current_version = desired_version  # Fallback to desired version

        logging.debug("%s/%s: final chart_name='%s', current_version='%s'", hr_ns, hr_name, chart_name, current_version)
        return chart_name, current_version

    # Handle traditional chart spec
    chart_node = spec.get("chart") or {}

    # Handle case where chart_node itself is a string (direct chart reference)
    if isinstance(chart_node, str):
        chart_name = chart_node
        chart_spec = {}
    else:
        chart_spec = chart_node.get("spec") or {}
        chart_name = chart_spec.get("chart") or chart_node.get("chart")

    # Handle repositoryRef case - chart name might be in a different location
    if not chart_name and "repositoryRef" in chart_node:
        # For repositoryRef, the chart name is usually the same as the HelmRelease name
        # or we might need to look it up from the HelmRepository
        hr_name_for_chart = hr.get("metadata", {}).get("name", "")
        # Remove common suffixes like version numbers
        chart_name = re.sub(r'-\d+.*$', '', hr_name_for_chart)

    # Handle OCIRepository case - try to extract chart name from OCI URL
    if not chart_name:
        # Check in chart_spec first
        source_ref = chart_spec.get("sourceRef") or {}
        if not source_ref:
            # Check at spec level directly (alternative structure)
            source_ref = spec.get("sourceRef") or {}

        if source_ref.get("kind") == "OCIRepository":
            logging.debug("%s/%s: found OCIRepository sourceRef: %s", hr_ns, hr_name, source_ref)
            # For OCI repositories, we need to look up the OCIRepository
            # and extract the chart name from its URL
            try:
                oci_repo, _ = get_oci_repository(
                    coapi,
                    source_ref.get("namespace") or hr["metadata"]["namespace"],
                    source_ref.get("name")
                )
                if oci_repo:
                    logging.debug("%s/%s: found OCI repo: %s", hr_ns, hr_name, oci_repo.get("spec"))
                    oci_spec = oci_repo.get("spec") or {}
                    url = oci_spec.get("url", "")
                    if url.startswith("oci://"):
                        # Extract chart name from OCI URL like oci://ghcr.io/berriai/litellm-helm
                        path_parts = url.replace("oci://", "").split("/")
                        if len(path_parts) >= 2:
                            # Last part is usually the chart name
                            chart_name = path_parts[-1]
                            logging.debug("%s/%s: extracted chart name from OCI URL: '%s'", hr_ns, hr_name, chart_name)
                else:
                    logging.debug("%s/%s: OCI repository not found: %s/%s", hr_ns, hr_name, source_ref.get("namespace"), source_ref.get("name"))
            except Exception as e:
                logging.debug("Failed to resolve OCI repository for chart name: %s", e)

    # Fallback: if still no chart name, use the HelmRelease name (common for OCI)
    if not chart_name:
        chart_name = hr.get("metadata", {}).get("name")
        logging.debug("%s/%s: using HelmRelease name as chart name: '%s'", hr_ns, hr_name, chart_name)

    # Debug logging for chart structure
    logging.debug("%s/%s chartRef: %s, chart_node: %s, chart_spec: %s, extracted chart_name: '%s'",
                 hr_ns, hr_name, spec.get("chartRef"), chart_node, chart_spec, chart_name or "None")

    # Prefer the actual applied revision from status if available
    status = hr.get("status") or {}
    applied = status.get("lastAppliedRevision") or status.get("lastAttemptedRevision")

    desired_version = chart_spec.get("version") or None

    # For OCI repositories, try to get version from the OCIRepository
    if not desired_version:
        source_ref = chart_spec.get("sourceRef") or {}
        if source_ref.get("kind") == "OCIRepository":
            try:
                oci_repo, _ = get_oci_repository(
                    coapi,
                    source_ref.get("namespace") or hr["metadata"]["namespace"],
                    source_ref.get("name")
                )
                if oci_repo:
                    oci_spec = oci_repo.get("spec") or {}
                    ref = oci_spec.get("ref") or {}
                    tag = ref.get("tag") or ref.get("semver")
                    if tag:
                        desired_version = tag
            except Exception as e:
                logging.debug("Failed to resolve OCI repository for version: %s", e)

    # Applied revision is typically the version; sometimes includes chart name (e.g. mychart-1.2.3 or mychart-1.2.3-rc.1)
    current_version: Optional[str]
    if applied:
        # 1) If applied is already a version string, accept it
        if parse_version(applied):
            current_version = applied
        # 2) If we know chart_name and applied starts with "{chart_name}-", take the suffix
        elif chart_name and applied.startswith(f"{chart_name}-"):
            candidate = applied[len(chart_name) + 1 :]
            current_version = candidate if parse_version(candidate) else None
        else:
            # 3) Try to extract a trailing semver (with optional leading 'v')
            m = re.search(
                r"(?:^|-)v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z\.-]+)?(?:\+[0-9A-Za-z\.-]+)?)$",
                applied,
            )
            if m:
                candidate = m.group(1)
                current_version = candidate if parse_version(candidate) else None
                if not chart_name:
                    # Trim trailing '-' if present before the version
                    prefix = applied[: m.start(1)]
                    if prefix.endswith("-"):
                        prefix = prefix[:-1]
                    chart_name = prefix or chart_name
            else:
                current_version = None
    else:
        current_version = desired_version

    return chart_name, current_version


# Cache for parsed versions to avoid repeated parsing
_version_cache: Dict[str, Optional[semver.VersionInfo]] = {}

def parse_version(text: Optional[str]) -> Optional[semver.VersionInfo]:
    """Parse version string with caching for performance."""
    if not text:
        return None
    
    # Check cache first
    if text in _version_cache:
        return _version_cache[text]
    
    raw = text.strip()
    if raw.startswith("v"):
        raw = raw[1:]
    
    try:
        version = semver.VersionInfo.parse(raw)
        _version_cache[text] = version
        return version
    except ValueError:
        _version_cache[text] = None
        return None


def fetch_repo_index(repo: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Prefer the artifact.url if present; fallback to spec.url + index.yaml
    artifact_url = ((repo.get("status") or {}).get("artifact") or {}).get("url")
    index_url = None
    if artifact_url and artifact_url.endswith("index.yaml"):
        index_url = artifact_url
    else:
        base = (repo.get("spec") or {}).get("url")
        if base:
            if not base.endswith("/"):
                base += "/"
            index_url = base + "index.yaml"
    if not index_url:
        return None
    try:
        resp = requests.get(index_url, timeout=REQUEST_TIMEOUT, headers=DEFAULT_HEADERS)
        resp.raise_for_status()
        # First attempt: use text as-is (requests decodes if Content-Encoding: gzip)
        try:
            return yaml.safe_load(resp.text)
        except Exception:
            # Fallbacks for servers serving gzipped content as application/gzip (no Content-Encoding)
            ct = (resp.headers.get("Content-Type") or "").lower()
            content = resp.content or b""
            if (
                content[:2] == b"\x1f\x8b"
                or "application/gzip" in ct
                or "application/x-gzip" in ct
            ):
                import gzip

                try:
                    decompressed = gzip.decompress(content)
                    text = decompressed.decode("utf-8", errors="replace")
                    return yaml.safe_load(text)
                except Exception:
                    logging.exception(
                        "Failed to decompress and parse gzipped index from %s (content-type=%s, length=%s)",
                        index_url,
                        ct,
                        len(content),
                    )
                    return None
            # Final fallback: try utf-8-sig decode in case of BOM or odd encodings
            try:
                text = content.decode("utf-8-sig", errors="strict")
                return yaml.safe_load(text)
            except Exception:
                logging.exception(
                    "Failed parsing repo index from %s (content-type=%s, length=%s)",
                    index_url,
                    ct,
                    len(content),
                )
                return None
    except Exception:
        logging.exception("Failed fetching repo index from %s", index_url)
        return None


def latest_available_version(
    index: Dict[str, Any], chart_name: str, include_prerelease: bool
) -> Optional[str]:
    """Find the latest available version from chart index with optimization."""
    entries = (index or {}).get("entries") or {}
    chart_entries = entries.get(chart_name) or []
    
    if not chart_entries:
        return None
    
    best_version: Optional[semver.VersionInfo] = None
    best_version_text: Optional[str] = None
    
    for entry in chart_entries:
        ver_text = entry.get("version")
        if not ver_text or entry.get("deprecated") is True:
            continue
            
        ver = parse_version(ver_text)
        if not ver:
            continue
            
        if not include_prerelease and ver.prerelease is not None:
            continue
            
        if best_version is None or ver > best_version:
            best_version = ver
            best_version_text = ver_text
    
    return best_version_text


def should_update(current_version_text: Optional[str], latest_version_text: Optional[str], include_prerelease: bool = False) -> bool:
    """
    Determine if an update should be performed based on version comparison.
    
    Returns True if latest_version_text is semantically greater than current_version_text.
    Returns False if latest_version_text is None, invalid, equal, or older.
    Returns True if current_version_text is None or invalid, but latest_version_text is valid (upgrade from unknown).
    Respects include_prerelease flag: if False, will return False for pre-release latest versions.
    """
    if not latest_version_text:
        return False
        
    latest_ver = parse_version(latest_version_text)
    if not latest_ver:
        return False
        
    # Check pre-release status
    if not include_prerelease and latest_ver.prerelease:
        return False
        
    if not current_version_text:
        # If no current version is installed/detected, we should install the latest
        return True
        
    current_ver = parse_version(current_version_text)
    if not current_ver:
        # If current version is invalid/unknown, we assume we should update to the valid latest
        return True
        
    # Only update if latest > current
    return latest_ver > current_ver



def clear_caches() -> None:
    """Clear all caches to prevent memory buildup."""
    global _version_cache, _manifest_cache
    _version_cache.clear()
    _manifest_cache.clear()
    logging.debug("Cleared performance caches")


def check_once(coapi: client.CustomObjectsApi) -> None:
    """Perform a single check cycle with metrics instrumentation."""
    start_time = time.time()
    
    try:
        releases, hr_version = list_helm_releases(coapi)
        if hr_version is None:
            logging.error("No HelmRelease API version available; skipping iteration", 
                         extra={"error_type": "api_version", "component": "kubernetes"})
            METRICS['errors_total'].labels(error_type="api_version", component="kubernetes").inc()
            return
        
        # Update metrics
        total_releases = len(releases)
        METRICS['helm_releases_total'].set(total_releases)
        
        logging.info("Starting HelmRelease check cycle", 
                    extra={"total_releases": total_releases, "api_version": hr_version})
        
    except Exception as e:
        logging.error("Failed to list HelmReleases", extra={"error_type": "list_releases", "component": "kubernetes"})
        METRICS['errors_total'].labels(error_type="list_releases", component="kubernetes").inc()
        return

    # Clone/update repository once at the beginning if REPO_URL is configured
    repo_dir = None
    if REPO_URL:
        logging.debug("Initializing repository access...")
        try:
            repo_dir = ensure_repo_cloned_or_updated()
            if not repo_dir:
                logging.warning("Repository access failed, continuing without manifest path resolution",
                              extra={"error_type": "repo_access", "component": "git"})
                METRICS['errors_total'].labels(error_type="repo_access", component="git").inc()
            else:
                METRICS['git_operations_total'].labels(operation="clone_or_update", status="success").inc()
        except Exception as e:
            logging.error("Repository operation failed", extra={"error_type": "repo_operation", "component": "git"})
            METRICS['git_operations_total'].labels(operation="clone_or_update", status="error").inc()
            METRICS['errors_total'].labels(error_type="repo_operation", component="git").inc()

    outdated_count = 0
    up_to_date_count = 0
    
    # Run nova scan
    logging.info("Running nova scan to detect outdated releases...")
    nova_integration = NovaIntegration()
    outdated_releases = nova_integration.get_outdated_releases()
    
    # Build lookup: (target_namespace, release_name) -> latest_version
    outdated_lookup = {}
    for r in outdated_releases:
        key = (r.get('namespace'), r.get('release'))
        if 'Latest' in r and 'version' in r['Latest']:
             if key in outdated_lookup:
                 logging.warning("Duplicate nova key %s/%s: replacing %s with %s", key[0], key[1], outdated_lookup[key], r['Latest']['version'])
             outdated_lookup[key] = r['Latest']['version']
             logging.debug("Nova outdated release: %s/%s chart='%s' -> %s", r.get('namespace'), r.get('release'), r.get('chartName'), r['Latest']['version'])

    for hr in releases:
        hr_ns = hr["metadata"]["namespace"]
        hr_name = hr["metadata"]["name"]
        
        chart_name, current_version_text = get_current_chart_name_and_version(coapi, hr)
        logging.debug("%s/%s: extracted chart_name='%s', current_version='%s'", hr_ns, hr_name, chart_name, current_version_text)
        if not chart_name:
            logging.info("%s/%s: chart name unknown; skipping", hr_ns, hr_name)
            continue
        if not current_version_text:
            logging.info("%s/%s: current version unknown; skipping", hr_ns, hr_name)
            continue

        # Determine release name and target namespace as Flux would
        spec = hr.get("spec", {})
        target_ns = spec.get("targetNamespace", hr_ns)
        release_name = spec.get("releaseName", hr_name)

        if target_ns != hr_ns or release_name != hr_name:
            logging.info("%s/%s maps to release %s/%s", hr_ns, hr_name, target_ns, release_name)
        else:
            logging.debug("%s/%s maps to release %s/%s", hr_ns, hr_name, target_ns, release_name)

        lookup_key = (target_ns, release_name)
        latest_text = outdated_lookup.get(lookup_key)
        if latest_text:
            logging.debug("Found match for %s/%s (lookup key: %s -> %s)", hr_ns, hr_name, lookup_key, latest_text)
        else:
            logging.debug("No match for %s/%s (lookup key: %s) - trying fallback method", hr_ns, hr_name, lookup_key)

        # Fallback: if Nova didn't find this release, use the classic method
        if not latest_text:
            logging.debug("%s/%s: Nova not found, using fallback method", hr_ns, hr_name)

            # Try to resolve the repository and check for updates using the classic method
            repo = resolve_repo_for_release(coapi, hr)
            if not repo:
                logging.debug(
                    "%s/%s: HelmRepository not resolved; skipping", hr_ns, hr_name
                )
                up_to_date_count += 1
                continue

            spec = repo.get("spec") or {}
            if spec.get("type") == "oci":
                logging.debug(
                    "%s/%s: OCI HelmRepository not supported in fallback method; skipping", hr_ns, hr_name
                )
                up_to_date_count += 1
                continue

            try:
                index = fetch_repo_index(repo)
                if not index:
                    logging.debug("%s/%s: unable to fetch repo index; skipping", hr_ns, hr_name)
                    METRICS['repository_index_fetches_total'].labels(status="failed").inc()
                    up_to_date_count += 1
                    continue
                METRICS['repository_index_fetches_total'].labels(status="success").inc()
            except Exception as e:
                logging.error("Failed to fetch repository index", extra={"error_type": "index_fetch", "component": "repository", "namespace": hr_ns, "hr_name": hr_name})
                METRICS['repository_index_fetches_total'].labels(status="error").inc()
                METRICS['errors_total'].labels(error_type="index_fetch", component="repository").inc()
                up_to_date_count += 1
                continue

            latest_text = latest_available_version(index, chart_name, INCLUDE_PRERELEASE)
            if not latest_text:
                logging.debug(
                    "%s/%s: no versions found in repo index for chart %s; assuming up-to-date",
                    hr_ns,
                    hr_name,
                    chart_name,
                )
                up_to_date_count += 1
                continue
            
            
        if not should_update(current_version_text, latest_text, include_prerelease=INCLUDE_PRERELEASE):
            logging.info("%s/%s: skipping update (%s is not > %s or pre-release filtered)", hr_ns, hr_name, latest_text, current_version_text)
            up_to_date_count += 1
            continue

        manifest_rel_path = None
        if repo_dir:
            manifest_rel_path = resolve_manifest_path_for_release(
                repo_dir, hr_ns, hr_name
            )
            if manifest_rel_path:
                 logging.info(
                    "📄 %s/%s -> %s",
                    hr_ns,
                    hr_name,
                    manifest_rel_path,
                )
            else:
                logging.info(
                    "No manifest found for %s/%s (pattern: %s) - skipping PR creation",
                    hr_ns,
                    hr_name,
                    REPO_SEARCH_PATTERN,
                )

        outdated_count += 1
        logging.info(
            "📈 Update available: %s/%s (%s -> %s)",
            hr_ns,
            hr_name,
            current_version_text,
            latest_text,
            extra={"namespace": hr_ns, "hr_name": hr_name, "current_version": current_version_text, "latest_version": latest_text, "status": "outdated"}
        )

        if GITHUB_TOKEN and repo_dir and manifest_rel_path:
            logging.info(
                "🔄 Processing GitHub PR creation for %s/%s", hr_ns, hr_name
            )

            github_client = create_github_client()
            if github_client:
                # Check if this is an OCI chartRef release and collect OCI information
                chart_ref = hr.get("spec", {}).get("chartRef")
                logging.info("%s/%s: checking for OCI chartRef - chart_ref: %s", hr_ns, hr_name, chart_ref)
                oci_info = None
                if chart_ref and chart_ref.get("kind") == "OCIRepository":
                    try:
                        oci_repo_name = chart_ref.get("name")
                        oci_repo_namespace = chart_ref.get("namespace") or hr_ns

                        # Get OCI URL from the OCIRepository we looked up earlier
                        oci_repo, _ = get_oci_repository(coapi, oci_repo_namespace, oci_repo_name)
                        if oci_repo:
                            oci_spec = oci_repo.get("spec") or {}
                            oci_url = oci_spec.get("url", "")

                            # Try to get appVersion from the new chart version
                            app_version = inspect_helm_chart_appversion(oci_url, latest_text)

                            if oci_url or app_version:
                                oci_info = {
                                    'oci_url': oci_url,
                                    'app_version': app_version
                                }
                                logging.info("📋 Collected OCI info for PR: %s", oci_info)
                    except Exception as e:
                        logging.warning("Failed to collect OCI info for PR: %s", e)

                branch_name = f"update-{hr_ns}-{hr_name}-{latest_text}".replace(
                    ".", "-"
                )

                existing_pr = check_if_pr_already_exists(
                    github_client, hr_ns, hr_name, branch_name, latest_text
                )
                if existing_pr:
                    logging.info(
                        "🎯 PR already exists for %s/%s: %s",
                        hr_ns,
                        hr_name,
                        existing_pr,
                    )

                    # Check if we need to update the existing PR with OCI information
                    if oci_info:
                        if update_existing_pr_with_oci_info(github_client, existing_pr, oci_info):
                            logging.info("📝 Updated existing PR with new OCI information")
                        else:
                            logging.debug("PR already has OCI information or update failed")

                    logging.info(
                        "✅ Skipping file operations since PR is already created"
                    )
                    continue  # Skip to next HelmRelease

                branch_name = create_update_branch(
                    repo_dir, hr_ns, hr_name, latest_text
                )
                if branch_name:

                    if chart_ref and chart_ref.get("kind") == "OCIRepository":
                        # For OCI chartRef releases, update the OCIRepository manifest
                        oci_repo_name = chart_ref.get("name")
                        oci_repo_namespace = chart_ref.get("namespace") or hr_ns
                        logging.info("🔄 Updating OCI chartRef release %s/%s -> OCIRepository %s/%s: %s -> %s",
                                   hr_ns, hr_name, oci_repo_namespace, oci_repo_name, current_version_text, latest_text)
                        success = update_oci_repository_manifest(
                            repo_dir,
                            oci_repo_name,
                            oci_repo_namespace,
                            latest_text,
                            current_version_text,
                        )
                    else:
                        # For traditional HelmRelease, update the HelmRelease manifest
                        success = update_helm_release_manifest(
                            repo_dir,
                            manifest_rel_path,
                            latest_text,
                            current_version_text,
                        )

                    if success:
                        if commit_and_push_changes(
                            repo_dir,
                            branch_name,
                            hr_ns,
                            hr_name,
                            current_version_text,
                            latest_text,
                            github_client,
                        ):
                            pr_url = create_github_pull_request(
                                github_client,
                                hr_ns,
                                hr_name,
                                current_version_text,
                                latest_text,
                                branch_name,
                                manifest_rel_path,
                                oci_info,
                            )
                            if pr_url:
                                logging.info(
                                    "🎉 Successfully created PR for %s/%s: %s",
                                    hr_ns,
                                    hr_name,
                                    pr_url,
                                    extra={"namespace": hr_ns, "hr_name": hr_name, "pr_url": pr_url, "status": "success"}
                                )
                                METRICS['pull_requests_created_total'].labels(namespace=hr_ns, name=hr_name).inc()
                                METRICS['updates_processed_total'].labels(namespace=hr_ns, name=hr_name, status="success").inc()
                            else:
                                logging.error(
                                    "❌ Failed to create PR for %s/%s",
                                    hr_ns,
                                    hr_name,
                                    extra={"namespace": hr_ns, "hr_name": hr_name, "status": "failed"}
                                )
                                METRICS['updates_processed_total'].labels(namespace=hr_ns, name=hr_name, status="failed").inc()
                        else:
                            logging.error(
                                "❌ Failed to commit and push changes for %s/%s",
                                hr_ns,
                                hr_name,
                            )
                    else:
                        logging.error(
                            "❌ Failed to update manifest for %s/%s", hr_ns, hr_name
                        )
                else:
                    logging.error(
                        "❌ Failed to create update branch for %s/%s",
                        hr_ns,
                        hr_name,
                    )
            else:
                logging.warning(
                    "⚠️  GitHub client not available, skipping PR creation"
                )
    
    # Check which nova releases were not processed and which FluxCD CRDs were not matched
    processed_keys = set()
    fluxcd_releases = []
    for hr in releases:
        spec = hr.get("spec", {})
        target_ns = spec.get("targetNamespace", hr["metadata"]["namespace"])
        release_name = spec.get("releaseName", hr["metadata"]["name"])
        processed_keys.add((target_ns, release_name))
        fluxcd_releases.append((hr["metadata"]["namespace"], hr["metadata"]["name"], target_ns, release_name))

    unprocessed_nova = []
    for key in outdated_lookup.keys():
        if key not in processed_keys:
            unprocessed_nova.append(key)

    unmatched_fluxcd = []
    for hr_ns, hr_name, target_ns, release_name in fluxcd_releases:
        if (target_ns, release_name) not in outdated_lookup:
            unmatched_fluxcd.append((hr_ns, hr_name, target_ns, release_name))

    if unprocessed_nova:
        logging.info("Nova releases not matched to any FluxCD HelmRelease: %s",
                    [f"{ns}/{name}" for ns, name in unprocessed_nova])

    if unmatched_fluxcd:
        logging.info("FluxCD HelmReleases not found in nova scan: %s",
                    [f"{hr_ns}/{hr_name} -> {target_ns}/{release_name}" for hr_ns, hr_name, target_ns, release_name in unmatched_fluxcd])

    # Update final metrics
    METRICS['helm_releases_outdated'].set(outdated_count)
    METRICS['helm_releases_up_to_date'].set(up_to_date_count)
    METRICS['last_successful_check_timestamp'].set(time.time())

    # Record check cycle duration
    duration = time.time() - start_time
    METRICS['check_cycle_duration_seconds'].observe(duration)

    logging.info("Check cycle completed",
                extra={"total_releases": total_releases, "outdated": outdated_count, "up_to_date": up_to_date_count, "nova_outdated": len(outdated_lookup), "duration_seconds": duration})


def main() -> None:
    """Main application entry point with optimized configuration."""
    configure_logging()
    
    # Validate configuration
    is_valid, errors = Config.validate_configuration()
    if not is_valid:
        logging.error("❌ Configuration validation failed:")
        for error in errors:
            logging.error("  - %s", error)
        logging.error("Please fix the configuration errors and restart the application.")
        sys.exit(1)
    
    logging.info("✅ Configuration validation passed")
    
    # Initialize metrics
    initialize_metrics()
    
    coapi = load_kube_config()
    interval = Config.DEFAULT_INTERVAL_SECONDS
    
    # Start health check server
    start_health_server()
    
    # Check if running in single-run mode (for CronJob)
    run_mode = os.getenv("RUN_MODE", "continuous").lower()
    
    # Initialize GitHub manager once
    github_manager = GitHubManager()

    # Log configuration once at startup
    if run_mode == "once":
        logging.info("🚀 Starting FluxCD Helm upgrader v0.7.0 (single-run mode)")
    else:
        logging.info("🚀 Starting FluxCD Helm upgrader v0.7.0 (continuous mode, interval: %ss)", interval)
    
    if Config.REPO_URL:
        logging.info("📂 Repository: %s", Config.REPO_URL)
        logging.info("🔑 SSH Keys: %s, %s", Config.SSH_PRIVATE_KEY_PATH, Config.SSH_PUBLIC_KEY_PATH)
        if github_manager.is_available():
            logging.info("🐙 GitHub PRs enabled for: %s", Config.GITHUB_REPOSITORY)
        elif Config.GITHUB_TOKEN:
            logging.info("🐙 GitHub token configured but repository setup failed")
        else:
            logging.info("🐙 GitHub integration disabled - no token provided")
    else:
        logging.info("📂 No repository URL configured - only cluster scanning enabled")
    
    cycle_count = 0
    
    # Single-run mode for CronJob
    if run_mode == "once":
        logging.info("🔄 Starting single check run...")
        try:
            check_once(coapi)
            logging.info("✅ Single check run completed successfully")
        except Exception:
            logging.exception("❌ Unexpected failure during single check run")
            exit(1)  # Exit with error code for CronJob failure tracking
        finally:
            clear_caches()  # Clean up before exit
        return
    
    # Continuous mode for Deployment (original behavior)
    while True:
        cycle_count += 1
        logging.info("🔄 Starting check cycle #%d...", cycle_count)
        
        try:
            check_once(coapi)
            logging.info("✅ Check cycle #%d completed", cycle_count)
            
            # Clear caches periodically to prevent memory buildup
            if cycle_count % 10 == 0:
                clear_caches()
                
        except Exception:
            logging.exception("❌ Unexpected failure during check loop #%d", cycle_count)
            
        logging.info("⏰ Sleeping for %s seconds...", interval)
        time.sleep(interval)


if __name__ == "__main__":
    main()
