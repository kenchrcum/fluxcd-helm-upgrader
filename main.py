import os
import time
import logging
import subprocess
import shutil
import glob
from pathlib import Path
from urllib.parse import urlparse, urlunparse, quote
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml
import semver
import re
from kubernetes import client, config
from kubernetes.client import ApiException
from github import Github, GithubException


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
        "User-Agent": "fluxcd-helm-upgrader/0.2.0 (+https://github.com/kenchrcum/fluxcd-helm-upgrader)",
        "Accept": "application/x-yaml, text/yaml, text/plain;q=0.9, */*;q=0.8",
    }
    
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
    
    @classmethod
    def get_boolean_env(cls, key: str, default: bool = False) -> bool:
        """Helper to parse boolean environment variables."""
        return os.getenv(key, str(default)).lower() in ("1", "true", "yes", "on")


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
    return repo_str.split("/", 1)


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
            # Try to create known_hosts with GitHub entry
            try:
                github_known_hosts = "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
                with open(known_hosts_path, "w") as f:
                    f.write(github_known_hosts + "\n")
                known_hosts_path.chmod(0o644)
                logging.debug("Added GitHub to known hosts")
            except OSError:
                logging.warning(
                    "Could not create known_hosts file (read-only file system)"
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
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


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

        target_version_patterns = [
            r"(^\s*version:\s*)" + re.escape(str(new_version)) + r"(\s*$)",
            r'(^\s*version:\s*["\'])' + re.escape(str(new_version)) + r'(["\']\s*$)',
        ]

        for pattern in target_version_patterns:
            if re.search(pattern, content, re.MULTILINE):
                logging.info(
                    "✅ Manifest already contains target version %s, no update needed",
                    new_version,
                )
                return True

        # Use regex to find and replace the version field while preserving formatting
        # Pattern to match version field in chart spec, accounting for various indentation
        patterns = [
            # Standard format: version: old_version
            r"(^\s*version:\s*)" + re.escape(str(current_version)) + r"(\s*$)",
            # With quotes: version: "old_version"
            r'(^\s*version:\s*["\'])'
            + re.escape(str(current_version))
            + r'(["\']\s*$)',
        ]

        updated = False
        for pattern in patterns:
            if re.search(pattern, content, re.MULTILINE):
                # Use a lambda function to avoid backreference issues in the replacement string
                def replacement(match):
                    return match.group(1) + str(new_version) + match.group(2)

                content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
                updated = True
                logging.info(
                    "Updated version from %s to %s in manifest",
                    current_version,
                    new_version,
                )
                break

        if not updated:
            logging.warning(
                "No version field found to update in manifest (searched for: %s)",
                current_version,
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
    github_client: Github, namespace: str, name: str, branch_name: str
) -> Optional[str]:
    """Check if a PR already exists for this update."""
    try:
        if not GITHUB_REPOSITORY:
            return None

        owner, repo_name = parse_github_repository(GITHUB_REPOSITORY)
        repo = github_client.get_repo(f"{owner}/{repo_name}")

        # Get all open PRs
        pulls = repo.get_pulls(state="open", head=f"{owner}:{branch_name}")

        # Check if any PR matches our update
        title_pattern = f"Update {name} in namespace {namespace}"
        for pr in pulls:
            if title_pattern in pr.title:
                logging.info(
                    "✅ Found existing PR for %s/%s: %s", namespace, name, pr.html_url
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
            logging.error("Failed to add files to git: %s", err.strip())
            return False

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
            logging.error("Failed to commit changes: %s", err.strip())
            return False

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
            logging.error("Failed to push branch %s: %s", branch_name, err.strip())
            if "non-fast-forward" in err or "Updates were rejected" in err:
                logging.info(
                    "💡 Tip: Set GIT_FORCE_PUSH=true to force push existing branches"
                )
            return False

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
        body = f"""## Helm Chart Update

**Application:** {name}
**Namespace:** {namespace}
**Current Version:** {current_version}
**New Version:** {new_version}

### Changes
- Updated HelmRelease manifest: `{manifest_path}`
- Version updated from `{current_version}` to `{new_version}`

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
                    github_client, namespace, name, branch_name
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
        else:
            logging.error("❌ Failed to create GitHub Pull Request: %s", str(e))
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
            return items, version
        except ApiException as e:
            if e.status in (404, 403):
                continue
            logging.exception("Failed listing HelmReleases for %s", version)
            continue
        except Exception:
            logging.exception("Unexpected error listing HelmReleases for %s", version)
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


def resolve_repo_for_release(
    coapi: client.CustomObjectsApi, hr: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
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
    return None


def get_current_chart_name_and_version(
    hr: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    spec = hr.get("spec") or {}
    chart_node = spec.get("chart") or {}
    chart_spec = chart_node.get("spec") or {}
    chart_name = chart_spec.get("chart") or chart_node.get("chart")

    # Prefer the actual applied revision from status if available
    status = hr.get("status") or {}
    applied = status.get("lastAppliedRevision") or status.get("lastAttemptedRevision")

    desired_version = chart_spec.get("version") or None

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


def clear_caches() -> None:
    """Clear all caches to prevent memory buildup."""
    global _version_cache, _manifest_cache
    _version_cache.clear()
    _manifest_cache.clear()
    logging.debug("Cleared performance caches")


def check_once(coapi: client.CustomObjectsApi) -> None:
    releases, hr_version = list_helm_releases(coapi)
    if hr_version is None:
        logging.error("No HelmRelease API version available; skipping iteration")
        return

    # Clone/update repository once at the beginning if REPO_URL is configured
    repo_dir = None
    if REPO_URL:
        logging.debug("Initializing repository access...")
        repo_dir = ensure_repo_cloned_or_updated()
        if not repo_dir:
            logging.warning(
                "⚠️  Repository access failed, continuing without manifest path resolution"
            )

    for hr in releases:
        hr_ns = hr["metadata"]["namespace"]
        hr_name = hr["metadata"]["name"]
        chart_name, current_version_text = get_current_chart_name_and_version(hr)
        if not chart_name:
            logging.debug("%s/%s: chart name unknown; skipping", hr_ns, hr_name)
            continue
        if not current_version_text:
            logging.debug("%s/%s: current version unknown; skipping", hr_ns, hr_name)
            continue
        current_version = parse_version(current_version_text)
        if not current_version:
            logging.debug(
                "%s/%s: unable to parse current version '%s'",
                hr_ns,
                hr_name,
                current_version_text,
            )
            continue

        repo = resolve_repo_for_release(coapi, hr)
        if not repo:
            logging.debug(
                "%s/%s: HelmRepository not resolved; skipping", hr_ns, hr_name
            )
            continue

        spec = repo.get("spec") or {}
        if spec.get("type") == "oci":
            logging.debug(
                "%s/%s: OCI HelmRepository not supported yet; skipping", hr_ns, hr_name
            )
            continue

        index = fetch_repo_index(repo)
        if not index:
            logging.debug("%s/%s: unable to fetch repo index; skipping", hr_ns, hr_name)
            continue

        latest_text = latest_available_version(index, chart_name, INCLUDE_PRERELEASE)
        if not latest_text:
            logging.debug(
                "%s/%s: no versions found in repo index for chart %s",
                hr_ns,
                hr_name,
                chart_name,
            )
            continue
        latest_ver = parse_version(latest_text)
        if not latest_ver:
            logging.debug(
                "%s/%s: unable to parse repo version '%s'", hr_ns, hr_name, latest_text
            )
            continue

        # Try to locate the HelmRelease manifest path if repository is available
        if repo_dir:
            manifest_rel_path = resolve_manifest_path_for_release(
                repo_dir, hr_ns, hr_name
            )
            if manifest_rel_path:
                if latest_ver > current_version:
                    # Show manifest path for releases with updates available
                    logging.info(
                        "📄 %s/%s -> %s",
                        hr_ns,
                        hr_name,
                        manifest_rel_path,
                    )
                else:
                    # Debug level for releases that are up-to-date
                    logging.debug(
                        "📄 %s/%s -> %s (up-to-date)",
                        hr_ns,
                        hr_name,
                        manifest_rel_path,
                    )
            else:
                logging.debug(
                    "No manifest found for %s/%s (pattern: %s)",
                    hr_ns,
                    hr_name,
                    REPO_SEARCH_PATTERN,
                )

        if latest_ver > current_version:
            logging.info(
                "📈 Update available: %s/%s (%s -> %s)",
                hr_ns,
                hr_name,
                current_version_text,
                latest_text,
            )

            # Check if we should create a PR for this update
            if GITHUB_TOKEN and repo_dir and manifest_rel_path:
                logging.info(
                    "🔄 Processing GitHub PR creation for %s/%s", hr_ns, hr_name
                )

                # Create GitHub client
                github_client = create_github_client()
                if github_client:
                    # Generate branch name to check for existing PR
                    branch_name = f"update-{hr_ns}-{hr_name}-{latest_text}".replace(
                        ".", "-"
                    )

                    # Check if PR already exists before doing any file operations
                    existing_pr = check_if_pr_already_exists(
                        github_client, hr_ns, hr_name, branch_name
                    )
                    if existing_pr:
                        logging.info(
                            "🎯 PR already exists for %s/%s: %s",
                            hr_ns,
                            hr_name,
                            existing_pr,
                        )
                        logging.info(
                            "✅ Skipping file operations since PR is already created"
                        )
                        continue  # Skip to next HelmRelease

                    # Create update branch
                    branch_name = create_update_branch(
                        repo_dir, hr_ns, hr_name, latest_text
                    )
                    if branch_name:
                        # Update manifest
                        if update_helm_release_manifest(
                            repo_dir,
                            manifest_rel_path,
                            latest_text,
                            current_version_text,
                        ):
                            # Commit and push changes (this will handle the case where no changes are needed)
                            if commit_and_push_changes(
                                repo_dir,
                                branch_name,
                                hr_ns,
                                hr_name,
                                current_version_text,
                                latest_text,
                                github_client,
                            ):
                                # Create PR
                                pr_url = create_github_pull_request(
                                    github_client,
                                    hr_ns,
                                    hr_name,
                                    current_version_text,
                                    latest_text,
                                    branch_name,
                                    manifest_rel_path,
                                )
                                if pr_url:
                                    logging.info(
                                        "🎉 Successfully created PR for %s/%s: %s",
                                        hr_ns,
                                        hr_name,
                                        pr_url,
                                    )
                                else:
                                    logging.error(
                                        "❌ Failed to create PR for %s/%s",
                                        hr_ns,
                                        hr_name,
                                    )
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
        else:
            logging.debug(
                "%s/%s: up-to-date (chart %s current %s, latest %s)",
                hr_ns,
                hr_name,
                chart_name,
                current_version_text,
                latest_text,
            )


def main() -> None:
    """Main application entry point with optimized configuration."""
    configure_logging()
    coapi = load_kube_config()
    interval = Config.DEFAULT_INTERVAL_SECONDS
    
    # Initialize GitHub manager once
    github_manager = GitHubManager()

    # Log configuration once at startup
    logging.info("🚀 Starting FluxCD Helm upgrader v0.2.0 (interval: %ss)", interval)
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
