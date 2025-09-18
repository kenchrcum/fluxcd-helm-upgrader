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


HELM_RELEASE_GROUP = "helm.toolkit.fluxcd.io"
SOURCE_GROUP = "source.toolkit.fluxcd.io"
# Try newer versions first; gracefully fall back
HELM_RELEASE_VERSIONS = ["v2", "v2beta2", "v2beta1"]
SOURCE_VERSIONS = ["v1", "v1beta2", "v1beta1"]

DEFAULT_INTERVAL_SECONDS = int(os.getenv("INTERVAL_SECONDS", "300"))
INCLUDE_PRERELEASE = os.getenv("INCLUDE_PRERELEASE", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
REQUEST_TIMEOUT = (5, 20)  # connect, read
DEFAULT_HEADERS = {
    "User-Agent": "fluxcd-helm-upgrader/0.1 (+https://github.com/kenchrcum/fluxcd-helm-upgrader)",
    "Accept": "application/x-yaml, text/yaml, text/plain;q=0.9, */*;q=0.8",
}

# Git repository configuration for locating HelmRelease manifests
REPO_URL = os.getenv("REPO_URL", "").strip()
REPO_BRANCH = os.getenv("REPO_BRANCH", "").strip()
REPO_SEARCH_PATTERN = os.getenv(
    "REPO_SEARCH_PATTERN",
    "/components/{namespace}/*/helmrelease*.y*ml",
).strip()
REPO_CLONE_DIR = os.getenv("REPO_CLONE_DIR", "/tmp/fluxcd-repo").strip()

# SSH key configuration for private repository access
SSH_PRIVATE_KEY_PATH = os.getenv(
    "SSH_PRIVATE_KEY_PATH", "/home/app/.ssh/private_key"
).strip()
SSH_PUBLIC_KEY_PATH = os.getenv(
    "SSH_PUBLIC_KEY_PATH", "/home/app/.ssh/public_key"
).strip()
SSH_KNOWN_HOSTS_PATH = os.getenv(
    "SSH_KNOWN_HOSTS_PATH", "/home/app/.ssh/known_hosts"
).strip()


def validate_ssh_key_loading(private_key_path: str) -> bool:
    """Test if SSH private key can be loaded by ssh-keygen."""
    try:
        # First check if ssh-keygen is available
        check_ssh_keygen = subprocess.run(
            ["which", "ssh-keygen"],
            capture_output=True,
            text=True,
        )
        if check_ssh_keygen.returncode != 0:
            logging.warning("ssh-keygen not found, skipping key validation")
            return True

        # Check file permissions and existence
        if not os.path.exists(private_key_path):
            logging.error("SSH private key file does not exist: %s", private_key_path)
            return False

        # Check if file is readable
        try:
            with open(private_key_path, 'r') as f:
                content = f.read()
                if not content.strip():
                    logging.error("SSH private key file is empty: %s", private_key_path)
                    return False
        except PermissionError:
            logging.error("Cannot read SSH private key file (permission denied): %s", private_key_path)
            return False
        except Exception as e:
            logging.error("Error reading SSH private key file: %s", str(e))
            return False

        # Try to validate with ssh-keygen
        result = subprocess.run(
            ["ssh-keygen", "-l", "-f", private_key_path],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            logging.debug("SSH key loading validation passed")
            return True
        else:
            stderr_msg = result.stderr.strip()
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
        # Determine SSH directory based on environment
        if os.path.exists("/home/app"):  # Container environment
            home_dir = Path("/home/app")
        else:  # Local development environment
            home_dir = Path.home()

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
            with open(private_key_path, 'r') as f:
                key_content = f.read().strip()
                if not key_content:
                    logging.error("SSH private key file is empty")
                    return False

                # Check if it's a valid SSH private key format
                if not (key_content.startswith('-----BEGIN OPENSSH PRIVATE KEY-----') or
                        key_content.startswith('-----BEGIN RSA PRIVATE KEY-----') or
                        key_content.startswith('-----BEGIN EC PRIVATE KEY-----') or
                        key_content.startswith('-----BEGIN PRIVATE KEY-----')):
                    logging.error("SSH private key is not in a recognized format")
                    logging.error("Supported formats: OpenSSH, RSA, ECDSA, or PKCS#8")
                    logging.error("You may need to convert your key using: ssh-keygen -p -f key_file -m pem")
                    return False

                if not (key_content.endswith('-----END OPENSSH PRIVATE KEY-----\n') or
                        key_content.endswith('-----END RSA PRIVATE KEY-----\n') or
                        key_content.endswith('-----END EC PRIVATE KEY-----\n') or
                        key_content.endswith('-----END PRIVATE KEY-----\n') or
                        key_content.endswith('-----END OPENSSH PRIVATE KEY-----') or
                        key_content.endswith('-----END RSA PRIVATE KEY-----') or
                        key_content.endswith('-----END EC PRIVATE KEY-----') or
                        key_content.endswith('-----END PRIVATE KEY-----')):
                    logging.warning("SSH private key may be missing trailing newline")
                    logging.warning("This can cause SSH authentication to fail")
                    logging.info("Consider adding a newline at the end of your SSH key in Vault")

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
            logging.debug("Could not set permissions on private key (likely read-only mount)")

        # Set proper permissions on public key if it exists (if writable)
        if public_key_path.exists():
            try:
                public_key_path.chmod(0o644)
            except OSError:
                logging.debug("Could not set permissions on public key (likely read-only mount)")

        # Check known_hosts and add GitHub if needed
        if known_hosts_path.exists():
            try:
                known_hosts_path.chmod(0o644)
            except OSError:
                logging.debug("Could not set permissions on known_hosts (likely read-only mount)")
        else:
            # Try to create known_hosts with GitHub entry
            try:
                github_known_hosts = "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
                with open(known_hosts_path, "w") as f:
                    f.write(github_known_hosts + "\n")
                known_hosts_path.chmod(0o644)
                logging.debug("Added GitHub to known hosts")
            except OSError:
                logging.warning("Could not create known_hosts file (read-only file system)")

        # Configure git to use SSH with the correct key paths
        env = os.environ.copy()
        env.setdefault(
            "GIT_SSH_COMMAND",
            f"ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile={SSH_KNOWN_HOSTS_PATH} -i {SSH_PRIVATE_KEY_PATH} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=30",
        )

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

        # Determine SSH directory based on environment
        if os.path.exists("/home/app"):  # Container environment
            home_dir = Path("/home/app")
        else:  # Local development environment
            home_dir = Path.home()

        ssh_dir = home_dir / ".ssh"
        ssh_dir_str = str(ssh_dir)

        # Test SSH access with git ls-remote using the correct key paths
        env = os.environ.copy()
        env.setdefault(
            "GIT_SSH_COMMAND",
            f"ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile={SSH_KNOWN_HOSTS_PATH} -i {SSH_PRIVATE_KEY_PATH} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=30",
        )

        result = subprocess.run(
            ["git", "ls-remote", ssh_url, "HEAD"],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            logging.debug("SSH access validated")
            return True
        else:
            stderr_output = result.stderr.strip()
            logging.error("SSH access validation failed: %s", stderr_output)

            # Provide specific guidance based on error type
            if "Load key" in stderr_output and "error in libcrypto" in stderr_output:
                logging.error("SSH key format issue detected. Common solutions:")
                logging.error("1. Convert PKCS#8 format to PEM: openssl rsa -in key.pem -out key.pem")
                logging.error("2. Convert to OpenSSH format: ssh-keygen -p -f key_file -m pem")
                logging.error("3. Regenerate key: ssh-keygen -t rsa -b 4096 -C 'flux-deploy-key'")
            elif "Permission denied" in stderr_output:
                logging.error("SSH authentication failed. Check:")
                logging.error("1. SSH key has correct permissions in repository")
                logging.error("2. SSH key is added to repository deploy keys")
                logging.error("3. Repository URL format is correct")
            elif "Could not resolve hostname" in stderr_output:
                logging.error("DNS/Network issue. Check internet connectivity and DNS resolution")

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
    env = os.environ.copy()
    # Disable terminal prompts entirely so we fail fast instead of hanging
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    env.setdefault("GIT_ASKPASS", "true")

    # Clear any existing credential helpers that might interfere
    env.setdefault("GIT_CONFIG_GLOBAL", "")
    env.setdefault("GIT_CONFIG_SYSTEM", "")

    # Use SSH authentication with appropriate SSH directory
    if os.path.exists("/home/app"):  # Container environment
        home_dir = Path("/home/app")
    else:  # Local development environment
        home_dir = Path.home()

    ssh_dir = home_dir / ".ssh"
    ssh_dir_str = str(ssh_dir)
    env.setdefault(
        "GIT_SSH_COMMAND",
        f"ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile={SSH_KNOWN_HOSTS_PATH} -i {SSH_PRIVATE_KEY_PATH} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=30",
    )
    base_cmd = ["git"]
    base_cmd += ["-c", "credential.helper="]  # Disable credential helpers

    full_cmd = base_cmd + args

    # Log the command for debugging
    safe_cmd = full_cmd

    logging.debug("Running git command: %s", " ".join(safe_cmd))

    proc = subprocess.run(
        full_cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


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
                    ["reset", "--hard", f"origin/{branch}"], cwd=str(clone_dir_path)
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


def resolve_manifest_path_for_release(
    repo_dir: str, namespace: str, name: str
) -> Optional[str]:
    try:
        # Allow multiple patterns separated by ';'
        patterns = [p for p in REPO_SEARCH_PATTERN.split(";") if p.strip()]
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
                except Exception:
                    continue
                try:
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
                        return str(p.relative_to(repo_root))
                except Exception:
                    # Ignore YAML parse errors for non-HelmRelease files
                    continue
        return None
    except Exception:
        logging.exception(
            "Error searching for HelmRelease manifest for %s/%s", namespace, name
        )
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


def parse_version(text: Optional[str]) -> Optional[semver.VersionInfo]:
    if not text:
        return None
    raw = text.strip()
    if raw.startswith("v"):
        raw = raw[1:]
    try:
        return semver.VersionInfo.parse(raw)
    except ValueError:
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
    entries = (index or {}).get("entries") or {}
    chart_entries = entries.get(chart_name) or []
    best: Optional[Tuple[semver.VersionInfo, str]] = None
    for entry in chart_entries:
        ver_text = entry.get("version")
        if not ver_text:
            continue
        if entry.get("deprecated") is True:
            continue
        ver = parse_version(ver_text)
        if not ver:
            continue
        if (not include_prerelease) and (ver.prerelease is not None):
            continue
        if (best is None) or (ver > best[0]):
            best = (ver, ver_text)
    return best[1] if best else None


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
    configure_logging()
    coapi = load_kube_config()
    interval = DEFAULT_INTERVAL_SECONDS

    # Log configuration once at startup
    logging.info("🚀 Starting FluxCD Helm upgrader (interval: %ss)", interval)
    if REPO_URL:
        logging.info("📂 Repository: %s", REPO_URL)
        logging.info("🔑 SSH Keys: %s, %s", SSH_PRIVATE_KEY_PATH, SSH_PUBLIC_KEY_PATH)
    else:
        logging.info("📂 No repository URL configured - only cluster scanning enabled")
    while True:
        logging.info("🔄 Starting new check cycle...")
        try:
            check_once(coapi)
            logging.info("✅ Check cycle completed")
        except Exception:
            logging.exception("❌ Unexpected failure during check loop")
        logging.info("⏰ Sleeping for %s seconds...", interval)
        time.sleep(interval)


if __name__ == "__main__":
    main()
