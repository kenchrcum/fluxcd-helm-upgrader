import os
import time
import logging
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
INCLUDE_PRERELEASE = os.getenv("INCLUDE_PRERELEASE", "false").lower() in ("1", "true", "yes", "on")
REQUEST_TIMEOUT = (5, 20)  # connect, read
DEFAULT_HEADERS = {
    "User-Agent": "fluxcd-helm-upgrader/0.1 (+https://github.com/kenchrcum/fluxcd-helm-upgrader)",
    "Accept": "application/x-yaml, text/yaml, text/plain;q=0.9, */*;q=0.8",
}


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


def list_helm_releases(coapi: client.CustomObjectsApi) -> Tuple[List[Dict[str, Any]], Optional[str]]:
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
    logging.warning("HelmRelease CRD not found under known versions: %s", HELM_RELEASE_VERSIONS)
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
                group=group, version=version, namespace=namespace, plural=plural, name=name
            )
            return obj, version
        except ApiException as e:
            if e.status in (404, 403):
                continue
            logging.exception("Error getting %s/%s %s", group, version, plural)
            continue
        except Exception:
            logging.exception("Unexpected error getting %s/%s %s", group, version, plural)
            continue
    return None, None


def get_helm_chart_for_release(
    coapi: client.CustomObjectsApi, hr: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    hr_ns = hr["metadata"]["namespace"]
    hr_name = hr["metadata"]["name"]
    chart_spec = (hr.get("spec") or {}).get("chart") or {}
    inner_spec = (chart_spec.get("spec") or {})
    src_ref = (inner_spec.get("sourceRef") or {})
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
        src_ref = ((chart.get("spec") or {}).get("sourceRef") or {})
        if src_ref.get("kind") == "HelmRepository":
            repo, _ = get_helm_repository(
                coapi, src_ref.get("namespace") or chart["metadata"]["namespace"], src_ref.get("name")
            )
            if repo:
                return repo
    chart_spec = (hr.get("spec") or {}).get("chart") or {}
    inner_spec = (chart_spec.get("spec") or {})
    src_ref = (inner_spec.get("sourceRef") or {})
    if src_ref.get("kind") == "HelmRepository":
        repo, _ = get_helm_repository(
            coapi, src_ref.get("namespace") or hr["metadata"]["namespace"], src_ref.get("name")
        )
        if repo:
            return repo
    return None


def get_current_chart_name_and_version(hr: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    spec = (hr.get("spec") or {})
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
            m = re.search(r'(?:^|-)v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z\.-]+)?(?:\+[0-9A-Za-z\.-]+)?)$', applied)
            if m:
                candidate = m.group(1)
                current_version = candidate if parse_version(candidate) else None
                if not chart_name:
                    # Trim trailing '-' if present before the version
                    prefix = applied[: m.start(1)]
                    if prefix.endswith('-'):
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
            if content[:2] == b"\x1f\x8b" or "application/gzip" in ct or "application/x-gzip" in ct:
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
                "%s/%s: unable to parse current version '%s'", hr_ns, hr_name, current_version_text
            )
            continue

        repo = resolve_repo_for_release(coapi, hr)
        if not repo:
            logging.debug("%s/%s: HelmRepository not resolved; skipping", hr_ns, hr_name)
            continue

        spec = repo.get("spec") or {}
        if spec.get("type") == "oci":
            logging.debug("%s/%s: OCI HelmRepository not supported yet; skipping", hr_ns, hr_name)
            continue

        index = fetch_repo_index(repo)
        if not index:
            logging.debug("%s/%s: unable to fetch repo index; skipping", hr_ns, hr_name)
            continue

        latest_text = latest_available_version(index, chart_name, INCLUDE_PRERELEASE)
        if not latest_text:
            logging.debug("%s/%s: no versions found in repo index for chart %s", hr_ns, hr_name, chart_name)
            continue
        latest_ver = parse_version(latest_text)
        if not latest_ver:
            logging.debug("%s/%s: unable to parse repo version '%s'", hr_ns, hr_name, latest_text)
            continue

        if latest_ver > current_version:
            logging.info(
                "Update available: HelmRelease %s/%s for chart %s -> %s (current %s)",
                hr_ns,
                hr_name,
                chart_name,
                latest_text,
                current_version_text,
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
    logging.info("Starting FluxCD Helm upgrader loop with interval=%ss", interval)
    while True:
        try:
            check_once(coapi)
        except Exception:
            logging.exception("Unexpected failure during check loop")
        time.sleep(interval)


if __name__ == "__main__":
    main()
