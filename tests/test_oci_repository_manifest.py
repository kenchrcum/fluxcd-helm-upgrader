"""Unit tests for locating and updating OCIRepository manifests."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import find_oci_repository_manifest, update_oci_repository_manifest

OCI_REPO = """apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: continuview-site
  namespace: helmrepositories
spec:
  interval: 5m0s
  url: oci://registry.example.com/continuview/helm/continuview-site
  secretRef:
    name: regcred
  ref:
    tag: 0.0.8
"""

HELM_RELEASE = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: continuview-site
  namespace: continuview
spec:
  chartRef:
    kind: OCIRepository
    name: continuview-site
    namespace: helmrepositories
  values:
    image:
      tag: 0.0.8
"""

# Unrelated manifest whose *file name* contains the OCIRepository name
RUNNER = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: runner-continuview-site
  namespace: github-actions-runner
spec:
  chartRef:
    kind: OCIRepository
    name: runner
    namespace: helmrepositories
"""


def _write(tmp_path, rel, content):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestOciRepositoryManifest:

    def test_file_name_match_without_matching_content_is_ignored(self, tmp_path):
        """Regression: an unrelated '...-continuview-site.yaml' must not be picked."""
        runner = _write(tmp_path, "components/github-actions-runner/kubeone-cluster/helmrelease-runner-continuview-site.yaml", RUNNER)
        site = _write(tmp_path, "components/continuview/kubeone-cluster/helmrelease-site.yaml",
                      "---\n" + OCI_REPO + "---\n" + HELM_RELEASE)

        assert update_oci_repository_manifest(str(tmp_path), "continuview-site", "helmrepositories", "0.0.9", "0.0.8")

        assert runner.read_text() == RUNNER
        # Only the OCIRepository document changes, not the HelmRelease's image tag
        assert site.read_text() == "---\n" + OCI_REPO.replace("tag: 0.0.8", "tag: 0.0.9") + "---\n" + HELM_RELEASE

    def test_other_namespace_does_not_match(self, tmp_path):
        _write(tmp_path, "a/oci.yaml", OCI_REPO.replace("namespace: helmrepositories", "namespace: other"))

        assert find_oci_repository_manifest(str(tmp_path), "continuview-site", "helmrepositories") is None
        assert not update_oci_repository_manifest(str(tmp_path), "continuview-site", "helmrepositories", "0.0.9", "0.0.8")

    def test_exact_namespace_preferred_over_missing_namespace(self, tmp_path):
        _write(tmp_path, "a/oci.yaml", OCI_REPO.replace("  namespace: helmrepositories\n", ""))
        _write(tmp_path, "b/oci.yml", OCI_REPO)

        path, _, _ = find_oci_repository_manifest(str(tmp_path), "continuview-site", "helmrepositories")
        assert str(path) == "b/oci.yml"

    def test_missing_namespace_is_accepted(self, tmp_path):
        _write(tmp_path, "a/oci.yaml", OCI_REPO.replace("  namespace: helmrepositories\n", ""))

        path, _, _ = find_oci_repository_manifest(str(tmp_path), "continuview-site", "helmrepositories")
        assert str(path) == "a/oci.yaml"

    def test_already_up_to_date(self, tmp_path):
        site = _write(tmp_path, "a/oci.yaml", OCI_REPO.replace("0.0.8", "0.0.9"))

        assert update_oci_repository_manifest(str(tmp_path), "continuview-site", "helmrepositories", "0.0.9", "0.0.8")
        assert "tag: 0.0.9" in site.read_text()

    def test_v_prefix_and_quotes_preserved(self, tmp_path):
        site = _write(tmp_path, "a/oci.yaml", OCI_REPO.replace("tag: 0.0.8", 'tag: "v0.0.8"'))

        assert update_oci_repository_manifest(str(tmp_path), "continuview-site", "helmrepositories", "0.0.9", "0.0.8")
        assert 'tag: "v0.0.9"' in site.read_text()
