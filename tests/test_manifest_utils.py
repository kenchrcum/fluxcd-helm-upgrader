"""Unit tests for manifest utility functions."""

import os
import pytest
from unittest.mock import patch, mock_open
import tempfile
import shutil
from pathlib import Path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import update_helm_release_manifest, resolve_manifest_path_for_release


class TestManifestUtils:
    """Test cases for manifest utility functions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.repo_dir = Path(self.temp_dir)

    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_update_helm_release_manifest_success(self):
        """Test successful HelmRelease manifest update."""
        # Create test manifest file
        manifest_content = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: test-app
  namespace: default
spec:
  chart:
    spec:
      chart: nginx
      version: 1.0.0
"""
        manifest_path = self.repo_dir / "test-manifest.yaml"
        manifest_path.write_text(manifest_content)
        
        # Update manifest
        result = update_helm_release_manifest(
            str(self.repo_dir), 
            "test-manifest.yaml", 
            "1.1.0", 
            "1.0.0"
        )
        
        assert result is True
        
        # Verify update
        updated_content = manifest_path.read_text()
        assert "version: 1.1.0" in updated_content
        assert "version: 1.0.0" not in updated_content

    def test_update_helm_release_manifest_quoted_version(self):
        """Test updating HelmRelease manifest with quoted version."""
        manifest_content = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: test-app
  namespace: default
spec:
  chart:
    spec:
      chart: nginx
      version: "1.0.0"
"""
        manifest_path = self.repo_dir / "test-manifest.yaml"
        manifest_path.write_text(manifest_content)
        
        result = update_helm_release_manifest(
            str(self.repo_dir), 
            "test-manifest.yaml", 
            "1.1.0", 
            "1.0.0"
        )
        
        assert result is True
        updated_content = manifest_path.read_text()
        assert 'version: "1.1.0"' in updated_content

    def test_update_helm_release_manifest_already_updated(self):
        """Test updating HelmRelease manifest that's already at target version."""
        manifest_content = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: test-app
  namespace: default
spec:
  chart:
    spec:
      chart: nginx
      version: 1.1.0
"""
        manifest_path = self.repo_dir / "test-manifest.yaml"
        manifest_path.write_text(manifest_content)
        
        result = update_helm_release_manifest(
            str(self.repo_dir), 
            "test-manifest.yaml", 
            "1.1.0", 
            "1.0.0"
        )
        
        assert result is True  # Should return True even if no update needed

    def test_update_helm_release_manifest_version_not_found(self):
        """Test updating HelmRelease manifest when current version not found."""
        manifest_content = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: test-app
  namespace: default
spec:
  chart:
    spec:
      chart: nginx
      version: 2.0.0
"""
        manifest_path = self.repo_dir / "test-manifest.yaml"
        manifest_path.write_text(manifest_content)
        
        result = update_helm_release_manifest(
            str(self.repo_dir), 
            "test-manifest.yaml", 
            "1.1.0", 
            "1.0.0"
        )
        
        assert result is False

    def test_update_helm_release_manifest_file_not_found(self):
        """Test updating HelmRelease manifest when file doesn't exist."""
        result = update_helm_release_manifest(
            str(self.repo_dir), 
            "nonexistent.yaml", 
            "1.1.0", 
            "1.0.0"
        )
        
        assert result is False

    def test_resolve_manifest_path_for_release_success(self):
        """Test successful manifest path resolution."""
        # Create test manifest file
        manifest_content = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: test-app
  namespace: default
spec:
  chart:
    spec:
      chart: nginx
      version: 1.0.0
"""
        manifest_path = self.repo_dir / "components" / "default" / "test-app" / "helmrelease.yaml"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(manifest_content)
        
        # Mock the search pattern
        with patch('main.REPO_SEARCH_PATTERN', '/components/{namespace}/*/helmrelease*.y*ml'):
            result = resolve_manifest_path_for_release(
                str(self.repo_dir), 
                "default", 
                "test-app"
            )
        
        assert result == "components/default/test-app/helmrelease.yaml"

    def test_resolve_manifest_path_for_release_not_found(self):
        """Test manifest path resolution when manifest not found."""
        with patch('main.REPO_SEARCH_PATTERN', '/components/{namespace}/*/helmrelease*.y*ml'):
            result = resolve_manifest_path_for_release(
                str(self.repo_dir), 
                "default", 
                "nonexistent-app"
            )
        
        assert result is None

    def test_resolve_manifest_path_for_release_wrong_namespace(self):
        """Test manifest path resolution with wrong namespace."""
        # Create test manifest file
        manifest_content = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: test-app
  namespace: default
spec:
  chart:
    spec:
      chart: nginx
      version: 1.0.0
"""
        manifest_path = self.repo_dir / "components" / "default" / "test-app" / "helmrelease.yaml"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(manifest_content)
        
        with patch('main.REPO_SEARCH_PATTERN', '/components/{namespace}/*/helmrelease*.y*ml'):
            result = resolve_manifest_path_for_release(
                str(self.repo_dir), 
                "other-namespace", 
                "test-app"
            )
        
        assert result is None

    def test_resolve_manifest_path_for_release_wrong_name(self):
        """Test manifest path resolution with wrong name."""
        # Create test manifest file
        manifest_content = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: test-app
  namespace: default
spec:
  chart:
    spec:
      chart: nginx
      version: 1.0.0
"""
        manifest_path = self.repo_dir / "components" / "default" / "test-app" / "helmrelease.yaml"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(manifest_content)
        
        with patch('main.REPO_SEARCH_PATTERN', '/components/{namespace}/*/helmrelease*.y*ml'):
            result = resolve_manifest_path_for_release(
                str(self.repo_dir), 
                "default", 
                "other-app"
            )
        
        assert result is None

    def test_resolve_manifest_path_for_release_caching(self):
        """Test that manifest path resolution uses caching."""
        # Create test manifest file
        manifest_content = """apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: test-app
  namespace: default
spec:
  chart:
    spec:
      chart: nginx
      version: 1.0.0
"""
        manifest_path = self.repo_dir / "components" / "default" / "test-app" / "helmrelease.yaml"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(manifest_content)
        
        with patch('main.REPO_SEARCH_PATTERN', '/components/{namespace}/*/helmrelease*.y*ml'):
            # First call
            result1 = resolve_manifest_path_for_release(
                str(self.repo_dir), 
                "default", 
                "test-app"
            )
            # Second call should use cache
            result2 = resolve_manifest_path_for_release(
                str(self.repo_dir), 
                "default", 
                "test-app"
            )
        
        assert result1 == result2
        assert result1 == "components/default/test-app/helmrelease.yaml"
