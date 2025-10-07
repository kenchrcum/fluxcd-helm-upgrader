"""Unit tests for configuration validation."""

import os
import pytest
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import Config


class TestConfigValidation:
    """Test cases for configuration validation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_validate_configuration_valid_minimal(self):
        """Test validation with minimal valid configuration."""
        # Test the validation logic directly by mocking the class attributes
        with patch.object(Config, 'REPO_URL', ''), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'), \
             patch.object(Config, 'GITHUB_REPOSITORY', 'owner/repo'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is True
            assert len(errors) == 0

    def test_validate_configuration_valid_with_repo_url(self):
        """Test validation with valid REPO_URL configuration."""
        with patch.object(Config, 'REPO_URL', 'https://github.com/owner/repo.git'), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'), \
             patch.object(Config, 'GITHUB_REPOSITORY', 'owner/repo'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is True
            assert len(errors) == 0

    def test_validate_configuration_missing_required(self):
        """Test validation with missing required configuration."""
        with patch.object(Config, 'REPO_URL', ''), \
             patch.object(Config, 'GITHUB_TOKEN', ''):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "Either REPO_URL or GITHUB_TOKEN must be configured" in errors

    def test_validate_configuration_invalid_repo_url(self):
        """Test validation with invalid REPO_URL format."""
        with patch.object(Config, 'REPO_URL', 'invalid-url'), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "REPO_URL must start with http://, https://, or git@" in errors

    def test_validate_configuration_ssh_repo_url_missing_git(self):
        """Test validation with SSH REPO_URL missing .git suffix."""
        with patch.object(Config, 'REPO_URL', 'git@github.com:owner/repo'), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "SSH REPO_URL should end with .git" in errors

    def test_validate_configuration_invalid_github_repository(self):
        """Test validation with invalid GITHUB_REPOSITORY format."""
        with patch.object(Config, 'GITHUB_TOKEN', 'test-token'), \
             patch.object(Config, 'GITHUB_REPOSITORY', 'invalid-format'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "GITHUB_REPOSITORY must be in format 'owner/repo'" in errors

    def test_validate_configuration_github_repository_multiple_slashes(self):
        """Test validation with GITHUB_REPOSITORY containing multiple slashes."""
        with patch.object(Config, 'GITHUB_TOKEN', 'test-token'), \
             patch.object(Config, 'GITHUB_REPOSITORY', 'owner/repo/subpath'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "GITHUB_REPOSITORY must contain exactly one '/' separator" in errors

    def test_validate_configuration_ssh_key_not_found(self):
        """Test validation with SSH key not found."""
        with patch.object(Config, 'REPO_URL', 'git@github.com:owner/repo.git'), \
             patch.object(Config, 'SSH_PRIVATE_KEY_PATH', '/nonexistent/key'), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "SSH private key not found: /nonexistent/key" in errors

    def test_validate_configuration_ssh_key_not_readable(self):
        """Test validation with SSH key not readable."""
        # Create a file but make it not readable
        ssh_key_path = Path(self.temp_dir) / "private_key"
        ssh_key_path.write_text("test key content")
        ssh_key_path.chmod(0o000)  # No permissions
        
        try:
            with patch.object(Config, 'REPO_URL', 'git@github.com:owner/repo.git'), \
                 patch.object(Config, 'SSH_PRIVATE_KEY_PATH', str(ssh_key_path)), \
                 patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
                is_valid, errors = Config.validate_configuration()
                assert is_valid is False
                assert any("SSH private key not readable:" in error for error in errors)
        finally:
            ssh_key_path.chmod(0o600)  # Restore permissions for cleanup

    def test_validate_configuration_interval_too_small(self):
        """Test validation with interval too small."""
        with patch.object(Config, 'DEFAULT_INTERVAL_SECONDS', 30), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "INTERVAL_SECONDS should be at least 60 seconds" in errors

    def test_validate_configuration_interval_too_large(self):
        """Test validation with interval too large."""
        with patch.object(Config, 'DEFAULT_INTERVAL_SECONDS', 100000), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "INTERVAL_SECONDS should not exceed 86400 seconds (24 hours)" in errors

    def test_validate_configuration_health_check_port_invalid(self):
        """Test validation with invalid health check port."""
        with patch.object(Config, 'HEALTH_CHECK_PORT', 80), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "HEALTH_CHECK_PORT must be between 1024 and 65535" in errors

    def test_validate_configuration_metrics_port_invalid(self):
        """Test validation with invalid metrics port."""
        with patch.object(Config, 'METRICS_PORT', 70000), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "METRICS_PORT must be between 1024 and 65535" in errors

    def test_validate_configuration_ports_same(self):
        """Test validation with same health check and metrics ports."""
        with patch.object(Config, 'HEALTH_CHECK_PORT', 8080), \
             patch.object(Config, 'METRICS_PORT', 8080), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "HEALTH_CHECK_PORT and METRICS_PORT must be different" in errors

    def test_validate_configuration_search_pattern_no_slash(self):
        """Test validation with search pattern not starting with slash."""
        with patch.object(Config, 'REPO_SEARCH_PATTERN', 'components/{namespace}/*/helmrelease*.y*ml'), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "REPO_SEARCH_PATTERN should start with '/'" in errors

    def test_validate_configuration_search_pattern_no_namespace(self):
        """Test validation with search pattern without namespace placeholder (now valid)."""
        with patch.object(Config, 'REPO_SEARCH_PATTERN', '/components/*/helmrelease*.y*ml'), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is True
            assert len(errors) == 0

    def test_validate_configuration_clone_dir_parent_not_exists(self):
        """Test validation with clone directory parent not existing."""
        with patch.object(Config, 'REPO_CLONE_DIR', '/nonexistent/path/repo'), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert "Parent directory of REPO_CLONE_DIR does not exist: /nonexistent/path" in errors

    def test_validate_configuration_clone_dir_parent_not_writable(self):
        """Test validation with clone directory parent not writable."""
        # Create a directory but make it not writable
        clone_dir = Path(self.temp_dir) / "clone_dir"
        clone_dir.mkdir()
        clone_dir.chmod(0o444)  # Read-only
        
        try:
            with patch.object(Config, 'REPO_CLONE_DIR', str(clone_dir / "repo")), \
                 patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
                is_valid, errors = Config.validate_configuration()
                assert is_valid is False
                assert any("Parent directory of REPO_CLONE_DIR is not writable:" in error for error in errors)
        finally:
            clone_dir.chmod(0o755)  # Restore permissions for cleanup

    def test_validate_configuration_multiple_errors(self):
        """Test validation with multiple errors."""
        with patch.object(Config, 'REPO_URL', 'invalid-url'), \
             patch.object(Config, 'GITHUB_REPOSITORY', 'invalid-format'), \
             patch.object(Config, 'DEFAULT_INTERVAL_SECONDS', 30), \
             patch.object(Config, 'HEALTH_CHECK_PORT', 80), \
             patch.object(Config, 'GITHUB_TOKEN', 'test-token'):
            is_valid, errors = Config.validate_configuration()
            assert is_valid is False
            assert len(errors) >= 4
            assert "REPO_URL must start with http://, https://, or git@" in errors
            assert "GITHUB_REPOSITORY must be in format 'owner/repo'" in errors
            assert "INTERVAL_SECONDS should be at least 60 seconds" in errors
            assert "HEALTH_CHECK_PORT must be between 1024 and 65535" in errors
