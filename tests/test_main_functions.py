"""Tests for main application functions."""

import pytest
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path

from main import (
    clear_caches,
    get_home_directory,
    validate_ssh_key_loading,
)


class TestClearCaches:
    """Test the clear_caches function."""

    def test_clear_caches(self):
        """Test cache clearing."""
        with patch('main._version_cache', {'1.0.0': 'cached'}), \
             patch('main._manifest_cache', {'key': 'value'}):
            
            clear_caches()
            
            # Caches should be empty after clearing
            from main import _version_cache, _manifest_cache
            assert len(_version_cache) == 0
            assert len(_manifest_cache) == 0


class TestGetHomeDirectory:
    """Test the get_home_directory function."""

    def test_get_home_directory_with_env(self):
        """Test getting home directory from environment."""
        with patch.dict('os.environ', {'HOME': '/custom/home'}):
            result = get_home_directory()
            assert result == Path('/custom/home')

    def test_get_home_directory_without_env(self):
        """Test getting home directory without environment variable."""
        with patch.dict('os.environ', {}, clear=True), \
             patch('pathlib.Path.home') as mock_home:
            
            mock_home.return_value = Path('/default/home')
            
            result = get_home_directory()
            assert result == Path('/default/home')


class TestValidateSshKeyLoading:
    """Test the validate_ssh_key_loading function."""

    def test_validate_ssh_key_loading_success(self):
        """Test successful SSH key loading validation."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
            f.write("test key content\n")
            f.write("-----END OPENSSH PRIVATE KEY-----\n")
            f.flush()
            
            try:
                with patch('main.safe_run_command') as mock_run:
                    # Mock ssh-keygen availability check
                    mock_run.side_effect = [
                        (0, "", ""),  # which ssh-keygen succeeds
                        (0, "", "")   # ssh-keygen -l succeeds
                    ]
                    
                    result = validate_ssh_key_loading(f.name)
                    assert result is True
            finally:
                Path(f.name).unlink()

    def test_validate_ssh_key_loading_file_not_found(self):
        """Test SSH key loading validation with missing file."""
        result = validate_ssh_key_loading('/nonexistent/key')
        assert result is False

    def test_validate_ssh_key_loading_invalid_content(self):
        """Test SSH key loading validation with invalid content."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("invalid key content")
            f.flush()
            
            try:
                with patch('main.safe_run_command') as mock_run:
                    # Mock ssh-keygen availability check
                    mock_run.side_effect = [
                        (0, "", ""),  # which ssh-keygen succeeds
                        (1, "", "not a key file")   # ssh-keygen -l fails
                    ]
                    
                    result = validate_ssh_key_loading(f.name)
                    assert result is False
            finally:
                Path(f.name).unlink()

    def test_validate_ssh_key_loading_empty_file(self):
        """Test SSH key loading validation with empty file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("")
            f.flush()
            
            try:
                result = validate_ssh_key_loading(f.name)
                assert result is False
            finally:
                Path(f.name).unlink()
