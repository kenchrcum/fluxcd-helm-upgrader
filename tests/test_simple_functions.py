"""Tests for simple utility functions."""

import pytest
from unittest.mock import patch, MagicMock
import subprocess

from main import (
    safe_run_command,
    get_git_ssh_command,
    convert_to_ssh_url,
    parse_version,
)


class TestSafeRunCommand:
    """Test the safe_run_command function."""

    def test_safe_run_command_success(self):
        """Test successful command execution."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="success output",
                stderr=""
            )
            
            exit_code, stdout, stderr = safe_run_command(['echo', 'test'])
            
            assert exit_code == 0
            assert stdout == "success output"
            assert stderr == ""

    def test_safe_run_command_failure(self):
        """Test command execution failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="error output"
            )
            
            exit_code, stdout, stderr = safe_run_command(['false'])
            
            assert exit_code == 1
            assert stdout == ""
            assert stderr == "error output"

    def test_safe_run_command_exception(self):
        """Test command execution with exception."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(['sleep', '10'], 1)
            
            exit_code, stdout, stderr = safe_run_command(['sleep', '10'])
            
            assert exit_code == 1  # The function returns 1 for exceptions
            assert "timed out" in stderr


class TestGetGitSshCommand:
    """Test the get_git_ssh_command function."""

    def test_get_git_ssh_command(self):
        """Test SSH command generation."""
        with patch('main.SSH_PRIVATE_KEY_PATH', '/path/to/key'), \
             patch('main.SSH_KNOWN_HOSTS_PATH', '/path/to/known_hosts'):
            
            ssh_cmd = get_git_ssh_command()
            
            assert 'ssh' in ssh_cmd
            assert '/path/to/key' in ssh_cmd
            assert '/path/to/known_hosts' in ssh_cmd
            assert 'StrictHostKeyChecking=yes' in ssh_cmd


class TestConvertToSshUrl:
    """Test the convert_to_ssh_url function."""

    def test_convert_https_to_ssh(self):
        """Test converting HTTPS URL to SSH."""
        https_url = "https://github.com/owner/repo"
        ssh_url = convert_to_ssh_url(https_url)
        assert ssh_url == "git@github.com:owner/repo.git"

    def test_convert_https_to_ssh_with_trailing_slash(self):
        """Test converting HTTPS URL with trailing slash to SSH."""
        https_url = "https://github.com/owner/repo/"
        ssh_url = convert_to_ssh_url(https_url)
        assert ssh_url == "git@github.com:owner/repo.git"

    def test_convert_ssh_url_unchanged(self):
        """Test that SSH URL remains unchanged."""
        ssh_url = "git@github.com:owner/repo.git"
        result = convert_to_ssh_url(ssh_url)
        assert result == ssh_url


class TestParseVersion:
    """Test the parse_version function."""

    def test_parse_version_valid(self):
        """Test parsing valid version strings."""
        test_cases = [
            ("1.0.0", "1.0.0"),
            ("2.1.3", "2.1.3"),
            ("0.1.0-alpha", "0.1.0-alpha"),
        ]
        
        for version_str, expected_str in test_cases:
            result = parse_version(version_str)
            assert result is not None
            assert str(result) == expected_str

    def test_parse_version_invalid(self):
        """Test parsing invalid version strings."""
        invalid_versions = [
            None,
            "",
            "invalid",
            "1.0",
            "1.0.0.0",
        ]
        
        for version_str in invalid_versions:
            result = parse_version(version_str)
            assert result is None

    def test_parse_version_with_v_prefix(self):
        """Test parsing version strings with 'v' prefix."""
        result = parse_version("v1.0.0")
        assert result is not None
        assert str(result) == "1.0.0"
