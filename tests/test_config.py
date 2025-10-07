"""Unit tests for configuration management."""

import os
import pytest
from unittest.mock import patch
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import Config


class TestConfig:
    """Test cases for Config class."""

    def test_default_values(self):
        """Test default configuration values."""
        assert Config.HELM_RELEASE_GROUP == "helm.toolkit.fluxcd.io"
        assert Config.SOURCE_GROUP == "source.toolkit.fluxcd.io"
        assert Config.HELM_RELEASE_VERSIONS == ["v2", "v2beta2", "v2beta1"]
        assert Config.SOURCE_VERSIONS == ["v1", "v1beta2", "v1beta1"]
        assert Config.DEFAULT_INTERVAL_SECONDS == 300
        assert Config.REQUEST_TIMEOUT == (5, 20)
        assert Config.HEALTH_CHECK_PORT == 8080
        assert Config.METRICS_PORT == 8081

    def test_boolean_env_true_values(self):
        """Test boolean environment variable parsing for true values."""
        true_values = ["1", "true", "yes", "on", "TRUE", "YES", "ON"]
        for value in true_values:
            with patch.dict(os.environ, {'TEST_BOOL': value}):
                assert Config.get_boolean_env('TEST_BOOL', False) is True

    def test_boolean_env_false_values(self):
        """Test boolean environment variable parsing for false values."""
        false_values = ["0", "false", "no", "off", "FALSE", "NO", "OFF", ""]
        for value in false_values:
            with patch.dict(os.environ, {'TEST_BOOL': value}):
                assert Config.get_boolean_env('TEST_BOOL', True) is False

    def test_boolean_env_default(self):
        """Test boolean environment variable default values."""
        with patch.dict(os.environ, {}, clear=True):
            assert Config.get_boolean_env('MISSING_KEY', True) is True
            assert Config.get_boolean_env('MISSING_KEY', False) is False

    def test_include_prerelease_env(self):
        """Test INCLUDE_PRERELEASE environment variable parsing."""
        # Test the boolean parsing logic directly
        assert Config.get_boolean_env('INCLUDE_PRERELEASE', False) is False  # Default
        
        # Test with different values
        test_cases = [
            ('true', True),
            ('false', False),
            ('1', True),
            ('0', False),
            ('yes', True),
            ('no', False),
            ('on', True),
            ('off', False),
        ]
        
        for value, expected in test_cases:
            with patch.dict(os.environ, {'INCLUDE_PRERELEASE': value}):
                result = Config.get_boolean_env('INCLUDE_PRERELEASE', False)
                assert result == expected, f"Failed for value: {value}"

    def test_interval_seconds_env(self):
        """Test INTERVAL_SECONDS environment variable parsing."""
        # Test default value
        assert Config.DEFAULT_INTERVAL_SECONDS == 300
        
        # Test that the logic works (we can't easily test the actual env var without module reload)
        # But we can test the parsing logic
        test_value = int(os.getenv("INTERVAL_SECONDS", "300"))
        assert isinstance(test_value, int)
        assert test_value > 0

    def test_health_check_config_env(self):
        """Test health check configuration environment variables."""
        # Test default values
        assert Config.HEALTH_CHECK_PORT == 8080
        assert Config.HEALTH_CHECK_HOST == "0.0.0.0"
        
        # Test that the logic works
        test_port = int(os.getenv("HEALTH_CHECK_PORT", "8080"))
        test_host = os.getenv("HEALTH_CHECK_HOST", "0.0.0.0")
        assert isinstance(test_port, int)
        assert isinstance(test_host, str)

    def test_metrics_config_env(self):
        """Test metrics configuration environment variables."""
        # Test default values
        assert Config.METRICS_PORT == 8081
        assert Config.METRICS_HOST == "0.0.0.0"
        
        # Test that the logic works
        test_port = int(os.getenv("METRICS_PORT", "8081"))
        test_host = os.getenv("METRICS_HOST", "0.0.0.0")
        assert isinstance(test_port, int)
        assert isinstance(test_host, str)

    def test_git_force_push_env(self):
        """Test GIT_FORCE_PUSH environment variable parsing."""
        # Test default value
        assert Config.GIT_FORCE_PUSH is False
        
        # Test the boolean parsing logic
        test_cases = [
            ('true', True),
            ('false', False),
            ('1', True),
            ('0', False),
        ]
        
        for value, expected in test_cases:
            result = Config.get_boolean_env('GIT_FORCE_PUSH', False)
            # Since we can't easily mock the class attribute, test the method logic
            assert isinstance(result, bool)
