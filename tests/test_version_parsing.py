"""Unit tests for version parsing functionality."""

import os
import pytest
import semver
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from version_utils import parse_version
from main import get_current_chart_name_and_version


class TestVersionParsing:
    """Test cases for version parsing functions."""

    def test_parse_version_valid(self):
        """Test parsing valid version strings."""
        test_cases = [
            ("1.0.0", semver.VersionInfo(1, 0, 0)),
            ("2.1.3", semver.VersionInfo(2, 1, 3)),
            ("v1.0.0", semver.VersionInfo(1, 0, 0)),
            ("v2.1.3", semver.VersionInfo(2, 1, 3)),
            ("1.0.0-alpha.1", semver.VersionInfo(1, 0, 0, prerelease="alpha.1")),
            ("2.1.3-beta.2", semver.VersionInfo(2, 1, 3, prerelease="beta.2")),
            ("1.0.0+123", semver.VersionInfo(1, 0, 0, build="123")),
            ("2.1.3-alpha.1+456", semver.VersionInfo(2, 1, 3, prerelease="alpha.1", build="456")),
        ]
        
        for version_str, expected in test_cases:
            result = parse_version(version_str)
            assert result == expected, f"Failed to parse version: {version_str}"

    def test_parse_version_invalid(self):
        """Test parsing invalid version strings."""
        invalid_versions = [
            None,
            "",
            "invalid",
            "1.0",
            "1.0.0.0",
            "not-a-version",
        ]
        
        for version_str in invalid_versions:
            result = parse_version(version_str)
            assert result is None, f"Should return None for invalid version: {version_str}"

    def test_parse_version_caching(self):
        """Test that version parsing uses caching."""
        # First call
        result1 = parse_version("1.0.0")
        # Second call should use cache
        result2 = parse_version("1.0.0")
        
        assert result1 == result2
        assert result1 is result2  # Should be the same object due to caching

    def test_get_current_chart_name_and_version_from_status(self):
        """Test extracting chart name and version from HelmRelease status."""
        hr = {
            "spec": {
                "chart": {
                    "spec": {
                        "chart": "nginx",
                        "version": "1.0.0"
                    }
                }
            },
            "status": {
                "lastAppliedRevision": "nginx-1.0.0"
            }
        }
        
        chart_name, version = get_current_chart_name_and_version(None, hr)
        assert chart_name == "nginx"
        assert version == "1.0.0"

    def test_get_current_chart_name_and_version_from_spec(self):
        """Test extracting chart name and version from HelmRelease spec when status is missing."""
        hr = {
            "spec": {
                "chart": {
                    "spec": {
                        "chart": "redis",
                        "version": "2.1.0"
                    }
                }
            },
            "status": {}
        }
        
        chart_name, version = get_current_chart_name_and_version(None, hr)
        assert chart_name == "redis"
        assert version == "2.1.0"

    def test_get_current_chart_name_and_version_complex_revision(self):
        """Test extracting chart name and version from complex revision format."""
        hr = {
            "spec": {
                "chart": {
                    "spec": {
                        "chart": "postgresql",
                        "version": "1.2.3"
                    }
                }
            },
            "status": {
                "lastAppliedRevision": "postgresql-1.2.3-alpha.1+456"
            }
        }
        
        chart_name, version = get_current_chart_name_and_version(None, hr)
        assert chart_name == "postgresql"
        assert version == "1.2.3-alpha.1+456"

    def test_get_current_chart_name_and_version_missing_chart_name(self):
        """Test extracting version when chart name is missing from spec."""
        hr = {
            "spec": {
                "chart": {
                    "spec": {
                        "version": "3.0.0"
                    }
                }
            },
            "status": {
                "lastAppliedRevision": "myapp-3.0.0"
            }
        }
        
        chart_name, version = get_current_chart_name_and_version(None, hr)
        assert chart_name == "myapp"
        assert version == "3.0.0"

    def test_get_current_chart_name_and_version_invalid_revision(self):
        """Test handling invalid revision format."""
        hr = {
            "spec": {
                "chart": {
                    "spec": {
                        "chart": "nginx",
                        "version": "1.0.0"
                    }
                }
            },
            "status": {
                "lastAppliedRevision": "invalid-revision-format"
            }
        }
        
        chart_name, version = get_current_chart_name_and_version(None, hr)
        assert chart_name == "nginx"
        assert version is None  # Invalid revision format results in None

    def test_get_current_chart_name_and_version_empty_hr(self):
        """Test handling empty HelmRelease."""
        hr = {}
        
        chart_name, version = get_current_chart_name_and_version(None, hr)
        assert chart_name is None
        assert version is None
