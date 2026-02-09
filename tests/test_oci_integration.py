
import pytest
from unittest.mock import MagicMock, patch
from oci_integration import OciIntegration
import json

class TestOciIntegration:

    @patch('subprocess.run')
    def test_list_tags(self, mock_run):
        oci = OciIntegration()
        
        # Mock skopeo output
        mock_output = {
            "Repository": "docker.io/library/alpine",
            "Tags": ["3.14", "3.15", "latest", "edge", "3.15.0-rc1"]
        }
        mock_run.return_value.stdout = json.dumps(mock_output)
        mock_run.return_value.returncode = 0
        
        tags = oci.list_tags("oci://docker.io/library/alpine")
        assert "3.14" in tags
        assert "3.15.0-rc1" in tags
        
        # Verify skopeo call
        expected_cmd = ["skopeo", "list-tags", "docker://docker.io/library/alpine"]
        mock_run.assert_called_once()
        args, _ = mock_run.call_args
        assert args[0] == expected_cmd

    @patch('subprocess.run')
    def test_get_latest_version_stable(self, mock_run):
        oci = OciIntegration()
        
        mock_output = {
            "Repository": "test/repo",
            "Tags": ["1.0.0", "1.1.0", "1.2.0-rc1", "1.2.0-nightly"]
        }
        mock_run.return_value.stdout = json.dumps(mock_output)
        
        # Should return 1.1.0 (ignore 1.2.0-* pre-releases)
        latest = oci.get_latest_version("oci://test/repo", include_prerelease=False)
        assert latest == "1.1.0"
        
    @patch('subprocess.run')
    def test_get_latest_version_include_prerelease(self, mock_run):
        oci = OciIntegration()
        
        mock_output = {
            "Repository": "test/repo",
            "Tags": ["1.0.0", "1.1.0", "1.2.0-rc1"]
        }
        mock_run.return_value.stdout = json.dumps(mock_output)
        
        # Should return 1.2.0-rc1
        latest = oci.get_latest_version("oci://test/repo", include_prerelease=True)
        assert latest == "1.2.0-rc1"
