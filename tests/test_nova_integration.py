import pytest
from unittest.mock import patch, MagicMock
import subprocess
import json
from nova_integration import NovaIntegration

@pytest.fixture
def nova_integration():
    return NovaIntegration()

def test_find_releases_success(nova_integration):
    mock_output = [
        {
            "release": "release1",
            "chartName": "chart1",
            "namespace": "ns1",
            "Installed": {"version": "1.0.0"},
            "Latest": {"version": "1.1.0"},
            "outdated": True,
            "deprecated": False
        }
    ]
    
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout=json.dumps(mock_output),
            returncode=0
        )
        
        releases = nova_integration.find_releases()
        
        assert len(releases) == 1
        assert releases[0]["release"] == "release1"
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "nova" in args
        assert "find" in args
        assert "--format" in args
        assert "json" in args

def test_find_releases_empty(nova_integration):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="",
            returncode=0
        )
        
        releases = nova_integration.find_releases()
        assert releases == []

def test_find_releases_error(nova_integration):
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, ["nova"], stderr="error")
        
        releases = nova_integration.find_releases()
        assert releases == []

def test_find_releases_json_error(nova_integration):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="invalid-json",
            returncode=0
        )
        
        releases = nova_integration.find_releases()
        assert releases == []

def test_get_outdated_releases(nova_integration):
    mock_releases = [
        {"release": "r1", "outdated": True},
        {"release": "r2", "outdated": False},
        {"release": "r3", "outdated": True}
    ]
    
    with patch.object(NovaIntegration, 'find_releases', return_value=mock_releases):
        outdated = nova_integration.get_outdated_releases()
        assert len(outdated) == 2
        assert outdated[0]["release"] == "r1"
        assert outdated[1]["release"] == "r3"


