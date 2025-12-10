#!/usr/bin/env python3
"""
Test script to verify the fallback mechanism works when Nova doesn't find releases.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from unittest.mock import Mock, patch, MagicMock
import json

# Mock the kubernetes and other imports that might not be available
sys.modules['kubernetes'] = Mock()
sys.modules['kubernetes.client'] = Mock()
sys.modules['kubernetes.config'] = Mock()
sys.modules['github'] = Mock()
sys.modules['prometheus_client'] = Mock()

# Now import our modules
from nova_integration import NovaIntegration
from main import check_once

def test_fallback_logic():
    """Test that fallback logic is triggered when Nova doesn't find releases."""

    # Mock Nova to return empty results (simulating no releases found)
    mock_nova = Mock()
    mock_nova.get_outdated_releases.return_value = []

    # Mock Kubernetes API to return a sample HelmRelease
    mock_coapi = Mock()

    sample_hr = {
        "metadata": {
            "namespace": "default",
            "name": "test-release"
        },
        "spec": {
            "chart": {
                "spec": {
                    "chart": "test-chart",
                    "version": "1.0.0",
                    "sourceRef": {
                        "name": "test-repo",
                        "namespace": "default"
                    }
                }
            }
        }
    }

    # Mock the list_helm_releases function
    with patch('main.list_helm_releases', return_value=([sample_hr], 'v1')) as mock_list_hr, \
         patch('main.NovaIntegration', return_value=mock_nova), \
         patch('main.get_current_chart_name_and_version', return_value=('test-chart', '1.0.0')), \
         patch('main.resolve_repo_for_release') as mock_resolve_repo, \
         patch('main.fetch_repo_index') as mock_fetch_index, \
         patch('main.latest_available_version', return_value='2.0.0') as mock_latest_version, \
         patch('main.ensure_repo_cloned_or_updated', return_value=None), \
         patch('main.initialize_metrics'), \
         patch('main.METRICS'), \
         patch('main.logging') as mock_logging:

        # Mock repo resolution to return a repo
        mock_repo = {"spec": {"type": "default"}}
        mock_resolve_repo.return_value = mock_repo

        # Mock index fetch to return a valid index
        mock_fetch_index.return_value = {"entries": {"test-chart": [{"version": "2.0.0"}]}}

        # Call check_once
        check_once(mock_coapi)

        # Verify that Nova was called
        assert mock_nova.get_outdated_releases.called

        # Verify that fallback logic was triggered
        mock_resolve_repo.assert_called_once_with(mock_coapi, sample_hr)
        mock_fetch_index.assert_called_once_with(mock_repo)
        mock_latest_version.assert_called_once_with({"entries": {"test-chart": [{"version": "2.0.0"}]}}, 'test-chart', False)

        # Verify logging of fallback usage
        mock_logging.debug.assert_any_call("%s/%s: Nova not found, using fallback method", "default", "test-release")

    print("✅ Fallback logic test passed!")

if __name__ == "__main__":
    test_fallback_logic()
