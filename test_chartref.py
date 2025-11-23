#!/usr/bin/env python3

"""
Simple test script to verify chartRef logic for OCI repositories
"""

# Mock the kubernetes client and functions we need
class MockCoApi:
    pass

def get_oci_repository(coapi, namespace, name):
    """Mock OCIRepository lookup"""
    if name == "litellm":
        return {
            "spec": {
                "url": "oci://ghcr.io/berriai/litellm-helm",
                "ref": {
                    "tag": "0.1.805"
                }
            }
        }, None
    return None, None

# Import the function from main.py
import sys
sys.path.insert(0, '/home/kenneth/Documents/github/fluxcd-helm-upgrader')

# Mock the imports that might not be available
import unittest.mock as mock
with mock.patch.dict('sys.modules', {
    'kubernetes': mock.MagicMock(),
    'kubernetes.client': mock.MagicMock(),
    'kubernetes.config': mock.MagicMock(),
    'prometheus_client': mock.MagicMock(),
    'nova_integration': mock.MagicMock(),
}):
    from main import get_current_chart_name_and_version

# Test chartRef logic
def test_chartref_logic():
    hr = {
        "metadata": {
            "namespace": "demo-ai-services",
            "name": "litellm"
        },
        "spec": {
            "chartRef": {
                "kind": "OCIRepository",
                "name": "litellm",
                "namespace": "helmrepositories"
            }
        },
        "status": {
            "lastAppliedRevision": "0.1.805+94c7b2e9075a"
        }
    }

    coapi = MockCoApi()
    chart_name, current_version = get_current_chart_name_and_version(coapi, hr)

    print(f"Chart name: {chart_name}")
    print(f"Current version: {current_version}")

    assert chart_name == "litellm-helm", f"Expected 'litellm-helm', got '{chart_name}'"
    assert current_version == "0.1.805", f"Expected '0.1.805', got '{current_version}'"

    print("✅ chartRef test passed!")

if __name__ == "__main__":
    test_chartref_logic()
