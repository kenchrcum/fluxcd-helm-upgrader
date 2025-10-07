"""Integration tests for Kubernetes operations."""

import os
import pytest
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import list_helm_releases, get_namespaced_obj, resolve_repo_for_release


class TestKubernetesIntegration:
    """Integration tests for Kubernetes operations."""

    @patch('main.client.CustomObjectsApi')
    def test_list_helm_releases_success(self, mock_coapi_class):
        """Test successful HelmRelease listing."""
        # Mock API response
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        
        mock_response = {
            "items": [
                {
                    "metadata": {
                        "name": "test-app",
                        "namespace": "default"
                    },
                    "spec": {
                        "chart": {
                            "spec": {
                                "chart": "nginx",
                                "version": "1.0.0"
                            }
                        }
                    }
                }
            ]
        }
        mock_coapi.list_cluster_custom_object.return_value = mock_response
        
        # Test
        items, version = list_helm_releases(mock_coapi)
        
        assert len(items) == 1
        assert items[0]["metadata"]["name"] == "test-app"
        assert version == "v2"
        mock_coapi.list_cluster_custom_object.assert_called_once()

    @patch('main.client.CustomObjectsApi')
    def test_list_helm_releases_api_exception_404(self, mock_coapi_class):
        """Test HelmRelease listing with 404 API exception."""
        from kubernetes.client import ApiException
        
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        mock_coapi.list_cluster_custom_object.side_effect = ApiException(status=404)
        
        items, version = list_helm_releases(mock_coapi)
        
        assert items == []
        assert version is None

    @patch('main.client.CustomObjectsApi')
    def test_list_helm_releases_api_exception_403(self, mock_coapi_class):
        """Test HelmRelease listing with 403 API exception."""
        from kubernetes.client import ApiException
        
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        mock_coapi.list_cluster_custom_object.side_effect = ApiException(status=403)
        
        items, version = list_helm_releases(mock_coapi)
        
        assert items == []
        assert version is None

    @patch('main.client.CustomObjectsApi')
    def test_list_helm_releases_api_exception_500(self, mock_coapi_class):
        """Test HelmRelease listing with 500 API exception."""
        from kubernetes.client import ApiException
        
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        mock_coapi.list_cluster_custom_object.side_effect = ApiException(status=500)
        
        items, version = list_helm_releases(mock_coapi)
        
        assert items == []
        assert version is None

    @patch('main.client.CustomObjectsApi')
    def test_get_namespaced_obj_success(self, mock_coapi_class):
        """Test successful namespaced object retrieval."""
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        
        mock_response = {
            "metadata": {
                "name": "test-repo",
                "namespace": "default"
            },
            "spec": {
                "url": "https://charts.example.com"
            }
        }
        mock_coapi.get_namespaced_custom_object.return_value = mock_response
        
        obj, version = get_namespaced_obj(
            mock_coapi,
            "source.toolkit.fluxcd.io",
            ["v1", "v1beta2", "v1beta1"],
            "default",
            "helmrepositories",
            "test-repo"
        )
        
        assert obj == mock_response
        assert version == "v1"
        mock_coapi.get_namespaced_custom_object.assert_called_once()

    @patch('main.client.CustomObjectsApi')
    def test_get_namespaced_obj_not_found(self, mock_coapi_class):
        """Test namespaced object retrieval when object not found."""
        from kubernetes.client import ApiException
        
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        mock_coapi.get_namespaced_custom_object.side_effect = ApiException(status=404)
        
        obj, version = get_namespaced_obj(
            mock_coapi,
            "source.toolkit.fluxcd.io",
            ["v1", "v1beta2", "v1beta1"],
            "default",
            "helmrepositories",
            "nonexistent-repo"
        )
        
        assert obj is None
        assert version is None

    @patch('main.client.CustomObjectsApi')
    def test_resolve_repo_for_release_success(self, mock_coapi_class):
        """Test successful repository resolution for HelmRelease."""
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        
        # Mock HelmChart response
        mock_chart_response = {
            "metadata": {
                "name": "default-test-app",
                "namespace": "default"
            },
            "spec": {
                "sourceRef": {
                    "kind": "HelmRepository",
                    "name": "test-repo",
                    "namespace": "default"
                }
            }
        }
        
        # Mock HelmRepository response
        mock_repo_response = {
            "metadata": {
                "name": "test-repo",
                "namespace": "default"
            },
            "spec": {
                "url": "https://charts.example.com"
            }
        }
        
        # Configure mock to return different responses based on call
        def mock_get_namespaced_custom_object(group, version, namespace, plural, name):
            if plural == "helmcharts":
                return mock_chart_response
            elif plural == "helmrepositories":
                return mock_repo_response
            else:
                raise Exception("Unexpected call")
        
        mock_coapi.get_namespaced_custom_object.side_effect = mock_get_namespaced_custom_object
        
        # Test HelmRelease
        hr = {
            "metadata": {
                "name": "test-app",
                "namespace": "default"
            },
            "spec": {
                "chart": {
                    "spec": {
                        "chart": "nginx",
                        "version": "1.0.0"
                    }
                }
            }
        }
        
        result = resolve_repo_for_release(mock_coapi, hr)
        
        assert result == mock_repo_response

    @patch('main.client.CustomObjectsApi')
    def test_resolve_repo_for_release_fallback(self, mock_coapi_class):
        """Test repository resolution fallback to HelmRelease spec."""
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        
        # Mock HelmRepository response
        mock_repo_response = {
            "metadata": {
                "name": "test-repo",
                "namespace": "default"
            },
            "spec": {
                "url": "https://charts.example.com"
            }
        }
        
        # Configure mock to return None for helmcharts, repo for helmrepositories
        def mock_get_namespaced_custom_object(group, version, namespace, plural, name):
            if plural == "helmcharts":
                raise Exception("Not found")
            elif plural == "helmrepositories":
                return mock_repo_response
            else:
                raise Exception("Unexpected call")
        
        mock_coapi.get_namespaced_custom_object.side_effect = mock_get_namespaced_custom_object
        
        # Test HelmRelease with sourceRef in spec
        hr = {
            "metadata": {
                "name": "test-app",
                "namespace": "default"
            },
            "spec": {
                "chart": {
                    "spec": {
                        "chart": "nginx",
                        "version": "1.0.0",
                        "sourceRef": {
                            "kind": "HelmRepository",
                            "name": "test-repo",
                            "namespace": "default"
                        }
                    }
                }
            }
        }
        
        result = resolve_repo_for_release(mock_coapi, hr)
        
        assert result == mock_repo_response

    @patch('main.client.CustomObjectsApi')
    def test_resolve_repo_for_release_not_found(self, mock_coapi_class):
        """Test repository resolution when repository not found."""
        mock_coapi = MagicMock()
        mock_coapi_class.return_value = mock_coapi
        mock_coapi.get_namespaced_custom_object.side_effect = Exception("Not found")
        
        hr = {
            "metadata": {
                "name": "test-app",
                "namespace": "default"
            },
            "spec": {
                "chart": {
                    "spec": {
                        "chart": "nginx",
                        "version": "1.0.0"
                    }
                }
            }
        }
        
        result = resolve_repo_for_release(mock_coapi, hr)
        
        assert result is None
