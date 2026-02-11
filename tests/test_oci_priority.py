
import pytest
from unittest.mock import MagicMock, patch
from main import check_once
from oci_integration import OciIntegration

class TestOciPriority:
    
    @patch('main.client.CustomObjectsApi')
    @patch('main.fetch_repo_index')
    @patch('oci_integration.OciIntegration.get_latest_version')
    @patch('main.REPO_URL', '/tmp/mock-repo')
    @patch('main.GITHUB_TOKEN', 'fake-token')
    @patch('main.create_github_client', return_value=MagicMock())
    @patch('main.ensure_repo_cloned_or_updated', return_value='/tmp/mock-repo')
    @patch('main.resolve_manifest_path_for_release', return_value='clusters/my-cluster/demo-app.yaml')
    def test_oci_priority_over_nova(self, mock_resolve_manifest, mock_ensure_repo, mock_github_client, mock_get_latest, mock_fetch_repo, mock_coapi):
        # Setup: 
        # Nova/Repo would report version 0.1.0 (simulated by failure to find or being old)
        # OCI reports 0.1.4
        # Current is 0.1.3
        
        # Mock HelmReleases
        mock_coapi.return_value.list_cluster_custom_object.return_value = {
            "items": [
                {
                    "metadata": {"name": "demo-app", "namespace": "default"},
                    "spec": {
                        "chart": {
                            "spec": {
                                "chart": "demo-app",
                                "version": "0.1.3",
                                "sourceRef": {
                                    "kind": "OCIRepository",
                                    "name": "demo-repo",
                                    "namespace": "default"
                                }
                            }
                        }
                    }
                }
            ]
        }
        
        # Mock OCIRepository
        def get_custom_object(group, version, namespace, plural, name):
            if plural == "ocirepositories" and name == "demo-repo":
                return {
                    "spec": {
                        "url": "oci://private.registry/helm/demo-app"
                    }
                }
            return None
            
        mock_coapi.return_value.get_namespaced_custom_object.side_effect = get_custom_object
        
        # Mock OCI Integration to return newer version
        mock_get_latest.return_value = "0.1.4"
        
        with patch('main.update_oci_repository_manifest') as mock_update_oci, \
             patch('main.update_helm_release_manifest', return_value=True) as mock_update_hr, \
             patch('main.create_update_branch', return_value='update-branch'), \
             patch('main.commit_and_push_changes', return_value=True), \
             patch('main.create_github_pull_request', return_value='http://pr-url'):
             
            # We also need to mock Nova or ensure it doesn't crash
            with patch('main.NovaIntegration') as mock_nova:
                 mock_nova.return_value.get_outdated_releases.return_value = [] # Nova finds nothing useful
            
                 check_once(mock_coapi())
                 
            # Verify OCI was queried
            mock_get_latest.assert_called_with("oci://private.registry/helm/demo-app", include_prerelease=False)
            
            # Since the mock object has sourceRef Kind: OCIRepository, logic in main.py
            # determines whether to call update_oci_repository_manifest or update_helm_release_manifest
            # In our mock:
            # spec: { "chart": { "spec": { ... sourceRef ... } } } (Flux v2 HelmRelease style)
            # Top level 'chartRef' is missing.
            # So it should fall into `else` block -> update_helm_release_manifest.
            
            assert mock_update_hr.called
            args, _ = mock_update_hr.call_args
            # update_helm_release_manifest(repo_dir, manifest_rel_path, latest_text, current_version_text)
            # args[2] is latest_text
            assert args[2] == "0.1.4"
