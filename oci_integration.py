
import subprocess
import json
import logging
import semver
from typing import List, Optional
from version_utils import parse_version, is_pre_release_ver

class OciIntegration:
    """Handles OCI interactions using skopeo."""

    def __init__(self):
        self.skopeo_cmd = "skopeo"

    def list_tags(self, oci_url: str) -> List[str]:
        """
        List all tags for an OCI repository using skopeo.
        oci_url should be in format 'oci://registry/repo' or just 'docker://registry/repo'
        We convert oci:// to docker:// for skopeo.
        """
        if oci_url.startswith("oci://"):
            target = "docker://" + oci_url[6:]
        elif not oci_url.startswith("docker://"):
            target = "docker://" + oci_url
        else:
            target = oci_url

        try:
            # Use skopeo list-tags
            # Note: skopeo might need authentication. For now assuming public or mounted config.
            cmd = [self.skopeo_cmd, "list-tags", target]
            
            logging.debug("Running skopeo: %s", " ".join(cmd))
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30 
            )
            
            data = json.loads(result.stdout)
            return data.get("Tags", [])
            
        except subprocess.CalledProcessError as e:
            logging.debug("skopeo failed to list tags: %s", e.stderr)
            return []
        except json.JSONDecodeError as e:
            logging.error("Failed to parse skopeo output: %s", e)
            return []
        except FileNotFoundError:
            logging.warning("skopeo not found in path, OCI tag listing disabled")
            return []
        except Exception as e:
            logging.error("Unexpected error listing OCI tags: %s", e)
            return []

    def get_latest_version(self, oci_url: str, include_prerelease: bool = False) -> Optional[str]:
        """
        Find the latest version from an OCI repository, respecting pre-release filtering.
        """
        tags = self.list_tags(oci_url)
        if not tags:
            return None
            
        best_version: Optional[semver.VersionInfo] = None
        best_version_text: Optional[str] = None
        
        for tag in tags:
            ver = parse_version(tag)
            if not ver:
                continue
                
            if not include_prerelease and is_pre_release_ver(ver):
                continue
                
            if best_version is None or ver > best_version:
                best_version = ver
                best_version_text = tag
                
        return best_version_text
