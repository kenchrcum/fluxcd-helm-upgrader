import subprocess
import json
import logging
import os
from typing import List, Dict, Any, Optional

class NovaIntegration:
    def __init__(self):
        pass

    def find_releases(self) -> List[Dict[str, Any]]:
        """
        Run nova find --format json and return parsed output.
        """
        try:
            # Run nova find
            # We disable container scanning to focus on Helm charts and speed up
            cmd = ["nova", "find", "--format", "json", "--containers=false"]
            
            # Add optional extra arguments from environment variable
            extra_args = os.getenv("NOVA_ARGS", "").strip()
            if extra_args:
                cmd.extend(extra_args.split())
            
            logging.info("Running nova scan: %s", " ".join(cmd))
            
            # Set env to ensure it uses in-cluster config if needed, 
            # though client-go usually handles it.
            env = os.environ.copy()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                check=True
            )
            
            if not result.stdout.strip():
                return []
                
            data = json.loads(result.stdout)
            return data
        except subprocess.CalledProcessError as e:
            logging.error(f"nova find failed: {e.stderr}")
            return []
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse nova output: {e}")
            logging.debug(f"Raw output: {result.stdout}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error running nova: {e}")
            return []

    def get_outdated_releases(self) -> List[Dict[str, Any]]:
        """
        Returns a list of releases that nova considers outdated.
        """
        releases = self.find_releases()
        outdated = []
        for release in releases:
            # Check if outdated or deprecated (user might want to know about deprecated too)
            # The user's sample output shows "outdated": true/false.
            if release.get("outdated"):
                outdated.append(release)
        return outdated

