
import semver
from typing import Optional, Dict

# Cache for parsed versions to avoid re-parsing
_version_cache: Dict[str, Optional[semver.VersionInfo]] = {}

def parse_version(text: Optional[str]) -> Optional[semver.VersionInfo]:
    """Parse version string with caching for performance."""
    if not text:
        return None
    
    # Check cache first
    if text in _version_cache:
        return _version_cache[text]
    
    raw = text.strip()
    if raw.startswith("v"):
        raw = raw[1:]
    
    try:
        version = semver.VersionInfo.parse(raw)
        _version_cache[text] = version
        return version
    except ValueError:
        _version_cache[text] = None
        return None

def is_pre_release_ver(version: Optional[semver.VersionInfo]) -> bool:
    """
    Check if a version is a pre-release, with exceptions for 'stable' tag.
    Returns True if it is a pre-release that should be filtered out.
    Returns False if it is a stable version or has 'stable' tag exceptions.
    """
    if not version:
        return False
        
    if not version.prerelease:
        return False
        
    # Exception: treat "stable" as not a pre-release
    # Also handle composite like "stable.1" if needed, but for now exact match "stable"
    if str(version.prerelease).lower() == "stable":
        return False
        
    return True
