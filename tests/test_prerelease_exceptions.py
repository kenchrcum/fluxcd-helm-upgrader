
import pytest
from version_utils import parse_version

def is_stable(version_text):
    """Helper to simulate logic we want to implement."""
    ver = parse_version(version_text)
    if not ver:
        return False
    # Current logic (simulated failure)
    if ver.prerelease:
        return False
    return True

def test_stable_tag_rejection_current_behavior():
    """Verify that current logic rejects '1.81.3-stable'."""
    assert is_stable("1.81.3-stable") is False
    assert is_stable("1.0.0") is True

def test_desired_behavior_prototype():
    """Verify desired logic."""
    def new_is_stable(version_text):
        ver = parse_version(version_text)
        if not ver:
            return False
        
        if ver.prerelease:
            # Exception for 'stable'
            if ver.prerelease.lower() == "stable":
                return True
            return False
        return True

    assert new_is_stable("1.81.3-stable") is True
    assert new_is_stable("1.81.9-nightly-latest") is False
    assert new_is_stable("1.0.0-rc.1") is False
