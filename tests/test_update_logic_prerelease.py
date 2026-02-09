
import pytest
from main import should_update

class TestVersionUpdateLogicPreRelease:
    """Test cases for version update logic with pre-release filtering."""
    
    def test_should_update_newer_stable(self):
        """Should update if latest > current and safe."""
        assert should_update("1.0.0", "1.0.1", include_prerelease=False) is True
        assert should_update("1.0.0", "1.0.1", include_prerelease=True) is True

    def test_should_not_update_prerelease_default(self):
        """Should NOT update to pre-release if include_prerelease=False."""
        # 1.81.9-nightly-latest > 0.1.837 mathematically, but it's a pre-release
        assert should_update("0.1.837", "1.81.9-nightly-latest", include_prerelease=False) is False
        assert should_update("1.0.0", "2.0.0-rc.1", include_prerelease=False) is False

    def test_should_update_prerelease_allowed(self):
        """Should update to pre-release if include_prerelease=True."""
        assert should_update("0.1.837", "1.81.9-nightly-latest", include_prerelease=True) is True
        assert should_update("1.0.0", "2.0.0-rc.1", include_prerelease=True) is True

    def test_should_update_prerelease_to_newer_prerelease(self):
        """If current is pre-release, we might update to newer pre-release?"""
        # The logic depends on policy. Usually if include_prerelease=False, we only want stable.
        # Even if current is pre-release, we probably don't want another unless opted-in.
        assert should_update("1.0.0-alpha.1", "1.0.0-alpha.2", include_prerelease=False) is False
        assert should_update("1.0.0-alpha.1", "1.0.0-alpha.2", include_prerelease=True) is True

    def test_should_update_prerelease_to_stable(self):
        """Should always update from pre-release to stable (if newer)."""
        assert should_update("1.0.0-alpha.1", "1.0.0", include_prerelease=False) is True
