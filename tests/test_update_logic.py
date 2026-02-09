
import pytest
from main import should_update

class TestVersionUpdateLogic:
    """Test cases for version update logic."""
    
    def test_should_update_newer(self):
        """Should update if latest > current."""
        assert should_update("1.0.0", "1.0.1") is True
        assert should_update("1.0.0", "2.0.0") is True

    def test_should_update_same(self):
        """Should NOT update if latest == current."""
        assert should_update("1.0.0", "1.0.0") is False

    def test_should_update_older(self):
        """Should NOT update if latest < current (downgrade)."""
        assert should_update("1.0.1", "1.0.0") is False
        assert should_update("2.0.0", "1.0.0") is False
        assert should_update("0.27.0", "0.5.0") is False # The reported issue case

    def test_should_update_invalid_current(self):
        """If current is invalid/unknown, we probably should update (conservative fallback)."""
        # If we can't parse current, we might want to update assuming current is broken or not semver
        # BUT for safety, maybe we should log and continue. 
        # Let's assume the function handles None safely.
        # If current is None, we treat it as "no version installed", so update to latest.
        assert should_update(None, "1.0.0") is True
        assert should_update("invalid", "1.0.0") is True 

    def test_should_update_invalid_latest(self):
        """If latest is invalid, we definitely should NOT update."""
        assert should_update("1.0.0", None) is False
        assert should_update("1.0.0", "invalid") is False
