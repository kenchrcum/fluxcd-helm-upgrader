"""Unit tests for GitHub utility functions."""

import os
import pytest
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import parse_github_repository, GitHubManager


class TestGitHubUtils:
    """Test cases for GitHub utility functions."""

    def test_parse_github_repository_valid(self):
        """Test parsing valid GitHub repository strings."""
        test_cases = [
            ("owner/repo", ("owner", "repo")),
            ("kubernetes/kubernetes", ("kubernetes", "kubernetes")),
            ("fluxcd/flux2", ("fluxcd", "flux2")),
            ("my-org/my-repo", ("my-org", "my-repo")),
        ]
        
        for repo_str, expected in test_cases:
            result = parse_github_repository(repo_str)
            assert result == expected, f"Failed to parse repository: {repo_str}"
            assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"

    def test_parse_github_repository_invalid(self):
        """Test parsing invalid GitHub repository strings."""
        invalid_repos = [
            "owner",
            "owner/",
            "/repo",
            "",
            "owner/repo/subpath",
            "owner repo",
        ]
        
        for repo_str in invalid_repos:
            with pytest.raises(ValueError, match="GITHUB_REPOSITORY must be in format 'owner/repo'"):
                parse_github_repository(repo_str)

    def test_github_manager_no_token(self):
        """Test GitHubManager initialization without token."""
        with patch.dict(os.environ, {}, clear=True):
            manager = GitHubManager()
            assert manager.client is None
            assert manager.owner is None
            assert manager.repo_name is None
            assert not manager.is_available()

    def test_github_manager_no_repository(self):
        """Test GitHubManager initialization without repository."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}, clear=True):
            manager = GitHubManager()
            assert manager.client is None
            assert manager.owner is None
            assert manager.repo_name is None
            assert not manager.is_available()

    def test_github_manager_invalid_repository_format(self):
        """Test GitHubManager initialization with invalid repository format."""
        with patch.dict(os.environ, {
            'GITHUB_TOKEN': 'test-token',
            'GITHUB_REPOSITORY': 'invalid-format'
        }, clear=True):
            manager = GitHubManager()
            assert manager.client is None
            assert manager.owner is None
            assert manager.repo_name is None
            assert not manager.is_available()

    @patch('main.Github')
    def test_github_manager_successful_init(self, mock_github_class):
        """Test successful GitHubManager initialization."""
        # Mock GitHub client and user
        mock_client = MagicMock()
        mock_user = MagicMock()
        mock_user.login = "test-user"
        mock_client.get_user.return_value = mock_user
        mock_github_class.return_value = mock_client
        
        # Mock the environment variables at the class level
        with patch.object(GitHubManager, '__init__', lambda self: None):
            manager = GitHubManager()
            manager.client = mock_client
            manager.owner = "owner"
            manager.repo_name = "repo"
            
            assert manager.client is not None
            assert manager.owner == "owner"
            assert manager.repo_name == "repo"
            assert manager.is_available()

    @patch('main.Github')
    def test_github_manager_auth_failure(self, mock_github_class):
        """Test GitHubManager initialization with authentication failure."""
        from github import GithubException
        mock_github_class.side_effect = GithubException(401, "Bad credentials")
        
        with patch.dict(os.environ, {
            'GITHUB_TOKEN': 'invalid-token',
            'GITHUB_REPOSITORY': 'owner/repo'
        }, clear=True):
            manager = GitHubManager()
            
            assert manager.client is None
            assert manager.owner is None
            assert manager.repo_name is None
            assert not manager.is_available()

    @patch('main.Github')
    def test_github_manager_get_repo(self, mock_github_class):
        """Test GitHubManager get_repo method."""
        # Mock GitHub client and repository
        mock_client = MagicMock()
        mock_repo = MagicMock()
        mock_user = MagicMock()
        mock_user.login = "test-user"
        mock_client.get_user.return_value = mock_user
        mock_client.get_repo.return_value = mock_repo
        mock_github_class.return_value = mock_client
        
        # Mock the environment variables at the class level
        with patch.object(GitHubManager, '__init__', lambda self: None):
            manager = GitHubManager()
            manager.client = mock_client
            manager.owner = "owner"
            manager.repo_name = "repo"
            result = manager.get_repo()
            
            assert result == mock_repo
            mock_client.get_repo.assert_called_once_with("owner/repo")

    def test_github_manager_get_repo_not_available(self):
        """Test GitHubManager get_repo method when not available."""
        with patch.dict(os.environ, {}, clear=True):
            manager = GitHubManager()
            result = manager.get_repo()
            
            assert result is None
