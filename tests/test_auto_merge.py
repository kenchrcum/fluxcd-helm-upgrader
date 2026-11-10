"""Unit tests for the PR auto-merge feature."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from github import GithubException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import main
from main import (
    Config,
    auto_merge_pull_request,
    is_auto_merge_enabled,
    parse_auto_merge_patterns,
)

PR_URL = "https://github.com/owner/repo/pull/42"
BRANCH = "update-apps-my-app-1-2-3"


class TestParseAutoMergePatterns:
    """Test cases for parsing GITHUB_AUTO_MERGE_HELMRELEASES."""

    def test_empty(self):
        assert parse_auto_merge_patterns("") == []
        assert parse_auto_merge_patterns("   ") == []

    def test_json_list(self):
        assert parse_auto_merge_patterns('["my-app", " apps/other "]') == ["my-app", "apps/other"]

    def test_comma_separated(self):
        assert parse_auto_merge_patterns("my-app, apps/other,") == ["my-app", "apps/other"]

    @pytest.mark.parametrize("raw", ['["a", 1]', '{"a": "b"}', '["a"', '[""]'])
    def test_invalid(self, raw):
        with pytest.raises(ValueError, match="GITHUB_AUTO_MERGE_HELMRELEASES"):
            parse_auto_merge_patterns(raw)


class TestIsAutoMergeEnabled:
    """Test cases for matching HelmReleases against the auto-merge list."""

    def test_disabled_by_default(self):
        with patch('main.GITHUB_AUTO_MERGE_HELMRELEASES', ''):
            assert not is_auto_merge_enabled("apps", "my-app")

    @pytest.mark.parametrize(
        "namespace,name,expected",
        [
            ("apps", "my-app", True),           # name matches in any namespace
            ("other", "my-app", True),
            ("apps", "my-app-2", False),        # no substring matching
            ("staging", "foo", True),           # namespace/name
            ("production", "foo", False),
            ("dev", "anything", True),          # wildcard
            ("apps", "anything", False),
        ],
    )
    def test_matching(self, namespace, name, expected):
        with patch('main.GITHUB_AUTO_MERGE_HELMRELEASES', '["my-app", "staging/foo", "dev/*"]'):
            assert is_auto_merge_enabled(namespace, name) is expected

    def test_invalid_config_disables_auto_merge(self):
        with patch('main.GITHUB_AUTO_MERGE_HELMRELEASES', '{"my-app": true}'):
            assert not is_auto_merge_enabled("apps", "my-app")


def _make_client(pr):
    github_client = MagicMock()
    repo = github_client.get_repo.return_value
    repo.get_pull.return_value = pr
    return github_client, repo


def _open_pr():
    pr = MagicMock()
    pr.merged = False
    pr.state = "open"
    pr.head.ref = BRANCH
    pr.merge.return_value.merged = True
    return pr


@patch('main.GITHUB_REPOSITORY', 'owner/repo')
@patch('main.time.sleep', MagicMock())
class TestAutoMergePullRequest:
    """Test cases for merging update PRs."""

    def test_merges_open_pr_and_deletes_branch(self):
        pr = _open_pr()
        github_client, repo = _make_client(pr)

        with patch('main.GITHUB_AUTO_MERGE_METHOD', 'squash'), \
             patch('main.GITHUB_AUTO_MERGE_DELETE_BRANCH', True):
            assert auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)

        repo.get_pull.assert_called_once_with(42)
        pr.merge.assert_called_once_with(merge_method='squash')
        repo.get_git_ref.assert_called_once_with(f"heads/{BRANCH}")
        repo.get_git_ref.return_value.delete.assert_called_once()
        pr.enable_automerge.assert_not_called()

    def test_keeps_branch_when_delete_disabled(self):
        pr = _open_pr()
        github_client, repo = _make_client(pr)

        with patch('main.GITHUB_AUTO_MERGE_DELETE_BRANCH', False):
            assert auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)

        repo.get_git_ref.assert_not_called()

    def test_branch_delete_failure_does_not_fail_merge(self):
        pr = _open_pr()
        github_client, repo = _make_client(pr)
        repo.get_git_ref.side_effect = GithubException(422, {"message": "Reference does not exist"}, None)

        with patch('main.GITHUB_AUTO_MERGE_DELETE_BRANCH', True):
            assert auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)

    def test_already_merged(self):
        pr = _open_pr()
        pr.merged = True
        pr.state = "closed"
        github_client, _ = _make_client(pr)

        assert auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)
        pr.merge.assert_not_called()

    def test_closed_pr_is_not_merged(self):
        pr = _open_pr()
        pr.state = "closed"
        github_client, _ = _make_client(pr)

        assert not auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)
        pr.merge.assert_not_called()

    def test_foreign_branch_is_not_merged(self):
        pr = _open_pr()
        pr.head.ref = "someones-manual-branch"
        github_client, _ = _make_client(pr)

        assert not auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)
        pr.merge.assert_not_called()

    def test_url_without_pr_number(self):
        github_client = MagicMock()

        assert not auto_merge_pull_request(github_client, "PR already exists", "apps", "my-app", BRANCH)
        github_client.get_repo.assert_not_called()

    def test_retries_while_not_mergeable(self):
        pr = _open_pr()
        merged = MagicMock(merged=True)
        pr.merge.side_effect = [
            GithubException(405, {"message": "Pull Request is not mergeable"}, None),
            merged,
        ]
        github_client, _ = _make_client(pr)

        assert auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)
        assert pr.merge.call_count == 2
        pr.enable_automerge.assert_not_called()

    def test_falls_back_to_native_auto_merge(self):
        pr = _open_pr()
        pr.merge.side_effect = GithubException(405, {"message": "Required status check is expected"}, None)
        github_client, repo = _make_client(pr)

        with patch('main.GITHUB_AUTO_MERGE_METHOD', 'rebase'):
            assert not auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)

        assert pr.merge.call_count == 3
        pr.enable_automerge.assert_called_once_with(merge_method='REBASE')
        repo.get_git_ref.assert_not_called()

    def test_native_auto_merge_failure_is_handled(self):
        pr = _open_pr()
        pr.merge.side_effect = GithubException(403, {"message": "Resource not accessible"}, None)
        pr.enable_automerge.side_effect = GithubException(422, {"message": "Auto merge is not allowed"}, None)
        github_client, _ = _make_client(pr)

        assert not auto_merge_pull_request(github_client, PR_URL, "apps", "my-app", BRANCH)
        assert pr.merge.call_count == 1  # 403 is not retried


class TestAutoMergeConfigValidation:
    """Test cases for auto-merge configuration validation."""

    def _errors(self, **overrides):
        with patch.multiple(Config, **overrides):
            _, errors = Config.validate_configuration()
        return [e for e in errors if "AUTO_MERGE" in e]

    def test_valid(self):
        assert self._errors(
            GITHUB_AUTO_MERGE_HELMRELEASES='["my-app"]', GITHUB_AUTO_MERGE_METHOD='squash'
        ) == []

    def test_invalid_list(self):
        assert len(self._errors(GITHUB_AUTO_MERGE_HELMRELEASES='{"my-app": true}')) == 1

    def test_invalid_method(self):
        assert self._errors(GITHUB_AUTO_MERGE_METHOD='fast-forward') == [
            "GITHUB_AUTO_MERGE_METHOD must be one of: merge, squash, rebase"
        ]


class TestPullRequestBody:
    """The PR body should reflect whether the PR is auto-merged."""

    def _body(self, auto_merge):
        github_client = MagicMock()
        repo = github_client.get_repo.return_value
        repo.default_branch = "main"
        repo.create_pull.return_value.html_url = PR_URL
        with patch('main.GITHUB_REPOSITORY', 'owner/repo'), \
             patch('main.GITHUB_DEFAULT_BRANCH', ''), \
             patch('main.determine_github_assignee', return_value=None):
            url = main.create_github_pull_request(
                github_client, "apps", "my-app", "1.2.2", "1.2.3", BRANCH,
                "components/apps/my-app/helmrelease.yaml", auto_merge=auto_merge,
            )
        assert url == PR_URL
        return repo.create_pull.call_args.kwargs["body"]

    def test_default_body_asks_for_review(self):
        body = self._body(False)
        assert "### Testing" in body
        assert "### Auto-merge" not in body

    def test_auto_merge_body(self):
        body = self._body(True)
        assert "### Auto-merge" in body
        assert "### Testing" not in body
