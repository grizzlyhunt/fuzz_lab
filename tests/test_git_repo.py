"""Unit tests for git_repo.py.

checkout_repo shells out to git; proc.run is mocked (as git_repo.run, the name this
module imported it under) so the tests assert on the command line built rather than
cloning anything over the network.
"""

import os
from dataclasses import FrozenInstanceError
from unittest import mock

import pytest

from fuzz_lab import git_repo
from fuzz_lab.git_repo import SourceRepo, checkout_repo


class TestSourceRepo:
    def test_keeps_the_full_history_by_default(self):
        assert SourceRepo("cgltf", "https://example.invalid/cgltf").depth is None

    def test_is_immutable(self):
        # Repos are stored in FuzzerConfig and compared by value; freezing them keeps a
        # caller from editing an entry in place and desynchronising it from fuzzer.json.
        repo = SourceRepo("cgltf", "https://example.invalid/cgltf")

        with pytest.raises(FrozenInstanceError):
            # The assignment is the point of the test, so the type checker is told to
            # allow what it would otherwise (correctly) reject on a frozen dataclass.
            repo.name = "other"  # pyright: ignore[reportAttributeAccessIssue]

    def test_compares_by_value(self):
        assert SourceRepo("cgltf", "https://example.invalid/cgltf", 1) == SourceRepo(
            "cgltf", "https://example.invalid/cgltf", 1
        )


class TestCheckoutRepo:
    @pytest.fixture
    def repo(self):
        return SourceRepo("cgltf", "https://example.invalid/cgltf")

    def test_clones_into_a_subdirectory_named_after_the_repo(self, tmp_path, repo, completed):
        with mock.patch.object(git_repo, "run", return_value=completed()) as fake_run:
            checkout_repo(repo, str(tmp_path))

        args = fake_run.call_args.args[0]
        assert args[:2] == ["git", "clone"]
        assert args[-2:] == [repo.url, os.path.join(str(tmp_path), "cgltf")]

    def test_pulls_instead_of_cloning_when_the_checkout_already_exists(self, tmp_path, repo, completed):
        repo_dir = tmp_path / "cgltf"
        repo_dir.mkdir()

        with mock.patch.object(git_repo, "run", return_value=completed()) as fake_run:
            checkout_repo(repo, str(tmp_path))

        args = fake_run.call_args.args[0]
        assert args[:4] == ["git", "-C", str(repo_dir), "pull"]

    def test_shallow_clones_when_a_depth_is_configured(self, tmp_path, completed):
        repo = SourceRepo("cgltf", "https://example.invalid/cgltf", depth=1)

        with mock.patch.object(git_repo, "run", return_value=completed()) as fake_run:
            checkout_repo(repo, str(tmp_path))

        args = fake_run.call_args.args[0]
        assert "--depth" in args
        assert args[args.index("--depth") + 1] == "1"

    def test_omits_the_depth_flag_when_the_full_history_is_wanted(self, tmp_path, repo, completed):
        with mock.patch.object(git_repo, "run", return_value=completed()) as fake_run:
            checkout_repo(repo, str(tmp_path))

        assert "--depth" not in fake_run.call_args.args[0]

    def test_treats_a_zero_depth_as_no_depth_limit(self, tmp_path, completed):
        # `git clone --depth 0` is not a meaningful request, so 0 is folded into the
        # "full history" case rather than passed through.
        repo = SourceRepo("cgltf", "https://example.invalid/cgltf", depth=0)

        with mock.patch.object(git_repo, "run", return_value=completed()) as fake_run:
            checkout_repo(repo, str(tmp_path))

        assert "--depth" not in fake_run.call_args.args[0]

    def test_passes_the_depth_when_pulling_too(self, tmp_path, completed):
        repo = SourceRepo("cgltf", "https://example.invalid/cgltf", depth=1)
        (tmp_path / "cgltf").mkdir()

        with mock.patch.object(git_repo, "run", return_value=completed()) as fake_run:
            checkout_repo(repo, str(tmp_path))

        assert "--depth" in fake_run.call_args.args[0]

    def test_never_lets_git_stop_to_ask_for_credentials(self, tmp_path, repo, completed):
        # An unreachable or private URL would otherwise block the whole run on an
        # interactive prompt that nobody is watching.
        with mock.patch.object(git_repo, "run", return_value=completed()) as fake_run:
            checkout_repo(repo, str(tmp_path))

        assert fake_run.call_args.kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"

    def test_keeps_the_ambient_environment_so_git_can_find_its_config(self, tmp_path, repo, completed):
        with mock.patch.dict(os.environ, {"GIT_MARKER": "present"}):
            with mock.patch.object(git_repo, "run", return_value=completed()) as fake_run:
                checkout_repo(repo, str(tmp_path))

        assert fake_run.call_args.kwargs["env"]["GIT_MARKER"] == "present"

    def test_fails_loudly_when_git_exits_nonzero(self, tmp_path, repo, completed):
        with mock.patch.object(git_repo, "run", return_value=completed(returncode=128)):
            with pytest.raises(SystemExit, match="checkout failed"):
                checkout_repo(repo, str(tmp_path))

    def test_announces_success_only_after_git_succeeded(self, tmp_path, repo, completed, capsys):
        with mock.patch.object(git_repo, "run", return_value=completed()):
            checkout_repo(repo, str(tmp_path))

        assert "cgltf repository is ready." in capsys.readouterr().out
