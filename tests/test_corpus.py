"""Unit tests for corpus.py.

sync_corpus_source owns a slice of seed_corpus/ and rewrites it wholesale on every call,
so the tests below pin down both what it copies in and what it is allowed to delete.
minimize_corpus shells out to libFuzzer, with proc.run mocked as corpus.run.
"""

import os
from unittest import mock

import pytest

from fuzz_lab import corpus
from fuzz_lab.corpus import CorpusSource, minimize_corpus, source_prefix, sync_corpus_source


@pytest.fixture
def fuzzer_dir(tmp_path):
    return tmp_path


@pytest.fixture
def checkout(fuzzer_dir):
    """A repo checkout directory, where prepare_repos would have cloned one."""
    repo_dir = fuzzer_dir / "assets"
    repo_dir.mkdir()
    return repo_dir


def seed_corpus_names(fuzzer_dir):
    return sorted(os.listdir(fuzzer_dir / "seed_corpus"))


class TestSourcePrefix:
    def test_namespaces_files_by_repo(self):
        # Two repos can both ship a Box.gltf; the prefix is what keeps them apart once
        # every file is flattened into one directory.
        assert source_prefix("assets") == "assets__"


class TestSyncCorpusSource:
    def test_refuses_to_run_before_the_repo_is_checked_out(self, fuzzer_dir):
        source = CorpusSource("assets", [".gltf"])

        with pytest.raises(SystemExit, match="Run prepare_repos first"):
            sync_corpus_source(source, str(fuzzer_dir))

    def test_creates_the_seed_corpus_directory(self, fuzzer_dir, checkout):
        sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        assert (fuzzer_dir / "seed_corpus").is_dir()

    def test_copies_only_files_with_a_configured_extension(self, fuzzer_dir, checkout):
        (checkout / "model.gltf").write_text("{}")
        (checkout / "readme.md").write_text("docs")

        copied = sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        assert copied == 1
        assert seed_corpus_names(fuzzer_dir) == ["assets__model.gltf"]

    def test_matches_extensions_regardless_of_case(self, fuzzer_dir, checkout):
        # Sample assets are not consistent about this, and a missed .GLTF is a silently
        # smaller corpus rather than an error.
        (checkout / "upper.GLTF").write_text("{}")
        (checkout / "lower.gltf").write_text("{}")

        copied = sync_corpus_source(CorpusSource("assets", [".GlTf"]), str(fuzzer_dir))

        assert copied == 2

    def test_copies_several_configured_extensions(self, fuzzer_dir, checkout):
        (checkout / "model.gltf").write_text("{}")
        (checkout / "model.glb").write_bytes(b"glTF")

        copied = sync_corpus_source(CorpusSource("assets", [".gltf", ".glb"]), str(fuzzer_dir))

        assert copied == 2

    def test_flattens_nested_paths_into_the_filename(self, fuzzer_dir, checkout):
        # seed_corpus/ stays flat because libFuzzer reads a single directory, so the
        # relative path is folded into the name instead of creating subdirectories.
        nested = checkout / "Models" / "Box"
        nested.mkdir(parents=True)
        (nested / "Box.gltf").write_text("{}")

        sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        assert seed_corpus_names(fuzzer_dir) == ["assets__Models__Box__Box.gltf"]

    def test_keeps_same_named_files_from_different_directories_apart(self, fuzzer_dir, checkout):
        # The reason the whole relative path is folded in: sample repos are full of
        # identically named files, and a basename-only scheme would silently drop all
        # but one of them.
        for folder in ("Box", "Cube"):
            nested = checkout / folder
            nested.mkdir()
            (nested / "model.gltf").write_text("{}")

        copied = sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        assert copied == 2
        assert seed_corpus_names(fuzzer_dir) == ["assets__Box__model.gltf", "assets__Cube__model.gltf"]

    def test_never_walks_into_the_git_directory(self, fuzzer_dir, checkout):
        # .git holds loose objects and packs, none of which are corpus material.
        git_dir = checkout / ".git"
        git_dir.mkdir()
        (git_dir / "stray.gltf").write_text("{}")

        assert sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir)) == 0

    def test_drops_files_that_disappeared_upstream(self, fuzzer_dir, checkout):
        # The source owns every seed_corpus/ entry with its prefix and rewrites that set
        # from scratch, so a file deleted or renamed in the repo must not linger.
        (checkout / "old.gltf").write_text("{}")
        sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        (checkout / "old.gltf").unlink()
        (checkout / "new.gltf").write_text("{}")
        sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        assert seed_corpus_names(fuzzer_dir) == ["assets__new.gltf"]

    def test_leaves_files_owned_by_another_source_alone(self, fuzzer_dir, checkout):
        # Each source may only wipe its own prefix; clearing the whole directory would
        # destroy every other source's contribution on each sync.
        seed_dir = fuzzer_dir / "seed_corpus"
        seed_dir.mkdir()
        (seed_dir / "other__keepme.gltf").write_text("{}")
        (checkout / "model.gltf").write_text("{}")

        sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        assert seed_corpus_names(fuzzer_dir) == ["assets__model.gltf", "other__keepme.gltf"]

    def test_only_ever_deletes_files_carrying_its_own_prefix(self, fuzzer_dir, checkout):
        # Scoping, not preservation: a single source has no idea which other sources are
        # configured, so it may only touch its own prefix. seed_corpus/ is still a fully
        # managed directory -- dropping anything that no configured source owns (including
        # files added by hand) is Fuzzer.prepare_corpus()'s job, since only it sees the
        # whole configuration.
        seed_dir = fuzzer_dir / "seed_corpus"
        seed_dir.mkdir()
        (seed_dir / "handwritten.gltf").write_text("{}")

        sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        assert "handwritten.gltf" in seed_corpus_names(fuzzer_dir)

    def test_copies_file_contents_not_just_names(self, fuzzer_dir, checkout):
        (checkout / "model.gltf").write_text('{"asset":{"version":"2.0"}}')

        sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        copied = fuzzer_dir / "seed_corpus" / "assets__model.gltf"
        assert copied.read_text() == '{"asset":{"version":"2.0"}}'

    def test_reports_how_many_files_it_synced(self, fuzzer_dir, checkout, capsys):
        (checkout / "model.gltf").write_text("{}")

        sync_corpus_source(CorpusSource("assets", [".gltf"]), str(fuzzer_dir))

        assert "assets: 1 file(s) synced" in capsys.readouterr().out


class TestMinimizeCorpus:
    @pytest.fixture
    def seed_corpus(self, fuzzer_dir):
        corpus_dir = fuzzer_dir / "seed_corpus"
        corpus_dir.mkdir()
        (corpus_dir / "input-1").write_text("{}")
        return corpus_dir

    def test_refuses_to_run_without_a_built_binary(self, fuzzer_dir, seed_corpus):
        with pytest.raises(SystemExit, match="Run build_fuzzer first"):
            minimize_corpus(str(fuzzer_dir / "missing"), str(fuzzer_dir))

    def test_refuses_to_run_without_a_corpus(self, fuzzer_dir, fake_binary):
        with pytest.raises(SystemExit, match="Run prepare_corpus first"):
            minimize_corpus(fake_binary, str(fuzzer_dir))

    def test_merges_the_corpus_into_a_separate_directory(self, fuzzer_dir, fake_binary, seed_corpus, completed):
        # libFuzzer's -merge mode refuses to write into a directory it also reads from,
        # and seed_corpus/ gets resynced from its sources anyway.
        with mock.patch.object(corpus, "run", return_value=completed()) as fake_run:
            output_dir = minimize_corpus(fake_binary, str(fuzzer_dir))

        assert output_dir == str(fuzzer_dir / "min_corpus")
        assert fake_run.call_args.args[0] == [fake_binary, "-merge=1", output_dir, str(seed_corpus)]

    def test_leaves_the_seed_corpus_untouched(self, fuzzer_dir, fake_binary, seed_corpus, completed):
        with mock.patch.object(corpus, "run", return_value=completed()):
            minimize_corpus(fake_binary, str(fuzzer_dir))

        assert sorted(os.listdir(seed_corpus)) == ["input-1"]

    def test_starts_from_an_empty_output_directory(self, fuzzer_dir, fake_binary, seed_corpus, completed):
        # A leftover file from a previous run would be counted as kept, and libFuzzer
        # would treat it as existing coverage.
        stale_dir = fuzzer_dir / "min_corpus"
        stale_dir.mkdir()
        (stale_dir / "from-a-previous-run").write_text("{}")

        with mock.patch.object(corpus, "run", return_value=completed()):
            minimize_corpus(fake_binary, str(fuzzer_dir))

        assert os.listdir(stale_dir) == []

    def test_fails_loudly_when_libfuzzer_exits_nonzero(self, fuzzer_dir, fake_binary, seed_corpus, completed):
        with mock.patch.object(corpus, "run", return_value=completed(returncode=1)):
            with pytest.raises(SystemExit, match="minimize failed"):
                minimize_corpus(fake_binary, str(fuzzer_dir))

    def test_reports_how_many_inputs_survived(self, fuzzer_dir, fake_binary, seed_corpus, completed, capsys):
        def _merge(args, **kwargs):
            open(os.path.join(args[2], "kept-1"), "w").write("{}")
            return completed()

        with mock.patch.object(corpus, "run", side_effect=_merge):
            minimize_corpus(fake_binary, str(fuzzer_dir))

        assert "1 file(s) kept" in capsys.readouterr().out
