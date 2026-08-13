"""Unit tests for fuzzer.py.

Fuzzer is the object every CLI subcommand goes through. Roughly half of its methods are
thin delegations to build.py / corpus.py / run_fuzzer.py -- those are checked for passing
the right paths, with the callee mocked out. The other half (config edits, and the two
reconcile-with-disk methods) hold the real logic and get exercised for real against
tmp_path.
"""

import os
from unittest import mock

import pytest

from fuzz_lab import fuzzer as fuzzer_module
from fuzz_lab.corpus import CorpusSource
from fuzz_lab.fuzzer import Fuzzer, fuzzer_dir_for
from fuzz_lab.fuzzer_config import FuzzerConfig
from fuzz_lab.git_repo import SourceRepo

REPO = SourceRepo("cgltf", "https://example.invalid/cgltf")
ASSETS = SourceRepo("assets", "https://example.invalid/assets")


@pytest.fixture
def loaded(tmp_path):
    """A created-on-disk fuzzer, loaded and ready to edit."""
    return Fuzzer.create("cgltf", root=str(tmp_path))


def make_checkout(fuzzer, name):
    """Create a directory that looks like a git checkout prepare_repos made."""
    checkout = os.path.join(fuzzer.fuzzer_dir, name)
    os.makedirs(os.path.join(checkout, ".git"))
    return checkout


class TestFuzzerDirFor:
    def test_derives_the_directory_from_the_name(self):
        # The CLI only ever passes bare names around; this mapping is the single place
        # that turns one into a path.
        assert fuzzer_dir_for("cgltf", "/projects") == os.path.join("/projects", "cgltf_fuzz")


class TestCreate:
    def test_scaffolds_config_harness_and_dictionary(self, tmp_path):
        fuzzer = Fuzzer.create("cgltf", root=str(tmp_path))

        assert os.path.isfile(fuzzer.config_path)
        assert os.path.isfile(fuzzer.harness_path)
        assert os.path.isfile(fuzzer.dictionary_path)

    def test_writes_a_harness_that_compiles_as_is(self, tmp_path):
        # The placeholder has to be a valid fuzz target so `build_fuzzer` succeeds
        # immediately after `create_fuzzer`, before anyone edits it.
        fuzzer = Fuzzer.create("cgltf", root=str(tmp_path))

        harness = open(fuzzer.harness_path).read()
        assert "LLVMFuzzerTestOneInput" in harness

    def test_starts_the_dictionary_empty(self, tmp_path):
        # run_fuzz_target omits -dict for an empty file, so an empty dictionary means
        # "no dictionary" rather than an error.
        fuzzer = Fuzzer.create("cgltf", root=str(tmp_path))

        assert os.path.getsize(fuzzer.dictionary_path) == 0

    def test_refuses_to_clobber_an_existing_fuzzer(self, tmp_path):
        Fuzzer.create("cgltf", root=str(tmp_path))

        with pytest.raises(SystemExit, match="already exists"):
            Fuzzer.create("cgltf", root=str(tmp_path))

    def test_produces_a_fuzzer_that_load_can_read_back(self, tmp_path):
        Fuzzer.create("cgltf", root=str(tmp_path))

        assert Fuzzer.load("cgltf", root=str(tmp_path)).config.name == "cgltf"


class TestPaths:
    def test_locates_the_files_that_live_in_a_fuzzer_directory(self, loaded):
        assert loaded.harness_path == os.path.join(loaded.fuzzer_dir, "harness.c")
        assert loaded.config_path == os.path.join(loaded.fuzzer_dir, "fuzzer.json")
        assert loaded.dictionary_path == os.path.join(loaded.fuzzer_dir, "dictionary.dict")


class TestRepoConfig:
    def test_adding_a_repo_persists_it(self, loaded, tmp_path):
        loaded.add_repo(REPO)

        assert Fuzzer.load("cgltf", root=str(tmp_path)).config.source_repos == [REPO]

    def test_refuses_to_add_the_same_repo_name_twice(self, loaded):
        loaded.add_repo(REPO)

        with pytest.raises(SystemExit, match="already a source repo"):
            loaded.add_repo(SourceRepo("cgltf", "https://example.invalid/other"))

    def test_removing_a_repo_persists_the_removal(self, loaded, tmp_path):
        loaded.add_repo(REPO)
        loaded.add_repo(ASSETS)
        loaded.remove_repo("cgltf")

        assert Fuzzer.load("cgltf", root=str(tmp_path)).config.source_repos == [ASSETS]

    def test_refuses_to_remove_a_repo_that_is_not_configured(self, loaded):
        with pytest.raises(SystemExit, match="is not a source repo"):
            loaded.remove_repo("nope")

    def test_removing_a_repo_leaves_its_checkout_on_disk(self, loaded):
        # Config edits and filesystem work are deliberately separate subcommands; the
        # checkout is only dropped on the next prepare_repos.
        loaded.add_repo(REPO)
        checkout = make_checkout(loaded, "cgltf")

        loaded.remove_repo("cgltf")

        assert os.path.isdir(checkout)


class TestPrepareRepos:
    def test_checks_out_every_configured_repo(self, loaded):
        loaded.add_repo(REPO)
        loaded.add_repo(ASSETS)

        with mock.patch.object(fuzzer_module, "checkout_repo") as fake_checkout:
            loaded.prepare_repos()

        checked_out = [call.args[0] for call in fake_checkout.call_args_list]
        assert checked_out == [REPO, ASSETS]

    def test_deletes_a_checkout_that_is_no_longer_configured(self, loaded):
        stale = make_checkout(loaded, "removed-repo")

        with mock.patch.object(fuzzer_module, "checkout_repo"):
            loaded.prepare_repos()

        assert not os.path.exists(stale)

    def test_keeps_the_checkout_of_a_configured_repo(self, loaded):
        loaded.add_repo(REPO)
        checkout = make_checkout(loaded, "cgltf")

        with mock.patch.object(fuzzer_module, "checkout_repo"):
            loaded.prepare_repos()

        assert os.path.isdir(checkout)

    def test_never_deletes_a_directory_that_is_not_a_git_checkout(self, loaded):
        # The .git guard is what stops this from wiping seed_corpus/, build/, crashes/
        # or anything a human dropped in the fuzzer directory by hand.
        handmade = os.path.join(loaded.fuzzer_dir, "my-notes")
        os.makedirs(handmade)

        with mock.patch.object(fuzzer_module, "checkout_repo"):
            loaded.prepare_repos()

        assert os.path.isdir(handmade)

    def test_never_deletes_the_files_that_make_up_the_fuzzer(self, loaded):
        with mock.patch.object(fuzzer_module, "checkout_repo"):
            loaded.prepare_repos()

        assert os.path.isfile(loaded.config_path)
        assert os.path.isfile(loaded.harness_path)


class TestCorpusSourceConfig:
    def test_adding_a_corpus_source_persists_it(self, loaded, tmp_path):
        loaded.add_repo(ASSETS)
        loaded.add_corpus_source("assets", [".gltf"])

        reloaded = Fuzzer.load("cgltf", root=str(tmp_path))
        assert reloaded.config.corpus_sources == [CorpusSource("assets", [".gltf"])]

    def test_refuses_a_corpus_source_with_no_matching_repo(self, loaded):
        # prepare_corpus reads from that repo's checkout, so there would be nothing to
        # sync from.
        with pytest.raises(SystemExit, match="Add it with add_repo first"):
            loaded.add_corpus_source("assets", [".gltf"])

    def test_refuses_to_add_the_same_corpus_source_twice(self, loaded):
        loaded.add_repo(ASSETS)
        loaded.add_corpus_source("assets", [".gltf"])

        with pytest.raises(SystemExit, match="already a corpus source"):
            loaded.add_corpus_source("assets", [".glb"])

    def test_editing_replaces_the_extension_list(self, loaded, tmp_path):
        loaded.add_repo(ASSETS)
        loaded.add_corpus_source("assets", [".gltf"])
        loaded.edit_corpus_source("assets", [".glb", ".bin"])

        reloaded = Fuzzer.load("cgltf", root=str(tmp_path))
        assert reloaded.config.corpus_sources == [CorpusSource("assets", [".glb", ".bin"])]

    def test_refuses_to_edit_a_corpus_source_that_does_not_exist(self, loaded):
        with pytest.raises(SystemExit, match="is not a corpus source"):
            loaded.edit_corpus_source("assets", [".gltf"])

    def test_removing_a_corpus_source_persists_the_removal(self, loaded, tmp_path):
        loaded.add_repo(ASSETS)
        loaded.add_corpus_source("assets", [".gltf"])
        loaded.remove_corpus_source("assets")

        assert Fuzzer.load("cgltf", root=str(tmp_path)).config.corpus_sources == []

    def test_refuses_to_remove_a_corpus_source_that_does_not_exist(self, loaded):
        with pytest.raises(SystemExit, match="is not a corpus source"):
            loaded.remove_corpus_source("assets")


class TestPrepareCorpus:
    @pytest.fixture
    def seeded(self, loaded):
        """A fuzzer with one configured corpus source and a seed_corpus/ to reconcile."""
        loaded.add_repo(ASSETS)
        loaded.add_corpus_source("assets", [".gltf"])
        os.makedirs(os.path.join(loaded.fuzzer_dir, "seed_corpus"), exist_ok=True)
        return loaded

    @staticmethod
    def seed_file(fuzzer, name):
        path = os.path.join(fuzzer.fuzzer_dir, "seed_corpus", name)
        open(path, "w").write("{}")
        return path

    def test_syncs_every_configured_source(self, seeded):
        with mock.patch.object(fuzzer_module, "sync_corpus_source") as fake_sync:
            seeded.prepare_corpus()

        fake_sync.assert_called_once_with(CorpusSource("assets", [".gltf"]), seeded.fuzzer_dir)

    def test_creates_the_seed_corpus_directory_if_missing(self, loaded):
        with mock.patch.object(fuzzer_module, "sync_corpus_source"):
            loaded.prepare_corpus()

        assert os.path.isdir(os.path.join(loaded.fuzzer_dir, "seed_corpus"))

    def test_keeps_files_belonging_to_a_configured_source(self, seeded):
        kept = self.seed_file(seeded, "assets__Box.gltf")

        with mock.patch.object(fuzzer_module, "sync_corpus_source"):
            seeded.prepare_corpus()

        assert os.path.exists(kept)

    def test_drops_files_belonging_to_a_source_that_was_removed(self, seeded):
        # seed_corpus/ is flat, so a departed source is recognised by its name prefix
        # rather than by a subdirectory.
        stale = self.seed_file(seeded, "oldrepo__Box.gltf")

        with mock.patch.object(fuzzer_module, "sync_corpus_source"):
            seeded.prepare_corpus()

        assert not os.path.exists(stale)

    def test_drops_directories_left_in_the_seed_corpus(self, seeded):
        # sync_corpus_source only ever writes flat files, so any directory here predates
        # the flattening or was made by hand.
        stale_dir = os.path.join(seeded.fuzzer_dir, "seed_corpus", "Models")
        os.makedirs(stale_dir)

        with mock.patch.object(fuzzer_module, "sync_corpus_source"):
            seeded.prepare_corpus()

        assert not os.path.exists(stale_dir)

    def test_drops_files_that_carry_no_source_prefix(self, seeded):
        # seed_corpus/ is fully managed: its contents are defined entirely by the
        # configured sources, so a file dropped in by hand is removed here. This is the
        # step that enforces that policy -- sync_corpus_source only scopes itself to its
        # own prefix, having no view of the other sources.
        handmade = self.seed_file(seeded, "handwritten.gltf")

        with mock.patch.object(fuzzer_module, "sync_corpus_source"):
            seeded.prepare_corpus()

        assert not os.path.exists(handmade)


class TestRunFuzzTarget:
    def test_defaults_to_the_seed_corpus(self, loaded):
        with mock.patch.object(fuzzer_module, "run_fuzz_target") as fake_run:
            loaded.run_fuzz_target()

        assert fake_run.call_args.args[1] == os.path.join(loaded.fuzzer_dir, "seed_corpus")

    def test_honours_an_explicit_corpus_directory(self, loaded, tmp_path):
        chosen = str(tmp_path / "min_corpus")

        with mock.patch.object(fuzzer_module, "run_fuzz_target") as fake_run:
            loaded.run_fuzz_target(chosen)

        assert fake_run.call_args.args[1] == chosen

    def test_runs_the_binary_that_build_fuzz_target_produces(self, loaded):
        with mock.patch.object(fuzzer_module, "run_fuzz_target") as fake_run:
            loaded.run_fuzz_target()

        assert fake_run.call_args.args[0] == os.path.join(loaded.fuzzer_dir, "build", "cgltf_fuzzer")

    def test_omits_the_dictionary_flag_when_the_dictionary_is_empty(self, loaded):
        # libFuzzer errors out on an empty -dict file rather than treating it as zero
        # entries, so an untouched dictionary has to mean "no -dict at all".
        with mock.patch.object(fuzzer_module, "run_fuzz_target") as fake_run:
            loaded.run_fuzz_target()

        assert fake_run.call_args.args[3] == []

    def test_passes_the_dictionary_once_it_has_entries(self, loaded):
        open(loaded.dictionary_path, "w").write('kw1="glTF"\n')

        with mock.patch.object(fuzzer_module, "run_fuzz_target") as fake_run:
            loaded.run_fuzz_target()

        assert fake_run.call_args.args[3] == [f"-dict={loaded.dictionary_path}"]

    def test_creates_a_missing_dictionary_rather_than_failing(self, loaded):
        # A fuzzer scaffolded before dictionary_path existed should still run.
        os.remove(loaded.dictionary_path)

        with mock.patch.object(fuzzer_module, "run_fuzz_target"):
            loaded.run_fuzz_target()

        assert os.path.isfile(loaded.dictionary_path)

    def test_puts_the_dictionary_flag_ahead_of_caller_supplied_flags(self, loaded):
        open(loaded.dictionary_path, "w").write('kw1="glTF"\n')

        with mock.patch.object(fuzzer_module, "run_fuzz_target") as fake_run:
            loaded.run_fuzz_target(extra_args=["-max_total_time=60"])

        assert fake_run.call_args.args[3] == [
            f"-dict={loaded.dictionary_path}",
            "-max_total_time=60",
        ]


class TestDelegation:
    """The methods that only bind a fuzzer's name and directory to a module-level call."""

    def test_build_fuzz_target_passes_the_configured_repos(self, loaded):
        loaded.add_repo(REPO)

        with mock.patch.object(fuzzer_module, "build_fuzz_target") as fake_build:
            loaded.build_fuzz_target()

        fake_build.assert_called_once_with("cgltf", loaded.fuzzer_dir, [REPO])

    def test_build_coverage_target_passes_the_configured_repos(self, loaded):
        loaded.add_repo(REPO)

        with mock.patch.object(fuzzer_module, "build_coverage_target") as fake_build:
            loaded.build_coverage_target()

        fake_build.assert_called_once_with("cgltf", loaded.fuzzer_dir, [REPO])

    def test_minimize_corpus_targets_the_fuzz_binary(self, loaded):
        with mock.patch.object(fuzzer_module, "minimize_corpus") as fake_minimize:
            loaded.minimize_corpus()

        fake_minimize.assert_called_once_with(
            os.path.join(loaded.fuzzer_dir, "build", "cgltf_fuzzer"), loaded.fuzzer_dir
        )

    def test_coverage_report_targets_the_coverage_binary_and_seed_corpus(self, loaded):
        # A different binary from the fuzz target: the instrumented one.
        with mock.patch.object(fuzzer_module, "generate_coverage_report") as fake_report:
            loaded.generate_coverage_report()

        fake_report.assert_called_once_with(
            os.path.join(loaded.fuzzer_dir, "build", "cgltf_fuzzer_coverage"),
            os.path.join(loaded.fuzzer_dir, "seed_corpus"),
            loaded.fuzzer_dir,
        )

    def test_coverage_report_honours_an_explicit_corpus(self, loaded, tmp_path):
        chosen = str(tmp_path / "min_corpus")

        with mock.patch.object(fuzzer_module, "generate_coverage_report") as fake_report:
            loaded.generate_coverage_report(chosen)

        assert fake_report.call_args.args[1] == chosen

    def test_reproduce_crash_passes_the_output_path_through(self, loaded):
        with mock.patch.object(fuzzer_module, "reproduce_crash") as fake_reproduce:
            loaded.reproduce_crash("crashes/crash-abc", "somewhere.log")

        fake_reproduce.assert_called_once_with(
            os.path.join(loaded.fuzzer_dir, "build", "cgltf_fuzzer"), "crashes/crash-abc", "somewhere.log"
        )

    def test_minimize_crash_passes_the_extra_args_through(self, loaded):
        with mock.patch.object(fuzzer_module, "minimize_crash") as fake_minimize:
            loaded.minimize_crash("crashes/crash-abc", None, ["-max_total_time=10"])

        fake_minimize.assert_called_once_with(
            os.path.join(loaded.fuzzer_dir, "build", "cgltf_fuzzer"),
            "crashes/crash-abc",
            None,
            ["-max_total_time=10"],
        )

    def test_triage_crash_passes_the_extra_args_through(self, loaded):
        with mock.patch.object(fuzzer_module, "triage_crash") as fake_triage:
            loaded.triage_crash("crashes/crash-abc", None, ["-max_total_time=10"])

        fake_triage.assert_called_once_with(
            os.path.join(loaded.fuzzer_dir, "build", "cgltf_fuzzer"),
            "crashes/crash-abc",
            None,
            ["-max_total_time=10"],
        )

    def test_dedupe_crashes_scans_the_fuzzer_directory(self, loaded):
        with mock.patch.object(fuzzer_module, "dedupe_crashes") as fake_dedupe:
            loaded.dedupe_crashes("crashes/crash-abc")

        fake_dedupe.assert_called_once_with(
            os.path.join(loaded.fuzzer_dir, "build", "cgltf_fuzzer"), "crashes/crash-abc", loaded.fuzzer_dir
        )


class TestLoad:
    def test_refuses_a_directory_that_is_not_a_fuzzer(self, tmp_path):
        with pytest.raises(SystemExit, match="is not a fuzzer directory"):
            Fuzzer.load("nope", root=str(tmp_path))
