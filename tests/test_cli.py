"""Unit tests for cli.py.

Two things are worth pinning down here. First the argument validators, which are the only
sanitisation between a command line and paths built by joining those values onto the
fuzzer directory. Second the wiring: each subcommand has to reach the right Fuzzer method
with the right arguments, which is checked by driving main() with a mocked Fuzzer class
rather than by calling the handlers directly -- that way the parser defaults are covered
too.
"""

import sys
from unittest import mock

import pytest

import cli
from cli import file_extension, fuzzer_name
from git_repo import SourceRepo


@pytest.fixture
def fuzzer_cls():
    """Replace cli.Fuzzer so subcommands can be driven without touching the filesystem."""
    with mock.patch.object(cli, "Fuzzer") as fake:
        yield fake


@pytest.fixture
def loaded(fuzzer_cls):
    """Shorthand for the Fuzzer instance a subcommand gets back from Fuzzer.load()."""
    return fuzzer_cls.load.return_value


def run_cli(*argv):
    """Invoke main() as if the given arguments had been typed after `python3 cli.py`."""
    with mock.patch.object(sys, "argv", ["cli.py", *argv]):
        cli.main()


class TestFuzzerName:
    @pytest.mark.parametrize("name", ["cgltf", "libpng-1", "my_fuzzer", "A1"])
    def test_accepts_plain_names(self, name):
        assert fuzzer_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "..",  # would climb out of the project root
            "../etc",
            "a/b",  # path separator
            "a\\b",
            "with space",
            "",
            ".",
            "semi;colon",
            "star*",
            "$HOME",
        ],
    )
    def test_rejects_anything_that_could_escape_the_fuzzer_directory(self, name):
        # These values are joined onto paths (fuzzer_dir_for, and checkout paths in
        # git_repo), so restricting the character set is the whole defence.
        with pytest.raises(Exception):
            fuzzer_name(name)


class TestFileExtension:
    def test_accepts_an_extension_with_its_dot(self):
        assert file_extension(".gltf") == ".gltf"

    def test_adds_the_missing_dot(self):
        # Stored form always has one, since it is compared against os.path.splitext()
        # output which includes the dot.
        assert file_extension("gltf") == ".gltf"

    @pytest.mark.parametrize("value", ["", ".", "a/b", "a.b", "with space", "..gltf"])
    def test_rejects_anything_that_is_not_a_bare_extension(self, value):
        with pytest.raises(Exception):
            file_extension(value)


class TestParserItself:
    def test_requires_a_subcommand(self):
        # Without required=True, a bare `cli.py` would silently do nothing.
        with pytest.raises(SystemExit) as exit_info:
            run_cli()

        assert exit_info.value.code == 2

    def test_rejects_an_unsafe_fuzzer_name_before_doing_any_work(self, fuzzer_cls):
        with pytest.raises(SystemExit) as exit_info:
            run_cli("prepare_repos", "../escape")

        assert exit_info.value.code == 2
        fuzzer_cls.load.assert_not_called()


class TestConfigSubcommands:
    def test_create_fuzzer_scaffolds_by_name(self, fuzzer_cls):
        run_cli("create_fuzzer", "cgltf")

        fuzzer_cls.create.assert_called_once_with("cgltf")

    def test_add_repo_records_url_and_depth(self, fuzzer_cls, loaded):
        run_cli("add_repo", "cgltf", "cgltf", "https://example.invalid/cgltf", "--depth", "1")

        fuzzer_cls.load.assert_called_once_with("cgltf")
        loaded.add_repo.assert_called_once_with(SourceRepo("cgltf", "https://example.invalid/cgltf", depth=1))

    def test_add_repo_keeps_the_full_history_by_default(self, loaded):
        run_cli("add_repo", "cgltf", "cgltf", "https://example.invalid/cgltf")

        assert loaded.add_repo.call_args.args[0].depth is None

    def test_add_repo_validates_the_checkout_directory_name(self, fuzzer_cls):
        # repo_name becomes a directory under the fuzzer dir, so it is exactly as
        # sensitive as the fuzzer name.
        with pytest.raises(SystemExit) as exit_info:
            run_cli("add_repo", "cgltf", "../escape", "https://example.invalid/cgltf")

        assert exit_info.value.code == 2
        fuzzer_cls.load.assert_not_called()

    def test_remove_repo_edits_the_config(self, loaded):
        run_cli("remove_repo", "cgltf", "assets")

        loaded.remove_repo.assert_called_once_with("assets")

    def test_add_corpus_source_normalises_every_extension(self, loaded):
        run_cli("add_corpus_source", "cgltf", "assets", "gltf", ".glb")

        loaded.add_corpus_source.assert_called_once_with("assets", [".gltf", ".glb"])

    def test_edit_corpus_source_replaces_the_extension_list(self, loaded):
        run_cli("edit_corpus_source", "cgltf", "assets", "bin")

        loaded.edit_corpus_source.assert_called_once_with("assets", [".bin"])

    def test_remove_corpus_source_edits_the_config(self, loaded):
        run_cli("remove_corpus_source", "cgltf", "assets")

        loaded.remove_corpus_source.assert_called_once_with("assets")


class TestFilesystemSubcommands:
    def test_prepare_repos(self, loaded):
        run_cli("prepare_repos", "cgltf")
        loaded.prepare_repos.assert_called_once_with()

    def test_prepare_corpus(self, loaded):
        run_cli("prepare_corpus", "cgltf")
        loaded.prepare_corpus.assert_called_once_with()

    def test_minimize_corpus(self, loaded):
        run_cli("minimize_corpus", "cgltf")
        loaded.minimize_corpus.assert_called_once_with()

    def test_build_fuzzer(self, loaded):
        run_cli("build_fuzzer", "cgltf")
        loaded.build_fuzz_target.assert_called_once_with()

    def test_build_coverage(self, loaded):
        run_cli("build_coverage", "cgltf")
        loaded.build_coverage_target.assert_called_once_with()

    def test_coverage_report_defaults_to_the_seed_corpus(self, loaded):
        run_cli("coverage_report", "cgltf")
        loaded.generate_coverage_report.assert_called_once_with(None)

    def test_coverage_report_honours_an_explicit_corpus(self, loaded):
        run_cli("coverage_report", "cgltf", "--corpus", "cgltf_fuzz/min_corpus")
        loaded.generate_coverage_report.assert_called_once_with("cgltf_fuzz/min_corpus")


class TestRunFuzzer:
    def test_runs_until_interrupted_by_default(self, loaded):
        # No -max_total_time means the session keeps going until Ctrl+C, which is the
        # normal way to fuzz.
        run_cli("run_fuzzer", "cgltf")

        loaded.run_fuzz_target.assert_called_once_with(None, [])

    def test_bounds_the_session_when_a_time_is_given(self, loaded):
        run_cli("run_fuzzer", "cgltf", "--time", "60")

        loaded.run_fuzz_target.assert_called_once_with(None, ["-max_total_time=60"])

    def test_enables_value_profile_on_request(self, loaded):
        run_cli("run_fuzzer", "cgltf", "--value-profile")

        loaded.run_fuzz_target.assert_called_once_with(None, ["-use_value_profile=1"])

    def test_combines_both_flags(self, loaded):
        run_cli("run_fuzzer", "cgltf", "--time", "30", "--value-profile")

        loaded.run_fuzz_target.assert_called_once_with(
            None, ["-max_total_time=30", "-use_value_profile=1"]
        )

    def test_continues_past_crashes_on_request(self, loaded):
        # In-process libFuzzer always aborts the whole run on a crash (the process may be
        # corrupted); the only way to keep going is fork mode (-fork=1), which restarts a
        # fresh subprocess after each crash instead of exiting -- -ignore_crashes=1 tells
        # it to do that instead of stopping fork mode itself at the first crash.
        run_cli("run_fuzzer", "cgltf", "--continue-on-crash")

        loaded.run_fuzz_target.assert_called_once_with(None, ["-fork=1", "-ignore_crashes=1"])

    def test_combines_all_three_flags(self, loaded):
        run_cli("run_fuzzer", "cgltf", "--time", "30", "--value-profile", "--continue-on-crash")

        loaded.run_fuzz_target.assert_called_once_with(
            None,
            ["-max_total_time=30", "-use_value_profile=1", "-fork=1", "-ignore_crashes=1"],
        )

    def test_honours_an_explicit_corpus(self, loaded):
        run_cli("run_fuzzer", "cgltf", "--corpus", "cgltf_fuzz/min_corpus")

        assert loaded.run_fuzz_target.call_args.args[0] == "cgltf_fuzz/min_corpus"


class TestCrashSubcommands:
    CRASH = "cgltf_fuzz/crashes/crash-abc123"

    def test_repro_crash_saves_the_log_beside_the_crash_by_default(self, loaded):
        run_cli("repro_crash", "cgltf", self.CRASH)

        loaded.reproduce_crash.assert_called_once_with(self.CRASH, None)

    def test_repro_crash_honours_an_explicit_log_path(self, loaded):
        run_cli("repro_crash", "cgltf", self.CRASH, "--output", "report.txt")

        loaded.reproduce_crash.assert_called_once_with(self.CRASH, "report.txt")

    def test_minimize_crash_stops_after_ten_seconds_by_default(self, loaded):
        # Minimization has no natural stopping point, so the wrapper always supplies a
        # bound rather than leaving it to run forever.
        run_cli("minimize_crash", "cgltf", self.CRASH)

        loaded.minimize_crash.assert_called_once_with(self.CRASH, None, ["-max_total_time=10"])

    def test_minimize_crash_honours_an_explicit_budget_and_output(self, loaded):
        run_cli("minimize_crash", "cgltf", self.CRASH, "--time", "120", "--output", "small")

        loaded.minimize_crash.assert_called_once_with(self.CRASH, "small", ["-max_total_time=120"])

    def test_triage_crash_stops_after_ten_seconds_by_default(self, loaded):
        run_cli("triage_crash", "cgltf", self.CRASH)

        loaded.triage_crash.assert_called_once_with(self.CRASH, None, ["-max_total_time=10"])

    def test_triage_crash_honours_an_explicit_budget_and_output(self, loaded):
        run_cli("triage_crash", "cgltf", self.CRASH, "--time", "45", "--output", "small")

        loaded.triage_crash.assert_called_once_with(self.CRASH, "small", ["-max_total_time=45"])

    def test_dedupe_crashes_takes_the_reference_crash(self, loaded):
        run_cli("dedupe_crashes", "cgltf", self.CRASH)

        loaded.dedupe_crashes.assert_called_once_with(self.CRASH)


class TestExtractGlbJsonSubcommand:
    # No fuzzer name: extracting a JSON chunk from a .glb is pure byte slicing, with no
    # need for a built binary or fuzzer.json -- unlike every other crash subcommand above.
    GLB = "cgltf_fuzz/crashes/crash-abc123.min"

    @pytest.fixture
    def glb_module(self):
        with mock.patch.object(cli, "glb") as fake:
            yield fake

    def test_writes_the_json_chunk_beside_the_glb_by_default(self, glb_module):
        run_cli("extract_glb_json", self.GLB)

        glb_module.extract_glb_json.assert_called_once_with(self.GLB, None)

    def test_honours_an_explicit_output_path(self, glb_module):
        run_cli("extract_glb_json", self.GLB, "--output", "chunk.json")

        glb_module.extract_glb_json.assert_called_once_with(self.GLB, "chunk.json")
