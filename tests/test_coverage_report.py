"""Unit tests for coverage_report.py.

generate_coverage_report chains three external commands (the instrumented binary, then
llvm-profdata, then llvm-cov) and must stop at the first one that fails rather than
feeding a missing file to the next. proc.run is mocked as coverage_report.run.
"""

import os
from unittest import mock

import pytest

import coverage_report
from coverage_report import generate_coverage_report


@pytest.fixture
def fuzzer_dir(tmp_path):
    return str(tmp_path)


@pytest.fixture
def corpus_dir(tmp_path):
    corpus = tmp_path / "seed_corpus"
    corpus.mkdir()
    (corpus / "input-1").write_text("{}")
    return str(corpus)


class TestPreconditions:
    def test_refuses_to_run_without_a_coverage_binary(self, fuzzer_dir, corpus_dir):
        with pytest.raises(SystemExit, match="Run build_coverage first"):
            generate_coverage_report(os.path.join(fuzzer_dir, "missing"), corpus_dir, fuzzer_dir)

    def test_refuses_to_run_without_a_corpus(self, fuzzer_dir, fake_binary):
        with pytest.raises(SystemExit, match="not found"):
            generate_coverage_report(fake_binary, os.path.join(fuzzer_dir, "missing"), fuzzer_dir)


class TestPipeline:
    def test_runs_the_three_steps_in_order(self, fuzzer_dir, corpus_dir, fake_binary, completed):
        with mock.patch.object(coverage_report, "run", return_value=completed()) as fake_run:
            generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        executables = [call.args[0][0] for call in fake_run.call_args_list]
        assert executables == [fake_binary, "llvm-profdata", "llvm-cov"]

    def test_replays_the_corpus_once_instead_of_fuzzing(self, fuzzer_dir, corpus_dir, fake_binary, completed):
        # -runs=0 is what makes the instrumented binary walk the corpus and exit; without
        # it the "report" step would never terminate.
        with mock.patch.object(coverage_report, "run", return_value=completed()) as fake_run:
            generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        assert fake_run.call_args_list[0].args[0] == [fake_binary, "-runs=0", corpus_dir]

    def test_tells_the_instrumented_binary_where_to_write_its_counters(
        self, fuzzer_dir, corpus_dir, fake_binary, completed
    ):
        # Without LLVM_PROFILE_FILE the profile lands in the working directory as
        # default.profraw, and llvm-profdata would then merge a stale or missing file.
        with mock.patch.object(coverage_report, "run", return_value=completed()) as fake_run:
            generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        env = fake_run.call_args_list[0].kwargs["env"]
        assert env["LLVM_PROFILE_FILE"] == os.path.join(fuzzer_dir, "coverage", "coverage.profraw")

    def test_indexes_the_raw_profile_before_rendering(self, fuzzer_dir, corpus_dir, fake_binary, completed):
        # llvm-cov cannot read a .profraw directly, even for a single run.
        with mock.patch.object(coverage_report, "run", return_value=completed()) as fake_run:
            generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        args = fake_run.call_args_list[1].args[0]
        coverage_dir = os.path.join(fuzzer_dir, "coverage")
        assert args == [
            "llvm-profdata",
            "merge",
            "-sparse",
            os.path.join(coverage_dir, "coverage.profraw"),
            "-o",
            os.path.join(coverage_dir, "coverage.profdata"),
        ]

    def test_renders_html_into_the_report_directory(self, fuzzer_dir, corpus_dir, fake_binary, completed):
        with mock.patch.object(coverage_report, "run", return_value=completed()) as fake_run:
            report_dir = generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        args = fake_run.call_args_list[2].args[0]
        assert report_dir == os.path.join(fuzzer_dir, "coverage", "report")
        assert "-format=html" in args
        assert f"-output-dir={report_dir}" in args
        assert f"-instr-profile={os.path.join(fuzzer_dir, 'coverage', 'coverage.profdata')}" in args

    def test_clears_a_previous_report_before_writing_a_new_one(
        self, fuzzer_dir, corpus_dir, fake_binary, completed
    ):
        # llvm-cov writes one HTML file per source file; leftovers from a previous run
        # would show sources that are no longer part of the build.
        report_dir = os.path.join(fuzzer_dir, "coverage", "report")
        os.makedirs(report_dir)
        stale = os.path.join(report_dir, "stale.html")
        open(stale, "w").write("old")

        with mock.patch.object(coverage_report, "run", return_value=completed()):
            generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        assert not os.path.exists(stale)

    def test_points_at_the_report_index_when_done(self, fuzzer_dir, corpus_dir, fake_binary, completed, capsys):
        with mock.patch.object(coverage_report, "run", return_value=completed()):
            generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        expected = os.path.join(fuzzer_dir, "coverage", "report", "index.html")
        assert f"Coverage report generated at {expected}." in capsys.readouterr().out


class TestFailureStops:
    def _failing_at(self, step_index, completed):
        """proc.run stand-in returning a nonzero code for one step and success elsewhere."""
        results = [completed(), completed(), completed()]
        results[step_index] = completed(returncode=1)
        return results

    def test_stops_when_the_coverage_run_fails(self, fuzzer_dir, corpus_dir, fake_binary, completed):
        with mock.patch.object(coverage_report, "run", side_effect=self._failing_at(0, completed)) as fake_run:
            with pytest.raises(SystemExit, match="coverage run failed"):
                generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        # Merging a profile the run never produced would fail with a confusing error.
        assert fake_run.call_count == 1

    def test_stops_when_the_profile_merge_fails(self, fuzzer_dir, corpus_dir, fake_binary, completed):
        with mock.patch.object(coverage_report, "run", side_effect=self._failing_at(1, completed)) as fake_run:
            with pytest.raises(SystemExit, match="merge failed"):
                generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)

        assert fake_run.call_count == 2

    def test_reports_when_rendering_fails(self, fuzzer_dir, corpus_dir, fake_binary, completed):
        with mock.patch.object(coverage_report, "run", side_effect=self._failing_at(2, completed)):
            with pytest.raises(SystemExit, match="report generation failed"):
                generate_coverage_report(fake_binary, corpus_dir, fuzzer_dir)
