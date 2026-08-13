"""Unit tests for run_fuzzer.py's entry points.

Each of these builds a libFuzzer command line and reacts to its exit code. proc.run is
mocked throughout (patched as run_fuzzer.run, the name the module imported it under), so
no fuzz target is ever executed -- the assertions are about the arguments handed to
libFuzzer and the files written afterwards.
"""

import os
from unittest import mock

import pytest

from fuzz_lab import run_fuzzer
from asan_reports import DEFAULT_SUMMARY, PRIMITIVE_INDICES_FRAMES, SPARSE_INDICES_FRAMES, make_asan_log


@pytest.fixture
def crash_file(tmp_path):
    """A saved crashing input, as libFuzzer would have written under crashes/."""
    crash = tmp_path / "crash-abc123"
    crash.write_bytes(b'{"buffers":[{"uri":"data:;base64,"}]}')
    return str(crash)


class TestRunFuzzTarget:
    def test_refuses_to_run_without_a_built_binary(self, tmp_path):
        with pytest.raises(SystemExit, match="Run build_fuzzer first"):
            run_fuzzer.run_fuzz_target(str(tmp_path / "missing"), str(tmp_path / "corpus"), str(tmp_path))

    def test_creates_the_corpus_and_crashes_directories(self, tmp_path, fake_binary, completed):
        corpus_dir = tmp_path / "seed_corpus"
        with mock.patch.object(run_fuzzer, "run", return_value=completed()):
            run_fuzzer.run_fuzz_target(fake_binary, str(corpus_dir), str(tmp_path))

        assert corpus_dir.is_dir()
        assert (tmp_path / "crashes").is_dir()

    def test_points_libfuzzer_at_the_crashes_directory_for_artifacts(self, tmp_path, fake_binary, completed):
        # Without -artifact_prefix libFuzzer drops crash files in the current working
        # directory; the trailing separator is what makes it a directory rather than a
        # filename prefix.
        with mock.patch.object(run_fuzzer, "run", return_value=completed()) as fake_run:
            run_fuzzer.run_fuzz_target(fake_binary, str(tmp_path / "corpus"), str(tmp_path))

        expected = f"-artifact_prefix={os.path.join(str(tmp_path), 'crashes')}{os.sep}"
        assert expected in fake_run.call_args.args[0]

    def test_passes_extra_args_through_before_the_corpus_directory(self, tmp_path, fake_binary, completed):
        # The corpus directory has to stay the last positional argument, or libFuzzer
        # reads a flag as the corpus path.
        corpus_dir = str(tmp_path / "corpus")
        with mock.patch.object(run_fuzzer, "run", return_value=completed()) as fake_run:
            run_fuzzer.run_fuzz_target(fake_binary, corpus_dir, str(tmp_path), ["-max_total_time=60"])

        args = fake_run.call_args.args[0]
        assert args[-1] == corpus_dir
        assert "-max_total_time=60" in args

    def test_propagates_a_nonzero_exit_code(self, tmp_path, fake_binary, completed):
        # A crash makes libFuzzer exit nonzero; that is a finding, and the exit code has
        # to reach the shell rather than be swallowed.
        with mock.patch.object(run_fuzzer, "run", return_value=completed(returncode=77)):
            with pytest.raises(SystemExit) as exit_info:
                run_fuzzer.run_fuzz_target(fake_binary, str(tmp_path / "corpus"), str(tmp_path))

        assert exit_info.value.code == 77


class TestReproduceCrash:
    def test_refuses_to_run_without_a_built_binary(self, tmp_path, crash_file):
        with pytest.raises(SystemExit, match="Run build_fuzzer first"):
            run_fuzzer.reproduce_crash(str(tmp_path / "missing"), crash_file)

    def test_refuses_to_run_on_a_missing_crash_file(self, tmp_path, fake_binary):
        with pytest.raises(SystemExit, match="not found"):
            run_fuzzer.reproduce_crash(fake_binary, str(tmp_path / "no-such-crash"))

    def test_saves_the_report_next_to_the_crash_by_default(self, fake_binary, crash_file, completed):
        report = make_asan_log()
        with mock.patch.object(run_fuzzer, "run", return_value=completed(returncode=1, stdout=report)):
            run_fuzzer.reproduce_crash(fake_binary, crash_file)

        assert open(f"{crash_file}.log").read() == report

    def test_honours_an_explicit_output_path(self, tmp_path, fake_binary, crash_file, completed):
        elsewhere = str(tmp_path / "somewhere-else.txt")
        with mock.patch.object(run_fuzzer, "run", return_value=completed(returncode=1, stdout="report")):
            run_fuzzer.reproduce_crash(fake_binary, crash_file, elsewhere)

        assert open(elsewhere).read() == "report"
        assert not os.path.exists(f"{crash_file}.log")

    def test_merges_stderr_into_stdout_so_the_report_is_captured_in_order(
        self, fake_binary, crash_file, completed
    ):
        # ASan writes its report to stderr while libFuzzer's banner goes to stdout;
        # capturing them separately would scramble the saved log.
        with mock.patch.object(run_fuzzer, "run", return_value=completed(stdout="")) as fake_run:
            run_fuzzer.reproduce_crash(fake_binary, crash_file)

        assert fake_run.call_args.kwargs["stderr"] == run_fuzzer.subprocess.STDOUT
        assert fake_run.call_args.kwargs["stdout"] == run_fuzzer.subprocess.PIPE
        assert fake_run.call_args.kwargs["text"] is True

    def test_runs_the_single_input_rather_than_starting_a_fuzzing_session(
        self, fake_binary, crash_file, completed
    ):
        # Passing one file (and no -artifact_prefix or corpus dir) is what makes
        # libFuzzer replay it once and exit.
        with mock.patch.object(run_fuzzer, "run", return_value=completed(stdout="")) as fake_run:
            run_fuzzer.reproduce_crash(fake_binary, crash_file)

        assert fake_run.call_args.args[0] == [fake_binary, crash_file]

    def test_returns_the_exit_code_so_callers_can_tell_a_crash_from_a_clean_run(
        self, fake_binary, crash_file, completed
    ):
        with mock.patch.object(run_fuzzer, "run", return_value=completed(returncode=1, stdout="")):
            assert run_fuzzer.reproduce_crash(fake_binary, crash_file) == 1

        with mock.patch.object(run_fuzzer, "run", return_value=completed(returncode=0, stdout="")):
            assert run_fuzzer.reproduce_crash(fake_binary, crash_file) == 0

    def test_reports_when_the_input_no_longer_crashes(self, fake_binary, crash_file, completed, capsys):
        with mock.patch.object(run_fuzzer, "run", return_value=completed(returncode=0, stdout="")):
            run_fuzzer.reproduce_crash(fake_binary, crash_file)

        assert "did not crash" in capsys.readouterr().out

    def test_asks_ubsan_to_print_a_stack_trace(self, fake_binary, crash_file, completed):
        # Unlike ASan, UBSan does not print a stack trace by default. Without this,
        # a UBSan-only report has no frames for _crash_signature to read, so it can
        # never be confirmed to be the same bug as anything else.
        with mock.patch.object(run_fuzzer, "run", return_value=completed(stdout="")) as fake_run:
            run_fuzzer.reproduce_crash(fake_binary, crash_file)

        assert fake_run.call_args.kwargs["env"]["UBSAN_OPTIONS"] == "print_stacktrace=1"


class TestMinimizeCrash:
    def _succeeding_run(self, output_path, completed):
        """A proc.run stand-in that also creates the artifact libFuzzer would have written."""

        def _run(args, **kwargs):
            open(output_path, "w").write("minimized")
            return completed()

        return _run

    def test_refuses_to_run_without_a_built_binary(self, tmp_path, crash_file):
        with pytest.raises(SystemExit, match="Run build_fuzzer first"):
            run_fuzzer.minimize_crash(str(tmp_path / "missing"), crash_file)

    def test_refuses_to_run_on_a_missing_crash_file(self, tmp_path, fake_binary):
        with pytest.raises(SystemExit, match="not found"):
            run_fuzzer.minimize_crash(fake_binary, str(tmp_path / "no-such-crash"))

    def test_writes_the_minimized_input_beside_the_original_by_default(
        self, fake_binary, crash_file, completed
    ):
        with mock.patch.object(run_fuzzer, "run", side_effect=self._succeeding_run(f"{crash_file}.min", completed)):
            assert run_fuzzer.minimize_crash(fake_binary, crash_file) == f"{crash_file}.min"

    def test_leaves_the_original_crash_untouched(self, fake_binary, crash_file, completed):
        before = open(crash_file, "rb").read()
        with mock.patch.object(run_fuzzer, "run", side_effect=self._succeeding_run(f"{crash_file}.min", completed)):
            run_fuzzer.minimize_crash(fake_binary, crash_file)

        assert open(crash_file, "rb").read() == before

    def test_asks_libfuzzer_for_minimization_at_an_exact_path(self, fake_binary, crash_file, completed):
        with mock.patch.object(
            run_fuzzer, "run", side_effect=self._succeeding_run(f"{crash_file}.min", completed)
        ) as fake_run:
            run_fuzzer.minimize_crash(fake_binary, crash_file)

        args = fake_run.call_args.args[0]
        assert "-minimize_crash=1" in args
        assert f"-exact_artifact_path={crash_file}.min" in args
        # The input being minimized stays last, like the corpus dir does when fuzzing.
        assert args[-1] == crash_file

    def test_constrains_minimization_to_the_same_bug(self, fake_binary, crash_file, completed):
        # dedup_token_length is libFuzzer's own guard against a smaller candidate that
        # crashes somewhere else being accepted as "still the same crash".
        with mock.patch.object(
            run_fuzzer, "run", side_effect=self._succeeding_run(f"{crash_file}.min", completed)
        ) as fake_run:
            run_fuzzer.minimize_crash(fake_binary, crash_file)

        assert fake_run.call_args.kwargs["env"]["ASAN_OPTIONS"] == "dedup_token_length=3"

    def test_passes_extra_args_through(self, fake_binary, crash_file, completed):
        with mock.patch.object(
            run_fuzzer, "run", side_effect=self._succeeding_run(f"{crash_file}.min", completed)
        ) as fake_run:
            run_fuzzer.minimize_crash(fake_binary, crash_file, extra_args=["-max_total_time=10"])

        assert "-max_total_time=10" in fake_run.call_args.args[0]

    def test_fails_when_libfuzzer_exits_nonzero(self, fake_binary, crash_file, completed):
        with mock.patch.object(run_fuzzer, "run", return_value=completed(returncode=1)):
            with pytest.raises(SystemExit, match="without producing"):
                run_fuzzer.minimize_crash(fake_binary, crash_file)

    def test_fails_when_no_artifact_was_produced_despite_a_clean_exit(
        self, fake_binary, crash_file, completed
    ):
        # Returning success without the file would leave callers (triage_crash) trying to
        # reproduce a path that does not exist.
        with mock.patch.object(run_fuzzer, "run", return_value=completed(returncode=0)):
            with pytest.raises(SystemExit, match="without producing"):
                run_fuzzer.minimize_crash(fake_binary, crash_file)


class TestLogFor:
    def test_reuses_an_existing_report_without_rerunning_the_binary(self, fake_binary, crash_file):
        open(f"{crash_file}.log", "w").write(make_asan_log())

        with mock.patch.object(run_fuzzer, "reproduce_crash") as fake_reproduce:
            log_path = run_fuzzer._log_for(fake_binary, crash_file)

        fake_reproduce.assert_not_called()
        assert log_path == f"{crash_file}.log"

    def test_reproduces_the_crash_when_no_report_is_saved_yet(self, fake_binary, crash_file):
        with mock.patch.object(run_fuzzer, "reproduce_crash") as fake_reproduce:
            log_path = run_fuzzer._log_for(fake_binary, crash_file)

        fake_reproduce.assert_called_once_with(fake_binary, crash_file)
        assert log_path == f"{crash_file}.log"


class TestTriageCrash:
    @staticmethod
    def _reproduce_writing(logs_by_input):
        """Stand in for reproduce_crash, writing a caller-chosen report per input path."""

        def _reproduce(binary_path, path, output_path=None):
            open(output_path or f"{path}.log", "w").write(logs_by_input[path])
            return 1

        return _reproduce

    def test_stops_when_the_input_does_not_actually_crash(self, fake_binary, crash_file):
        with mock.patch.object(run_fuzzer, "reproduce_crash", return_value=0):
            with pytest.raises(SystemExit, match="nothing to triage"):
                run_fuzzer.triage_crash(fake_binary, crash_file)

    def test_confirms_a_minimized_crash_that_kept_the_same_bug(self, fake_binary, crash_file):
        same = make_asan_log(frames=SPARSE_INDICES_FRAMES)
        logs = {crash_file: same, f"{crash_file}.min": same}

        with mock.patch.object(run_fuzzer, "reproduce_crash", side_effect=self._reproduce_writing(logs)):
            with mock.patch.object(run_fuzzer, "minimize_crash"):
                assert run_fuzzer.triage_crash(fake_binary, crash_file) is True

    def test_flags_a_minimized_crash_that_drifted_onto_another_bug(self, fake_binary, crash_file, capsys):
        # Byte-level minimization only re-checks "does it still crash", so it can land on
        # a different call site. Reporting that as a match would hide a second bug.
        logs = {
            crash_file: make_asan_log(frames=SPARSE_INDICES_FRAMES),
            f"{crash_file}.min": make_asan_log(frames=PRIMITIVE_INDICES_FRAMES),
        }

        with mock.patch.object(run_fuzzer, "reproduce_crash", side_effect=self._reproduce_writing(logs)):
            with mock.patch.object(run_fuzzer, "minimize_crash"):
                assert run_fuzzer.triage_crash(fake_binary, crash_file) is False

        assert "MISMATCH" in capsys.readouterr().out

    def test_minimizes_to_a_sibling_min_file_by_default(self, fake_binary, crash_file):
        same = make_asan_log()
        logs = {crash_file: same, f"{crash_file}.min": same}

        with mock.patch.object(run_fuzzer, "reproduce_crash", side_effect=self._reproduce_writing(logs)):
            with mock.patch.object(run_fuzzer, "minimize_crash") as fake_minimize:
                run_fuzzer.triage_crash(fake_binary, crash_file, extra_args=["-max_total_time=10"])

        fake_minimize.assert_called_once_with(
            fake_binary, crash_file, f"{crash_file}.min", ["-max_total_time=10"]
        )

    def test_honours_an_explicit_minimized_output_path(self, tmp_path, fake_binary, crash_file):
        chosen = str(tmp_path / "smallest")
        same = make_asan_log()
        logs = {crash_file: same, chosen: same}

        with mock.patch.object(run_fuzzer, "reproduce_crash", side_effect=self._reproduce_writing(logs)):
            with mock.patch.object(run_fuzzer, "minimize_crash") as fake_minimize:
                run_fuzzer.triage_crash(fake_binary, crash_file, chosen)

        assert fake_minimize.call_args.args[2] == chosen


class TestDedupeCrashes:
    @pytest.fixture
    def fuzzer_dir(self, tmp_path):
        """A fuzzer directory with an empty crashes/ subdirectory."""
        (tmp_path / "crashes").mkdir()
        return tmp_path

    @staticmethod
    def _add_crash(fuzzer_dir, name, log=None):
        """Write a crash artifact and, optionally, its already-saved ASan report."""
        crash = fuzzer_dir / "crashes" / name
        crash.write_bytes(b"crashing input")
        if log is not None:
            (fuzzer_dir / "crashes" / f"{name}.log").write_text(log)
        return str(crash)

    def test_reports_a_missing_crashes_directory_instead_of_raising_oserror(
        self, tmp_path, fake_binary, crash_file
    ):
        # Every other failure path in this module exits with an explanatory message; a
        # raw FileNotFoundError traceback here would look like a bug in the tool.
        with pytest.raises(SystemExit, match="Run run_fuzzer first"):
            run_fuzzer.dedupe_crashes(fake_binary, crash_file, str(tmp_path / "no-such-fuzzer"))

    def test_checks_for_the_crashes_directory_before_reproducing_anything(
        self, tmp_path, fake_binary, crash_file
    ):
        # Reproducing the reference first would waste a full run before failing.
        with mock.patch.object(run_fuzzer, "reproduce_crash") as fake_reproduce:
            with pytest.raises(SystemExit):
                run_fuzzer.dedupe_crashes(fake_binary, crash_file, str(tmp_path / "no-such-fuzzer"))

        fake_reproduce.assert_not_called()

    def test_rejects_a_reference_whose_report_has_no_summary(self, fuzzer_dir, fake_binary):
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=make_asan_log(frames=None, summary=None))

        with pytest.raises(SystemExit, match="no ASan SUMMARY line"):
            run_fuzzer.dedupe_crashes(fake_binary, reference, str(fuzzer_dir))

    def test_deletes_a_crash_that_is_the_same_bug(self, fuzzer_dir, fake_binary):
        report = make_asan_log(frames=SPARSE_INDICES_FRAMES)
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=report)
        duplicate = self._add_crash(fuzzer_dir, "crash-dup", log=report)

        deleted = run_fuzzer.dedupe_crashes(fake_binary, reference, str(fuzzer_dir))

        assert not os.path.exists(duplicate)
        assert duplicate in deleted
        assert os.path.exists(reference)

    def test_keeps_a_crash_that_shares_a_summary_but_not_a_call_site(self, fuzzer_dir, fake_binary):
        # The case that makes SUMMARY-only comparison unsafe: same crash site, different
        # caller line, plausibly a second missing check worth its own fix.
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=make_asan_log(frames=SPARSE_INDICES_FRAMES))
        other = self._add_crash(fuzzer_dir, "crash-other", log=make_asan_log(frames=PRIMITIVE_INDICES_FRAMES))

        deleted = run_fuzzer.dedupe_crashes(fake_binary, reference, str(fuzzer_dir))

        assert os.path.exists(other)
        assert deleted == []

    def test_deletes_the_derivatives_of_a_duplicate_too(self, fuzzer_dir, fake_binary):
        # A duplicate's .log/.min/.min.log describe a bug already covered by the
        # reference, so leaving them behind just clutters crashes/.
        report = make_asan_log(frames=SPARSE_INDICES_FRAMES)
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=report)
        duplicate = self._add_crash(fuzzer_dir, "crash-dup", log=report)
        (fuzzer_dir / "crashes" / "crash-dup.min").write_bytes(b"small")
        (fuzzer_dir / "crashes" / "crash-dup.min.log").write_text(report)

        deleted = run_fuzzer.dedupe_crashes(fake_binary, reference, str(fuzzer_dir))

        assert set(deleted) == {
            duplicate,
            f"{duplicate}.log",
            f"{duplicate}.min",
            f"{duplicate}.min.log",
        }
        assert not any(p.name.startswith("crash-dup") for p in (fuzzer_dir / "crashes").iterdir())

    def test_does_not_treat_logs_and_minimized_inputs_as_crashes_to_check(self, fuzzer_dir, fake_binary):
        # These are derivatives of another artifact; checking them would double-count the
        # same finding and could delete the reference's own .min.
        report = make_asan_log(frames=SPARSE_INDICES_FRAMES)
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=report)
        (fuzzer_dir / "crashes" / "crash-ref.min").write_bytes(b"small")
        (fuzzer_dir / "crashes" / "crash-ref.min.log").write_text(report)

        deleted = run_fuzzer.dedupe_crashes(fake_binary, reference, str(fuzzer_dir))

        assert deleted == []
        assert (fuzzer_dir / "crashes" / "crash-ref.min").exists()

    def test_never_deletes_the_reference_itself(self, fuzzer_dir, fake_binary):
        # The reference is identified by absolute path, so a relative crash_path pointing
        # at the same file must not come back as its own duplicate.
        report = make_asan_log(frames=SPARSE_INDICES_FRAMES)
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=report)

        deleted = run_fuzzer.dedupe_crashes(fake_binary, os.path.relpath(reference), str(fuzzer_dir))

        assert deleted == []
        assert os.path.exists(reference)

    def test_leaves_untouched_a_crash_whose_report_has_no_summary(self, fuzzer_dir, fake_binary):
        # No SUMMARY means we could not read the report; deleting on that basis would be
        # destroying a finding we never actually compared.
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=make_asan_log(frames=SPARSE_INDICES_FRAMES))
        unreadable = self._add_crash(fuzzer_dir, "crash-odd", log=make_asan_log(frames=None, summary=None))

        deleted = run_fuzzer.dedupe_crashes(fake_binary, reference, str(fuzzer_dir))

        assert os.path.exists(unreadable)
        assert deleted == []

    def test_reproduces_a_crash_that_has_no_saved_report_yet(self, fuzzer_dir, fake_binary):
        report = make_asan_log(frames=SPARSE_INDICES_FRAMES)
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=report)
        pending = self._add_crash(fuzzer_dir, "crash-new")

        def _reproduce(binary_path, path, output_path=None):
            open(output_path or f"{path}.log", "w").write(report)
            return 1

        with mock.patch.object(run_fuzzer, "reproduce_crash", side_effect=_reproduce) as fake_reproduce:
            deleted = run_fuzzer.dedupe_crashes(fake_binary, reference, str(fuzzer_dir))

        fake_reproduce.assert_called_once_with(fake_binary, pending)
        assert pending in deleted

    def test_reports_what_it_checked_and_what_it_kept(self, fuzzer_dir, fake_binary, capsys):
        reference = self._add_crash(fuzzer_dir, "crash-ref", log=make_asan_log(frames=SPARSE_INDICES_FRAMES))
        self._add_crash(fuzzer_dir, "crash-other", log=make_asan_log(frames=PRIMITIVE_INDICES_FRAMES))

        run_fuzzer.dedupe_crashes(fake_binary, reference, str(fuzzer_dir))

        output = capsys.readouterr().out
        assert "Checked 1 other crash artifact(s)" in output
        assert "Duplicates deleted (0)" in output
        assert "Distinct bugs kept (1)" in output
        assert DEFAULT_SUMMARY in output
