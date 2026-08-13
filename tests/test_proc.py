"""Unit tests for proc.run().

run() is a thin wrapper around subprocess.run, so every test here mocks subprocess.run
out and asserts on what it was handed. Nothing in this file starts a real process.
"""

import os
import subprocess
from unittest import mock

from fuzz_lab import proc


def test_echoes_the_command_line_before_running_it(capsys):
    with mock.patch.object(subprocess, "run"):
        proc.run(["echo", "hello world"])

    # shlex.join quotes the argument containing a space, so the printed line stays
    # copy-pasteable into a shell.
    assert capsys.readouterr().out == "$ echo 'hello world'\n"


def test_returns_whatever_subprocess_run_returns():
    expected = subprocess.CompletedProcess(args=["true"], returncode=0)
    with mock.patch.object(subprocess, "run", return_value=expected):
        assert proc.run(["true"]) is expected


def test_passes_args_through_unchanged():
    with mock.patch.object(subprocess, "run") as fake_run:
        proc.run(["ls", "-la", "/tmp"])

    assert fake_run.call_args.args[0] == ["ls", "-la", "/tmp"]


def test_forwards_extra_kwargs_to_subprocess_run():
    with mock.patch.object(subprocess, "run") as fake_run:
        proc.run(["ls"], stdout=subprocess.PIPE, text=True)

    assert fake_run.call_args.kwargs["stdout"] == subprocess.PIPE
    assert fake_run.call_args.kwargs["text"] is True


def test_blanks_debuginfod_urls_when_no_env_is_given():
    # The whole reason this wrapper exists: Ubuntu sets DEBUGINFOD_URLS globally, and an
    # unreachable server makes llvm-symbolizer hang ~90s per ASan report.
    with mock.patch.dict(os.environ, {"DEBUGINFOD_URLS": "https://debuginfod.ubuntu.com"}):
        with mock.patch.object(subprocess, "run") as fake_run:
            proc.run(["true"])

    assert fake_run.call_args.kwargs["env"]["DEBUGINFOD_URLS"] == ""


def test_inherits_the_rest_of_the_ambient_environment():
    with mock.patch.dict(os.environ, {"SOME_PROJECT_VAR": "kept"}):
        with mock.patch.object(subprocess, "run") as fake_run:
            proc.run(["true"])

    assert fake_run.call_args.kwargs["env"]["SOME_PROJECT_VAR"] == "kept"


def test_blanks_debuginfod_urls_even_when_the_caller_supplies_an_env():
    # minimize_crash passes its own env to set ASAN_OPTIONS; the debuginfod override has
    # to win over whatever the caller inherited into that dict, or the hang comes back.
    caller_env = {"DEBUGINFOD_URLS": "https://debuginfod.ubuntu.com", "ASAN_OPTIONS": "dedup_token_length=3"}

    with mock.patch.object(subprocess, "run") as fake_run:
        proc.run(["true"], env=caller_env)

    passed_env = fake_run.call_args.kwargs["env"]
    assert passed_env["DEBUGINFOD_URLS"] == ""
    assert passed_env["ASAN_OPTIONS"] == "dedup_token_length=3"


def test_caller_env_replaces_the_ambient_environment_rather_than_extending_it():
    # A caller-supplied env is handed to subprocess.run as-is (plus the debuginfod
    # override), so variables that were only in os.environ do not survive. Callers that
    # want both have to start from a copy of os.environ themselves, which is what
    # run_fuzzer._asan_dedup_env() does.
    with mock.patch.dict(os.environ, {"AMBIENT_ONLY": "present"}):
        with mock.patch.object(subprocess, "run") as fake_run:
            proc.run(["true"], env={"ASAN_OPTIONS": "dedup_token_length=3"})

    assert "AMBIENT_ONLY" not in fake_run.call_args.kwargs["env"]


def test_does_not_modify_the_env_dict_the_caller_passed_in():
    # run() has to force DEBUGINFOD_URLS, but writing that into the caller's own dict
    # would silently edit state the caller still owns -- and would leak the override
    # into any later reuse of that same dict.
    caller_env = {"ASAN_OPTIONS": "dedup_token_length=3"}

    with mock.patch.object(subprocess, "run"):
        proc.run(["true"], env=caller_env)

    assert caller_env == {"ASAN_OPTIONS": "dedup_token_length=3"}


def test_an_explicitly_empty_env_is_not_treated_as_no_env_at_all():
    # env={} is a deliberate request for an empty environment; falling back to
    # os.environ here would hand the process far more than it asked for.
    with mock.patch.dict(os.environ, {"AMBIENT_ONLY": "present"}):
        with mock.patch.object(subprocess, "run") as fake_run:
            proc.run(["true"], env={})

    assert fake_run.call_args.kwargs["env"] == {"DEBUGINFOD_URLS": ""}


def test_env_is_not_passed_along_as_a_duplicate_keyword():
    # env is popped out of kwargs before forwarding, so subprocess.run must not receive
    # it twice (which would raise TypeError).
    with mock.patch.object(subprocess, "run") as fake_run:
        proc.run(["true"], env={"A": "b"})

    assert fake_run.call_count == 1
