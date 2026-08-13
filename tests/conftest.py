"""Fixtures shared across the test suite.

The report text these fixtures write is built by tests/asan_reports.py; this module only
wires it to temporary directories and provides the subprocess stand-ins that let the
run_fuzzer entry points be exercised without a compiled fuzz target.
"""

import subprocess

import pytest

from asan_reports import make_asan_log


@pytest.fixture
def write_log(tmp_path):
    """Return a helper writing an ASan report to tmp_path and giving back its path.

    Returns str paths rather than pathlib.Path because the production code builds sibling
    paths with f-string concatenation (f"{path}.log"), and passing Path objects would
    quietly exercise a different code path than the CLI does.
    """

    def _write(name, **kwargs):
        log_path = tmp_path / name
        log_path.write_text(make_asan_log(**kwargs))
        return str(log_path)

    return _write


@pytest.fixture
def completed():
    """Return a factory for subprocess.CompletedProcess stand-ins.

    The production code only ever reads .returncode and .stdout off the result of
    proc.run(), but using the real CompletedProcess type keeps the fakes honest if that
    ever changes.
    """

    def _completed(returncode=0, stdout="", args=None):
        return subprocess.CompletedProcess(args=args or ["fake"], returncode=returncode, stdout=stdout)

    return _completed


@pytest.fixture
def fake_binary(tmp_path):
    """Create a file standing in for the compiled fuzz target.

    Every entry point in run_fuzzer.py starts by checking the binary exists on disk, so
    tests that get past that check need a real file -- it is never executed, since
    proc.run is mocked out.
    """
    binary = tmp_path / "cgltf_fuzzer"
    binary.write_text("#!/bin/sh\n")
    return str(binary)
