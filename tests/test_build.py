"""Unit tests for build.py.

The two build entry points differ only in the clang flags they add, so the tests focus
on those flags and on the two binaries landing at distinct paths. proc.run is mocked as
build.run; clang is never invoked.
"""

import os
from unittest import mock

import pytest

from fuzz_lab import build
from fuzz_lab.build import build_coverage_target, build_fuzz_target, coverage_target_path, fuzz_target_path
from fuzz_lab.git_repo import SourceRepo


@pytest.fixture
def fuzzer_dir(tmp_path):
    """A fuzzer directory containing the harness the build compiles."""
    (tmp_path / "harness.c").write_text("int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}\n")
    return str(tmp_path)


class TestTargetPaths:
    def test_fuzz_and_coverage_binaries_do_not_share_a_path(self):
        # Building one must never clobber the other: minimize_corpus and
        # generate_coverage_report each expect their own binary to still be there.
        assert fuzz_target_path("cgltf", "d") != coverage_target_path("cgltf", "d")

    def test_binaries_live_under_the_build_subdirectory(self):
        assert fuzz_target_path("cgltf", "cgltf_fuzz") == os.path.join("cgltf_fuzz", "build", "cgltf_fuzzer")
        assert coverage_target_path("cgltf", "cgltf_fuzz") == os.path.join(
            "cgltf_fuzz", "build", "cgltf_fuzzer_coverage"
        )


class TestBuildFuzzTarget:
    def test_refuses_to_build_without_a_harness(self, tmp_path, completed):
        with pytest.raises(SystemExit, match="harness.c not found"):
            build_fuzz_target("cgltf", str(tmp_path), [])

    def test_creates_the_build_directory(self, fuzzer_dir, completed):
        with mock.patch.object(build, "run", return_value=completed()):
            build_fuzz_target("cgltf", fuzzer_dir, [])

        assert os.path.isdir(os.path.join(fuzzer_dir, "build"))

    def test_returns_the_path_it_built(self, fuzzer_dir, completed):
        with mock.patch.object(build, "run", return_value=completed()):
            output = build_fuzz_target("cgltf", fuzzer_dir, [])

        assert output == fuzz_target_path("cgltf", fuzzer_dir)

    def test_links_libfuzzer_and_asan(self, fuzzer_dir, completed):
        # -fsanitize=fuzzer is what supplies main(); without it the binary has no entry
        # point, and without address there is nothing to detect memory bugs. undefined
        # (UBSan) catches the signed-overflow/bad-shift bugs that often cause the bad
        # sizes an ASan crash later reports; -fno-sanitize-recover=all makes every check
        # abort instead of just logging, so libFuzzer actually registers the crash.
        with mock.patch.object(build, "run", return_value=completed()) as fake_run:
            build_fuzz_target("cgltf", fuzzer_dir, [])

        args = fake_run.call_args.args[0]
        assert "-fsanitize=address,fuzzer,undefined" in args
        assert "-fno-sanitize-recover=all" in args

    def test_compiles_the_harness_with_debug_info(self, fuzzer_dir, completed):
        # -g is what lets ASan print file:line frames, which the crash-dedup logic in
        # run_fuzzer.py parses.
        with mock.patch.object(build, "run", return_value=completed()) as fake_run:
            build_fuzz_target("cgltf", fuzzer_dir, [])

        args = fake_run.call_args.args[0]
        assert args[0] == "clang"
        assert os.path.join(fuzzer_dir, "harness.c") in args
        assert "-g" in args
        assert "-O1" in args

    def test_puts_every_source_repo_on_the_include_path(self, fuzzer_dir, completed):
        # harness.c includes headers vendored in whichever repo carries them, and there
        # is no flag marking a repo as code rather than corpus data.
        repos = [SourceRepo("cgltf", "https://example.invalid/cgltf"), SourceRepo("assets", "https://e.invalid/a")]

        with mock.patch.object(build, "run", return_value=completed()) as fake_run:
            build_fuzz_target("cgltf", fuzzer_dir, repos)

        args = fake_run.call_args.args[0]
        assert f"-I{os.path.join(fuzzer_dir, 'cgltf')}" in args
        assert f"-I{os.path.join(fuzzer_dir, 'assets')}" in args

    def test_names_the_output_with_the_o_flag(self, fuzzer_dir, completed):
        with mock.patch.object(build, "run", return_value=completed()) as fake_run:
            build_fuzz_target("cgltf", fuzzer_dir, [])

        args = fake_run.call_args.args[0]
        assert args[-2:] == ["-o", fuzz_target_path("cgltf", fuzzer_dir)]

    def test_explains_how_to_fix_a_missing_clang(self, fuzzer_dir):
        with mock.patch.object(build, "run", side_effect=FileNotFoundError):
            with pytest.raises(SystemExit, match="install LLVM/clang"):
                build_fuzz_target("cgltf", fuzzer_dir, [])

    def test_fails_loudly_when_clang_exits_nonzero(self, fuzzer_dir, completed):
        with mock.patch.object(build, "run", return_value=completed(returncode=1)):
            with pytest.raises(SystemExit, match="build failed"):
                build_fuzz_target("cgltf", fuzzer_dir, [])


class TestBuildCoverageTarget:
    def test_refuses_to_build_without_a_harness(self, tmp_path):
        with pytest.raises(SystemExit, match="harness.c not found"):
            build_coverage_target("cgltf", str(tmp_path), [])

    def test_returns_the_coverage_binary_path(self, fuzzer_dir, completed):
        with mock.patch.object(build, "run", return_value=completed()):
            output = build_coverage_target("cgltf", fuzzer_dir, [])

        assert output == coverage_target_path("cgltf", fuzzer_dir)

    def test_adds_the_instrumentation_llvm_cov_needs(self, fuzzer_dir, completed):
        with mock.patch.object(build, "run", return_value=completed()) as fake_run:
            build_coverage_target("cgltf", fuzzer_dir, [])

        args = fake_run.call_args.args[0]
        assert "-fprofile-instr-generate" in args
        assert "-fcoverage-mapping" in args

    def test_builds_unoptimised_so_line_coverage_stays_accurate(self, fuzzer_dir, completed):
        # With optimizations on, inlining and dead-code elimination make lines look
        # uncovered even when they ran.
        with mock.patch.object(build, "run", return_value=completed()) as fake_run:
            build_coverage_target("cgltf", fuzzer_dir, [])

        args = fake_run.call_args.args[0]
        assert "-O0" in args
        assert "-O1" not in args

    def test_still_links_libfuzzer_so_the_binary_can_replay_a_corpus(self, fuzzer_dir, completed):
        with mock.patch.object(build, "run", return_value=completed()) as fake_run:
            build_coverage_target("cgltf", fuzzer_dir, [])

        assert "-fsanitize=address,fuzzer,undefined" in fake_run.call_args.args[0]

    def test_fails_loudly_when_clang_exits_nonzero(self, fuzzer_dir, completed):
        with mock.patch.object(build, "run", return_value=completed(returncode=1)):
            with pytest.raises(SystemExit, match="build failed"):
                build_coverage_target("cgltf", fuzzer_dir, [])
