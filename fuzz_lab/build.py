import os

from .proc import run

__all__ = [
    "build_fuzz_target",
    "build_coverage_target",
    "fuzz_target_path",
    "coverage_target_path",
]

# ASan catches memory-safety bugs as they happen instead of them corrupting
# state silently, and -fsanitize=fuzzer links libFuzzer's own main() (the one
# that drives LLVMFuzzerTestOneInput). UBSan catches undefined behavior (signed
# overflow, invalid shifts, etc.) that often causes the bad sizes/offsets behind
# a later ASan crash. -fno-sanitize-recover=all makes every check abort instead
# of just logging and continuing, so libFuzzer actually registers the crash.
_SANITIZE_FLAGS = ["-fsanitize=address,fuzzer,undefined", "-fno-sanitize-recover=all"]


def _include_flags(fuzzer_dir, source_repos):
    # Every source repo checkout goes on the include path: harness.c #includes
    # headers (e.g. "cgltf.h") vendored in whichever repo carries them, and
    # there is no per-repo "this one holds code, not just corpus data" flag to
    # filter on. Extra -I flags for corpus-only repos (e.g. glTF-Sample-Assets)
    # are harmless.
    return [f"-I{os.path.join(fuzzer_dir, repo.name)}" for repo in source_repos]


def fuzz_target_path(name, fuzzer_dir):
    # Shared with minimize_corpus() in corpus.py, which needs to run the
    # already-built binary rather than rebuild it.
    return os.path.join(fuzzer_dir, "build", f"{name}_fuzzer")


def coverage_target_path(name, fuzzer_dir):
    # Shared with generate_coverage_report() in coverage.py, which needs to
    # run the already-built coverage binary rather than rebuild it.
    return os.path.join(fuzzer_dir, "build", f"{name}_fuzzer_coverage")


def _run_clang(args, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
        result = run(["clang", *args, "-o", output_path])
    except FileNotFoundError:
        raise SystemExit("clang not found: install LLVM/clang (needed for -fsanitize=fuzzer)")
    if result.returncode != 0:
        raise SystemExit(f"clang exited with code {result.returncode}: build failed")
    print(f"{output_path} built.")


def build_fuzz_target(name, fuzzer_dir, source_repos):
    """Compile harness.c into a libFuzzer+ASan binary, ready to run against seed_corpus/."""
    harness_path = os.path.join(fuzzer_dir, "harness.c")
    if not os.path.isfile(harness_path):
        raise SystemExit(f"{harness_path} not found")

    output_path = fuzz_target_path(name, fuzzer_dir)
    args = [
        harness_path,
        *_include_flags(fuzzer_dir, source_repos),
        "-O1",
        "-g",
        *_SANITIZE_FLAGS,
    ]
    _run_clang(args, output_path)
    return output_path


def build_coverage_target(name, fuzzer_dir, source_repos):
    """Compile harness.c with source-based coverage instrumentation on top of the fuzz build.

    Still links libFuzzer + ASan so the binary can replay seed_corpus/ (or a single
    crashing input) the same way the fuzz target does. -fprofile-instr-generate
    and -fcoverage-mapping are what let `llvm-profdata`/`llvm-cov` turn a run
    into a coverage report afterwards. -O0 keeps line coverage accurate: with
    optimizations on, inlining and dead-code elimination make lines look
    uncovered even when they ran.
    """
    harness_path = os.path.join(fuzzer_dir, "harness.c")
    if not os.path.isfile(harness_path):
        raise SystemExit(f"{harness_path} not found")

    output_path = coverage_target_path(name, fuzzer_dir)
    args = [
        harness_path,
        *_include_flags(fuzzer_dir, source_repos),
        "-O0",
        "-g",
        *_SANITIZE_FLAGS,
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
    ]
    _run_clang(args, output_path)
    return output_path
