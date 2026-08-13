import os
import shutil

from proc import run

__all__ = ["generate_coverage_report"]


def generate_coverage_report(binary_path, corpus_dir, fuzzer_dir):
    """Replay corpus_dir through the coverage binary and render an HTML line-coverage report.

    Three steps, the standard libFuzzer + llvm-cov workflow:
    - Run the binary over every file in corpus_dir. `-runs=0` replays the
      corpus once and exits instead of also fuzzing new inputs.
      LLVM_PROFILE_FILE tells the coverage-instrumented binary where to write
      its raw counters.
    - `llvm-profdata merge` turns that raw profile into the indexed .profdata
      format llvm-cov expects (required even for a single profraw file).
    - `llvm-cov show -format=html` renders a browsable per-line report.
    """
    if not os.path.isfile(binary_path):
        raise SystemExit(f"{binary_path} not found. Run build_coverage first.")
    if not os.path.isdir(corpus_dir):
        raise SystemExit(f"{corpus_dir} not found.")

    coverage_dir = os.path.join(fuzzer_dir, "coverage")
    os.makedirs(coverage_dir, exist_ok=True)
    profraw_path = os.path.join(coverage_dir, "coverage.profraw")
    profdata_path = os.path.join(coverage_dir, "coverage.profdata")
    report_dir = os.path.join(coverage_dir, "report")

    env = {**os.environ, "LLVM_PROFILE_FILE": profraw_path}
    result = run([binary_path, "-runs=0", corpus_dir], env=env)
    if result.returncode != 0:
        raise SystemExit(f"{binary_path} exited with code {result.returncode}: coverage run failed")

    result = run(["llvm-profdata", "merge", "-sparse", profraw_path, "-o", profdata_path])
    if result.returncode != 0:
        raise SystemExit(f"llvm-profdata exited with code {result.returncode}: merge failed")

    if os.path.isdir(report_dir):
        shutil.rmtree(report_dir)
    result = run(
        [
            "llvm-cov",
            "show",
            binary_path,
            f"-instr-profile={profdata_path}",
            "-format=html",
            f"-output-dir={report_dir}",
        ]
    )
    if result.returncode != 0:
        raise SystemExit(f"llvm-cov exited with code {result.returncode}: report generation failed")

    report_index = os.path.join(report_dir, "index.html")
    print(f"Coverage report generated at {report_index}.")
    return report_dir
