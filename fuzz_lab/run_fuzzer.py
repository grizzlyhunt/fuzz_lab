import os
import re
import subprocess

from .proc import run

__all__ = ["run_fuzz_target", "reproduce_crash", "minimize_crash", "triage_crash", "dedupe_crashes"]

_SUMMARY_RE = re.compile(r"^SUMMARY:.*$", re.MULTILINE)
_FRAME_RE = re.compile(r"^    #\d+ 0x[0-9a-f]+ in (.+)$")


def _sanitizer_env():
    """Environment tweaks needed to make saved reports usable by this module.

    ASAN_OPTIONS=dedup_token_length=3 forces ASan to only accept a smaller
    -minimize_crash=1 candidate that hits the same 3-frame DEDUP_TOKEN as the input it
    started from. This is libFuzzer's own internal guard against minimization drifting
    onto an unrelated crash -- it is unrelated to (and less precise than) the
    frame-based comparison this module does itself via _crash_signature, which compares
    file:line rather than just function names, so it can tell apart two call sites
    within the same calling function.

    UBSAN_OPTIONS=print_stacktrace=1 is unrelated to that guard: unlike ASan, UBSan
    does not print a stack trace by default, so without this a UBSan-only report (e.g.
    a misaligned load) has no frames for _crash_signature to read at all, and
    _same_bug() can never confirm two such reports describe the same bug.
    """
    return {**os.environ, "ASAN_OPTIONS": "dedup_token_length=3", "UBSAN_OPTIONS": "print_stacktrace=1"}


def run_fuzz_target(binary_path, corpus_dir, fuzzer_dir, extra_args=None):
    """Launch the fuzz binary against corpus_dir, which grows in place as libFuzzer runs.

    corpus_dir is passed to libFuzzer as its (writable) corpus directory: it
    seeds from the files already inside and appends any new input that grows
    coverage. Crashing/leaking/timing-out inputs are written to
    fuzzer_dir/crashes via -artifact_prefix instead of littering the current
    working directory, which is libFuzzer's default.

    extra_args passes through additional libFuzzer flags as-is (e.g.
    -max_total_time=60), so callers are not limited to what this wrapper
    anticipates. A nonzero exit code most often means libFuzzer found a
    crash, not that this wrapper failed, so it is propagated rather than
    turned into a SystemExit like the other subcommands.
    """
    if not os.path.isfile(binary_path):
        raise SystemExit(f"{binary_path} not found. Run build_fuzzer first.")
    os.makedirs(corpus_dir, exist_ok=True)

    crashes_dir = os.path.join(fuzzer_dir, "crashes")
    os.makedirs(crashes_dir, exist_ok=True)

    args = [
        binary_path,
        f"-artifact_prefix={crashes_dir}{os.sep}",
        *(extra_args or []),
        corpus_dir,
    ]
    result = run(args)
    if result.returncode != 0:
        print(f"Fuzzer exited with code {result.returncode}. Check {crashes_dir} for crashing input(s).")
        raise SystemExit(result.returncode)


def reproduce_crash(binary_path, crash_path, output_path=None):
    """Replay a single saved crash file against the fuzz binary and print its ASan report.

    A lone file argument (as opposed to a directory) makes libFuzzer run just that one
    input and exit, instead of fuzzing. No -dict/-artifact_prefix needed here: we are
    replaying an existing failure, not searching for a new one.

    stdout and stderr are merged (stderr=STDOUT) so the saved log preserves the same
    interleaving a terminal would show, since ASan writes its report to stderr while
    libFuzzer's own banner lines go to stdout. The combined output is written to
    output_path (default: crash_path + '.log') so the report can be inspected later
    without re-running the binary.
    """
    if not os.path.isfile(binary_path):
        raise SystemExit(f"{binary_path} not found. Run build_fuzzer first.")
    if not os.path.isfile(crash_path):
        raise SystemExit(f"{crash_path} not found.")
    if output_path is None:
        output_path = f"{crash_path}.log"

    result = run(
        [binary_path, crash_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=_sanitizer_env(),
    )
    print(result.stdout, end="")
    with open(output_path, "w") as log:
        log.write(result.stdout)

    if result.returncode != 0:
        print(f"Crash reproduced (exit code {result.returncode}). ASan report saved to {output_path}.")
    else:
        print("Input did not crash the target (already fixed, or not the right binary?).")
    return result.returncode


def minimize_crash(binary_path, crash_path, output_path=None, extra_args=None):
    """Shrink crash_path to the smallest input that still triggers the same bug.

    Writes the result to output_path (default: crash_path + '.min') via
    -exact_artifact_path, leaving crash_path itself untouched. See _sanitizer_env for
    why ASAN_OPTIONS and UBSAN_OPTIONS are set on the subprocess. extra_args should
    include a bound (-runs=N or -max_total_time=N): the libFuzzer -help text for
    -minimize_crash recommends one, since minimization otherwise has no built-in
    stopping point.
    """
    if not os.path.isfile(binary_path):
        raise SystemExit(f"{binary_path} not found. Run build_fuzzer first.")
    if not os.path.isfile(crash_path):
        raise SystemExit(f"{crash_path} not found.")
    if output_path is None:
        output_path = f"{crash_path}.min"

    args = [
        binary_path,
        "-minimize_crash=1",
        f"-exact_artifact_path={output_path}",
        *(extra_args or []),
        crash_path,
    ]
    result = run(args, env=_sanitizer_env())
    if result.returncode != 0 or not os.path.isfile(output_path):
        raise SystemExit(f"libFuzzer exited with code {result.returncode} without producing {output_path}.")
    print(f"Minimized crash written to {output_path}.")
    return output_path


def _summary_line(log_path):
    """Extract ASan's 'SUMMARY: ...' line from a saved report, or None if it has none."""
    with open(log_path) as log:
        match = _SUMMARY_RE.search(log.read())
    return match.group(0) if match else None


def _crash_signature(log_path, depth=3):
    """First `depth` frames of a saved report's own crash stack, as (function, file:line:col)
    pairs with addresses stripped out (addresses shift between runs under ASLR; file:line
    does not). Only the first contiguous "    #N 0x... in ..." block is read, so a second
    stack printed later in the same report (e.g. an allocation-site backtrace) is ignored.

    Comparing by file:line rather than just function name matters here: cgltf_validate
    calls cgltf_calc_index_bound from two different call sites (cgltf.h:1632 and :1719),
    which are plausibly two different missing checks. A signature built from function
    names alone (e.g. ASan's own DEDUP_TOKEN) cannot tell those apart, since both call
    sites are in the same function; comparing file:line of the *caller* frame can.
    Returns None if the report has no recognizable stack (e.g. a non-ASan crash).
    """
    frames = []
    with open(log_path) as log:
        for line in log:
            match = _FRAME_RE.match(line)
            if match:
                frames.append(match.group(1))
                if len(frames) == depth:
                    break
            elif frames:
                break
    return tuple(frames) if frames else None


def _same_bug(log_a, log_b):
    """True if two saved ASan reports are the same bug, per _crash_signature."""
    signature_a = _crash_signature(log_a)
    return signature_a is not None and signature_a == _crash_signature(log_b)


def _log_for(binary_path, path):
    """Return path's saved ASan report, reproducing it first only if not already saved."""
    log_path = f"{path}.log"
    if os.path.isfile(log_path):
        print(f"\n=== Reusing existing log: {log_path} ===")
    else:
        print(f"\n=== Reproducing: {path} ===")
        reproduce_crash(binary_path, path)
    return log_path


def triage_crash(binary_path, crash_path, min_output_path=None, extra_args=None):
    """Reproduce a crash, minimize it, reproduce the minimized input, and compare the two.

    Runs reproduce_crash on crash_path (saving its ASan report), then minimize_crash
    (default output: crash_path + '.min', itself guarded by ASAN_OPTIONS=
    dedup_token_length=3 so it cannot drift onto an unrelated bug), then
    reproduce_crash again on the minimized output. The two reports' crash-stack
    signatures (see _crash_signature) are compared as a second, human-visible
    confirmation that minimizing did not change which bug is being reproduced, and a
    final report is printed. Returns True if both reports agree.
    """
    if min_output_path is None:
        min_output_path = f"{crash_path}.min"

    print(f"=== Reproducing original crash: {crash_path} ===")
    if reproduce_crash(binary_path, crash_path) == 0:
        raise SystemExit(f"{crash_path} does not crash {binary_path}; nothing to triage.")
    original_log = f"{crash_path}.log"

    print(f"\n=== Minimizing: {crash_path} -> {min_output_path} ===")
    minimize_crash(binary_path, crash_path, min_output_path, extra_args)

    print(f"\n=== Reproducing minimized crash: {min_output_path} ===")
    reproduce_crash(binary_path, min_output_path)
    min_log = f"{min_output_path}.log"

    original_summary = _summary_line(original_log)
    min_summary = _summary_line(min_log)
    same_bug = _same_bug(original_log, min_log)

    print("\n=== Triage result ===")
    print(f"Original  ({original_log}):\n  {original_summary or '<no SUMMARY line found>'}")
    print(f"Minimized ({min_log}):\n  {min_summary or '<no SUMMARY line found>'}")
    print(
        "Same bug: YES"
        if same_bug
        else "Same bug: NO -- MISMATCH, investigate before trusting the minimized crash"
    )
    return same_bug


def dedupe_crashes(binary_path, crash_path, fuzzer_dir):
    """Delete other saved crashes that are exact duplicates of crash_path's bug.

    crash_path is the reference: its ASan report is reused if a '.log' is already saved
    next to it, otherwise reproduce_crash generates one first. Every other crash artifact
    directly under fuzzer_dir/crashes -- any file that is not crash_path itself, and does
    not end in '.log' or '.min' (those are derivatives of another artifact, not
    independent finds) -- is checked the same way. Files that are the same bug as the
    reference per _same_bug (crash-stack signature, i.e. matching call sites by
    file:line, not just crash-site function name) are deleted, along with any
    '.log'/'.min'/'.min.log' sitting next to them, since they are redundant reports of a
    bug already covered by crash_path. Prints a final report and returns the list of
    deleted paths.
    """
    crashes_dir = os.path.join(fuzzer_dir, "crashes")
    # Checked up front, before reproducing anything: the scan below would otherwise fail
    # with a bare FileNotFoundError, and only after spending a run on the reference crash.
    if not os.path.isdir(crashes_dir):
        raise SystemExit(f"{crashes_dir} not found. Run run_fuzzer first to collect crashes.")

    reference_log = _log_for(binary_path, crash_path)
    reference_summary = _summary_line(reference_log)
    if reference_summary is None:
        raise SystemExit(f"{crash_path} produced no ASan SUMMARY line; is it actually crashing?")

    reference_abspath = os.path.abspath(crash_path)
    candidates = sorted(
        entry.path
        for entry in os.scandir(crashes_dir)
        if entry.is_file()
        and not entry.name.endswith(".log")
        and not entry.name.endswith(".min")
        and os.path.abspath(entry.path) != reference_abspath
    )

    duplicates, distinct, unknown = [], [], []
    for other in candidates:
        other_log = _log_for(binary_path, other)
        summary = _summary_line(other_log)
        if summary is None:
            unknown.append(other)
        elif _same_bug(reference_log, other_log):
            duplicates.append(other)
        else:
            distinct.append((other, summary))

    deleted = []
    for other in duplicates:
        for path in (other, f"{other}.log", f"{other}.min", f"{other}.min.log"):
            if os.path.isfile(path):
                os.remove(path)
                deleted.append(path)

    print("\n=== Dedup report ===")
    print(f"Reference: {crash_path}\n  {reference_summary}")
    print(f"Checked {len(candidates)} other crash artifact(s) in {crashes_dir}.")

    print(f"\nDuplicates deleted ({len(duplicates)}):")
    for other in duplicates:
        print(f"  {other}")

    print(f"\nDistinct bugs kept ({len(distinct)}):")
    for other, summary in distinct:
        print(f"  {other}\n    {summary}")

    if unknown:
        print(f"\nNo SUMMARY line found, left untouched ({len(unknown)}):")
        for other in unknown:
            print(f"  {other}")

    return deleted
