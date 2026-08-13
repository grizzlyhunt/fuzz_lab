import argparse
import re

from . import glb
from .fuzzer import Fuzzer
from .git_repo import SourceRepo

# A fuzzer name ends up being used as a directory name, so it must not contain
# path separators, "..", or anything the shell/filesystem would treat specially.
# Restricting it to this small character set is simpler (and safer) than trying
# to sanitize arbitrary input afterwards.
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def fuzzer_name(value):
    """argparse type converter: accept the value only if it is a safe fuzzer name.

    argparse calls this with the raw string typed on the command line. Raising
    ArgumentTypeError makes argparse print a proper usage error and exit with
    code 2, instead of us crashing later with a confusing traceback.
    """
    if not _NAME_PATTERN.match(value):
        raise argparse.ArgumentTypeError(
            f"invalid fuzzer name {value!r}: use letters, digits, '_' or '-' only"
        )
    return value


# An extension ends up compared against os.path.splitext() output and used to
# build a set of matches, so we only need it free of path separators/spaces.
# Accepting it with or without the leading dot is just for convenience: it's
# normalized to always store it with one.
_EXTENSION_PATTERN = re.compile(r"^\.?[A-Za-z0-9]+$")


def file_extension(value):
    """argparse type converter: accept the value only if it looks like a bare extension.

    Normalizes to always include the leading dot, so ``gltf`` and ``.gltf``
    are stored (and compared against os.path.splitext()) the same way.
    """
    if not _EXTENSION_PATTERN.match(value):
        raise argparse.ArgumentTypeError(
            f"invalid extension {value!r}: use letters/digits, optionally prefixed with '.'"
        )
    return value if value.startswith(".") else f".{value}"


def create_fuzzer(args):
    """Handler for the `create_fuzzer` subcommand.

    Fuzzer.create() does all the scaffolding: it makes the directory, writes an
    empty fuzzer.json and drops the placeholder harness. It also refuses to run
    when the directory already exists, so we cannot silently clobber an existing
    fuzzer. The `name` -> `<name>_fuzz` directory mapping lives in fuzzer.py, so
    the CLI only ever passes the bare name around.
    """
    Fuzzer.create(args.name)


def add_repo(args):
    """Handler for the `add_repo` subcommand.

    This does NOT clone anything: it only records the repo (name, url, depth)
    in fuzzer.json via Fuzzer.add_repo(). Cloning/pulling is `prepare`'s job.
    Keeping the two separate means re-running `prepare` later (e.g. to refresh
    checkouts) never needs the repo URLs to be retyped.
    """
    # Fuzzer.load() reads back <name>_fuzz/fuzzer.json. It raises SystemExit
    # with a clear message if that directory/file does not exist yet, so we
    # do not need to check that ourselves here.
    fuzzer = Fuzzer.load(args.name)
    fuzzer.add_repo(SourceRepo(args.repo_name, args.url, depth=args.depth))
    print(f"{args.repo_name} added to {fuzzer.config_path}.")


def remove_repo(args):
    """Handler for the `remove_repo` subcommand.

    Only edits fuzzer.json (mirrors add_repo). The checkout directory, if any,
    is left on disk until the next `prepare_repos` run cleans it up.
    """
    fuzzer = Fuzzer.load(args.name)
    fuzzer.remove_repo(args.repo_name)
    print(f"{args.repo_name} removed from {fuzzer.config_path}.")


def prepare_repos(args):
    """Handler for the `prepare_repos` subcommand.

    Reconciles the fuzzer directory with fuzzer.json: clones repos that are
    missing, pulls the ones that already exist, and deletes checkouts that are
    no longer listed in the config. Safe to run repeatedly.
    """
    Fuzzer.load(args.name).prepare_repos()


def add_corpus_source(args):
    """Handler for the `add_corpus_source` subcommand.

    This does NOT copy any file: it only records repo_name + extensions in
    fuzzer.json via Fuzzer.add_corpus_source(). repo_name must already be a
    source repo (added with add_repo), since prepare_corpus reads files from
    that repo's checkout. Actually populating seed_corpus/ is prepare_corpus's job.
    """
    fuzzer = Fuzzer.load(args.name)
    fuzzer.add_corpus_source(args.repo_name, args.extensions)
    extensions = ", ".join(args.extensions)
    print(f"{args.repo_name} added as a corpus source of {fuzzer.config_path} ({extensions}).")


def edit_corpus_source(args):
    """Handler for the `edit_corpus_source` subcommand.

    Replaces the extension list of an existing corpus source in fuzzer.json.
    Config-only, like add_corpus_source; run prepare_corpus afterwards to
    resync seed_corpus/ with the new extensions.
    """
    fuzzer = Fuzzer.load(args.name)
    fuzzer.edit_corpus_source(args.repo_name, args.extensions)
    extensions = ", ".join(args.extensions)
    print(f"{args.repo_name} corpus source extensions updated to {extensions}.")


def remove_corpus_source(args):
    """Handler for the `remove_corpus_source` subcommand.

    Only edits fuzzer.json (mirrors remove_repo). The seed_corpus/<repo_name>
    subtree, if any, is left on disk until the next prepare_corpus run
    cleans it up.
    """
    fuzzer = Fuzzer.load(args.name)
    fuzzer.remove_corpus_source(args.repo_name)
    print(f"{args.repo_name} removed as a corpus source of {fuzzer.config_path}.")


def prepare_corpus(args):
    """Handler for the `prepare_corpus` subcommand.

    Reconciles fuzzer_dir/seed_corpus with fuzzer.json: resyncs the files owned by
    every configured corpus source and deletes files/dirs no longer owned by
    any of them. Requires prepare_repos to have been run first, since it reads
    from the repo checkouts under the fuzzer directory rather than cloning
    anything.
    """
    Fuzzer.load(args.name).prepare_corpus()


def minimize_corpus(args):
    """Handler for the `minimize_corpus` subcommand.

    Runs the already-built fuzzer binary with libFuzzer's -merge=1 mode to
    shrink seed_corpus/ down to a subset that keeps the same coverage, written to
    fuzzer_dir/min_corpus (seed_corpus/ itself is left untouched). Requires
    build_fuzzer to have been run first.
    """
    Fuzzer.load(args.name).minimize_corpus()


def run_fuzzer(args):
    """Handler for the `run_fuzzer` subcommand.

    Launches the fuzz binary against a corpus directory (default:
    seed_corpus/), which grows in place as libFuzzer finds new inputs.
    Crashing inputs are saved under fuzzer_dir/crashes. Requires
    build_fuzzer to have been run first. Runs until interrupted (Ctrl+C)
    unless --time is given.
    """
    extra_args = []
    if args.time is not None:
        extra_args.append(f"-max_total_time={args.time}")
    if args.value_profile:
        extra_args.append("-use_value_profile=1")
    if args.continue_on_crash:
        # In-process libFuzzer always aborts the whole run on a crash (ASan has just
        # reported memory corruption, so the process cannot be trusted to keep going).
        # -fork=1 moves fuzzing into a subprocess that gets restarted after each crash
        # instead of ending the session; -ignore_crashes=1 tells fork mode to do that
        # restart instead of stopping itself at the first crash it sees.
        extra_args.extend(["-fork=1", "-ignore_crashes=1"])
    Fuzzer.load(args.name).run_fuzz_target(args.corpus, extra_args)


def repro_crash(args):
    """Handler for the `repro_crash` subcommand.

    Replays a single saved crash file against the fuzz binary and prints its ASan
    report (exits nonzero if the crash still reproduces). The report is also saved
    to --output (default: crash_path + '.log') so it doesn't need to be reproduced
    again just to look at it. Requires build_fuzzer to have been run first.
    """
    Fuzzer.load(args.name).reproduce_crash(args.crash_path, args.output)


def minimize_crash(args):
    """Handler for the `minimize_crash` subcommand.

    Shrinks a saved crash file to the smallest input that still triggers the same
    bug, writing it to --output (default: crash_path + '.min') so the original
    crash file is never overwritten. Requires build_fuzzer to have been run first.
    """
    extra_args = [f"-max_total_time={args.time}"]
    Fuzzer.load(args.name).minimize_crash(args.crash_path, args.output, extra_args)


def triage_crash(args):
    """Handler for the `triage_crash` subcommand.

    Runs the full crash-triage pipeline: reproduce the original crash (saving its ASan
    report to crash_path + '.log'), minimize it to --output (default: crash_path +
    '.min'), reproduce the minimized crash (saving its report alongside it), then
    compare both reports' crash-stack signatures (call sites by file:line, not just the
    crash-site function name) and print whether they agree. Requires build_fuzzer to
    have been run first.
    """
    extra_args = [f"-max_total_time={args.time}"]
    Fuzzer.load(args.name).triage_crash(args.crash_path, args.output, extra_args)


def dedupe_crashes(args):
    """Handler for the `dedupe_crashes` subcommand.

    Reproduces crash_path if it has no saved '.log' yet, then does the same for every
    other crash artifact under the fuzzer's crashes/ directory (reusing any '.log'
    already there instead of re-running), and deletes any whose crash-stack signature
    matches crash_path's (call sites by file:line, not just the crash-site function
    name) -- along with their '.log'/'.min' derivatives, since they are redundant
    reports of the same bug. Requires build_fuzzer to have been run first.
    """
    Fuzzer.load(args.name).dedupe_crashes(args.crash_path)


def extract_glb_json(args):
    """Handler for the `extract_glb_json` subcommand.

    Pulls the JSON chunk out of a binary glTF (.glb) crash file and writes it to its
    own file (default: glb_path + '.json') for hand-editing -- unlike the .glb as a
    whole, plain glTF JSON is valid UTF-8, so it is safe to open in a text editor.
    Needs no fuzzer name: this is pure byte slicing, not a run of the fuzz binary.
    """
    glb.extract_glb_json(args.glb_path, args.output)


def build_fuzzer(args):
    """Handler for the `build_fuzzer` subcommand.

    Compiles harness.c with libFuzzer + ASan into fuzzer_dir/build/. Every
    configured source repo's checkout is added to the include path, since
    harness.c may #include headers vendored in one of them.
    """
    Fuzzer.load(args.name).build_fuzz_target()


def build_coverage(args):
    """Handler for the `build_coverage` subcommand.

    Compiles harness.c the same way as build_fuzzer, but with source-based
    coverage instrumentation added on top, so a run of the resulting binary
    can be turned into a coverage report with llvm-profdata/llvm-cov.
    """
    Fuzzer.load(args.name).build_coverage_target()


def coverage_report(args):
    """Handler for the `coverage_report` subcommand.

    Replays a corpus (default: seed_corpus/) through the coverage binary and
    renders an HTML line-coverage report under fuzzer_dir/coverage/report.
    Requires build_coverage to have been run first.
    """
    Fuzzer.load(args.name).generate_coverage_report(args.corpus)


def main():
    parser = argparse.ArgumentParser(description="Fuzzing harness scaffolding.")

    # Subcommands (`create_fuzzer`, and later `add_repo`, `prepare`, ...).
    # required=True makes running `cli.py` with no subcommand an error instead
    # of silently doing nothing.
    subparsers = parser.add_subparsers(required=True)

    ############################
    # Subcommand: create_fuzzer
    ############################

    create = subparsers.add_parser(
        "create_fuzzer",
        help="Create a fuzzer directory holding a placeholder harness.",
    )
    create.add_argument("name", type=fuzzer_name, help="Fuzzer name, e.g. 'cgltf'.")
    # set_defaults attaches the handler to the parsed arguments, so main() does
    # not need an if/elif chain growing with every new subcommand.
    create.set_defaults(func=create_fuzzer)

    ########################
    # Subcommand: add_repo
    ########################

    add = subparsers.add_parser(
        "add_repo",
        help="Register a source repo (name, url, optional depth) in the fuzzer config.",
    )
    add.add_argument("name", type=fuzzer_name, help="Fuzzer to add the repo to.")
    # repo_name also goes through fuzzer_name: git_repo.checkout_repo() joins it
    # onto the fuzzer directory as a checkout path (parent_dir/repo.name), so it
    # is exactly as security-sensitive as the fuzzer name itself.
    add.add_argument("repo_name", type=fuzzer_name, help="Directory name for the checkout.")
    add.add_argument("url", help="Git URL to clone, e.g. https://github.com/org/repo.git")
    add.add_argument(
        "--depth",
        type=int,
        default=None,
        help="Shallow clone depth. Omit to keep full history.",
    )
    add.set_defaults(func=add_repo)

    ########################
    # Subcommand: remove_repo
    ########################

    remove = subparsers.add_parser(
        "remove_repo",
        help="Remove a source repo from the fuzzer config (run prepare_repos to delete its checkout).",
    )
    remove.add_argument("name", type=fuzzer_name, help="Fuzzer to remove the repo from.")
    remove.add_argument("repo_name", type=fuzzer_name, help="Repo name, as passed to add_repo.")
    remove.set_defaults(func=remove_repo)

    ########################
    # Subcommand: prepare_repos
    ########################

    checkout = subparsers.add_parser(
        "prepare_repos",
        help="Clone/pull configured repos and delete checkouts no longer in the config.",
    )
    checkout.add_argument("name", type=fuzzer_name, help="Fuzzer to prepare.")
    checkout.set_defaults(func=prepare_repos)

    ##############################
    # Subcommand: add_corpus_source
    ##############################

    add_corpus = subparsers.add_parser(
        "add_corpus_source",
        help="Use an existing source repo as a base-corpus file source, given its extensions.",
    )
    add_corpus.add_argument("name", type=fuzzer_name, help="Fuzzer to add the corpus source to.")
    add_corpus.add_argument(
        "repo_name", type=fuzzer_name, help="Source repo to use, as passed to add_repo."
    )
    add_corpus.add_argument(
        "extensions",
        type=file_extension,
        nargs="+",
        help="File extensions to search for, e.g. gltf glb bin.",
    )
    add_corpus.set_defaults(func=add_corpus_source)

    ###############################
    # Subcommand: edit_corpus_source
    ###############################

    edit_corpus = subparsers.add_parser(
        "edit_corpus_source",
        help="Change the extensions searched for in an already-configured corpus source.",
    )
    edit_corpus.add_argument("name", type=fuzzer_name, help="Fuzzer to edit the corpus source of.")
    edit_corpus.add_argument(
        "repo_name", type=fuzzer_name, help="Corpus source repo, as passed to add_corpus_source."
    )
    edit_corpus.add_argument(
        "extensions",
        type=file_extension,
        nargs="+",
        help="New file extensions to search for, replacing the current ones.",
    )
    edit_corpus.set_defaults(func=edit_corpus_source)

    #################################
    # Subcommand: remove_corpus_source
    #################################

    remove_corpus = subparsers.add_parser(
        "remove_corpus_source",
        help="Stop using a repo as a base-corpus file source (run prepare_corpus to delete its files).",
    )
    remove_corpus.add_argument(
        "name", type=fuzzer_name, help="Fuzzer to remove the corpus source from."
    )
    remove_corpus.add_argument(
        "repo_name", type=fuzzer_name, help="Corpus source repo, as passed to add_corpus_source."
    )
    remove_corpus.set_defaults(func=remove_corpus_source)

    ##########################
    # Subcommand: prepare_corpus
    ##########################

    corpus = subparsers.add_parser(
        "prepare_corpus",
        help="Sync the fuzzer's seed_corpus/ directory from the configured corpus sources.",
    )
    corpus.add_argument("name", type=fuzzer_name, help="Fuzzer to prepare the corpus for.")
    corpus.set_defaults(func=prepare_corpus)

    ##########################
    # Subcommand: minimize_corpus
    ##########################

    minimize = subparsers.add_parser(
        "minimize_corpus",
        help="Shrink seed_corpus/ to a coverage-equivalent subset via libFuzzer -merge=1, written to min_corpus/.",
    )
    minimize.add_argument("name", type=fuzzer_name, help="Fuzzer to minimize the corpus for.")
    minimize.set_defaults(func=minimize_corpus)

    ########################
    # Subcommand: run_fuzzer
    ########################

    run_fuzz = subparsers.add_parser(
        "run_fuzzer",
        help="Launch the fuzz binary against a corpus, growing it in place and saving crashes.",
    )
    run_fuzz.add_argument("name", type=fuzzer_name, help="Fuzzer to run.")
    run_fuzz.add_argument(
        "--corpus",
        default=None,
        help="Corpus directory to fuzz with. Defaults to fuzzer_dir/seed_corpus.",
    )
    run_fuzz.add_argument(
        "--time",
        type=int,
        default=None,
        help="Stop after this many seconds (libFuzzer -max_total_time). Omit to run until interrupted.",
    )
    run_fuzz.add_argument(
        "--value-profile",
        action="store_true",
        help=(
            "Enable libFuzzer -use_value_profile=1: traces comparison operands at runtime and "
            "feeds them back into mutations, complementing (or standing in for) a manual "
            "dictionary. Off by default: it costs exec/sec and grows the corpus faster than "
            "normal, so pair it with periodic minimize_corpus runs rather than leaving it on "
            "for long regression runs."
        ),
    )
    run_fuzz.add_argument(
        "--continue-on-crash",
        action="store_true",
        help=(
            "Keep fuzzing past a crash instead of stopping at the first one, up until "
            "--time runs out (or Ctrl+C). Implemented as libFuzzer fork mode "
            "(-fork=1 -ignore_crashes=1): each crash is still saved under fuzzer_dir/crashes, "
            "but a fresh subprocess is restarted afterwards rather than ending the session."
        ),
    )
    run_fuzz.set_defaults(func=run_fuzzer)

    ########################
    # Subcommand: repro_crash
    ########################

    repro = subparsers.add_parser(
        "repro_crash",
        help="Replay a single saved crash file against the fuzz binary and print its ASan report.",
    )
    repro.add_argument("name", type=fuzzer_name, help="Fuzzer to replay the crash with.")
    repro.add_argument("crash_path", help="Path to the crash file, e.g. cgltf_fuzz/crashes/crash-<hash>.")
    repro.add_argument(
        "--output",
        default=None,
        help="Where to save the ASan report. Defaults to crash_path + '.log'.",
    )
    repro.set_defaults(func=repro_crash)

    ##########################
    # Subcommand: minimize_crash
    ##########################

    min_crash = subparsers.add_parser(
        "minimize_crash",
        help="Shrink a saved crash file to the smallest input that still triggers the same bug.",
    )
    min_crash.add_argument("name", type=fuzzer_name, help="Fuzzer to minimize the crash with.")
    min_crash.add_argument(
        "crash_path", help="Path to the crash file, e.g. cgltf_fuzz/crashes/crash-<hash>."
    )
    min_crash.add_argument(
        "--output",
        default=None,
        help="Where to write the minimized input. Defaults to crash_path + '.min'.",
    )
    min_crash.add_argument(
        "--time",
        type=int,
        default=10,
        help="Stop after this many seconds without finding new minimizations (libFuzzer -max_total_time). Default: 10.",
    )
    min_crash.set_defaults(func=minimize_crash)

    ########################
    # Subcommand: triage_crash
    ########################

    triage = subparsers.add_parser(
        "triage_crash",
        help="Reproduce, minimize, reproduce the minimized input, and confirm both hit the same bug.",
    )
    triage.add_argument("name", type=fuzzer_name, help="Fuzzer to triage the crash with.")
    triage.add_argument(
        "crash_path", help="Path to the crash file, e.g. cgltf_fuzz/crashes/crash-<hash>."
    )
    triage.add_argument(
        "--output",
        default=None,
        help="Where to write the minimized input. Defaults to crash_path + '.min'.",
    )
    triage.add_argument(
        "--time",
        type=int,
        default=10,
        help="Stop minimizing after this many seconds without finding new minimizations (libFuzzer -max_total_time). Default: 10.",
    )
    triage.set_defaults(func=triage_crash)

    ########################
    # Subcommand: dedupe_crashes
    ########################

    dedupe = subparsers.add_parser(
        "dedupe_crashes",
        help="Delete other saved crashes that are exact duplicates of crash_path's bug.",
    )
    dedupe.add_argument("name", type=fuzzer_name, help="Fuzzer whose crashes/ directory to dedupe.")
    dedupe.add_argument(
        "crash_path", help="Path to the reference crash file, e.g. cgltf_fuzz/crashes/crash-<hash>."
    )
    dedupe.set_defaults(func=dedupe_crashes)

    ##############################
    # Subcommand: extract_glb_json
    ##############################

    extract = subparsers.add_parser(
        "extract_glb_json",
        help="Pull the JSON chunk out of a binary glTF (.glb) crash file for safe hand-editing.",
    )
    extract.add_argument(
        "glb_path", help="Path to the .glb file, e.g. a saved crash or its minimized input."
    )
    extract.add_argument(
        "--output",
        default=None,
        help="Where to write the extracted JSON. Defaults to glb_path + '.json'.",
    )
    extract.set_defaults(func=extract_glb_json)

    ########################
    # Subcommand: build_fuzzer
    ########################

    build_fuzz = subparsers.add_parser(
        "build_fuzzer",
        help="Compile harness.c with libFuzzer + ASan into build/<name>_fuzzer.",
    )
    build_fuzz.add_argument("name", type=fuzzer_name, help="Fuzzer to build.")
    build_fuzz.set_defaults(func=build_fuzzer)

    ##########################
    # Subcommand: build_coverage
    ##########################

    build_cov = subparsers.add_parser(
        "build_coverage",
        help="Compile harness.c with coverage instrumentation into build/<name>_fuzzer_coverage.",
    )
    build_cov.add_argument("name", type=fuzzer_name, help="Fuzzer to build.")
    build_cov.set_defaults(func=build_coverage)

    ###########################
    # Subcommand: coverage_report
    ###########################

    cov_report = subparsers.add_parser(
        "coverage_report",
        help="Replay a corpus through the coverage binary and render an HTML report.",
    )
    cov_report.add_argument("name", type=fuzzer_name, help="Fuzzer to report coverage for.")
    cov_report.add_argument(
        "--corpus",
        default=None,
        help="Corpus directory to replay. Defaults to fuzzer_dir/seed_corpus.",
    )
    cov_report.set_defaults(func=coverage_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
