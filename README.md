# fuzz_lab

Command-line tooling that wraps the repetitive parts of a libFuzzer + AddressSanitizer
campaign against a C library: fetching the target's sources, building an instrumented
harness, keeping a seed corpus in sync, running the fuzzer, and triaging the crashes it
finds.

> **Scope and status.** This is a learning project — I built it to teach myself the
> practical side of fuzzing and vulnerability research, and it is shaped by what that
> workflow needs rather than by what a production fuzzing platform would need. It is
> currently only exercised against [cgltf](https://github.com/jkuhlmann/cgltf), so treat
> support for any other library as untested rather than unsupported: nothing in the
> design is cgltf-specific (see [Using it on another library](#using-it-on-another-library)),
> that is simply the only target it has been run against so far.
>
> It was written with the help of [Claude](https://claude.ai).

## Requirements

- Python 3 (no third-party runtime dependencies)
- `clang` with libFuzzer and sanitizer support
- `git`, for fetching target sources and corpus repositories
- `llvm-profdata` and `llvm-cov`, only for the coverage report

## Getting started

Everything goes through `cli.py`:

```sh
python3 cli.py --help
```

Each fuzzer lives in its own `<name>_fuzz/` directory, created for you and holding the
harness, the config, the corpus, the built binaries and the crashes. A full run looks
like this:

```sh
# 1. Scaffold <name>_fuzz/ with a placeholder harness.c, fuzzer.json and dictionary.dict
python3 cli.py create_fuzzer cgltf

# 2. Register the library's sources, then check them out
python3 cli.py add_repo cgltf cgltf https://github.com/jkuhlmann/cgltf.git --depth 1
python3 cli.py prepare_repos cgltf

# 3. Write the harness: edit cgltf_fuzz/harness.c so LLVMFuzzerTestOneInput()
#    feeds the fuzzer's bytes into the API you want to exercise.

# 4. Seed the corpus from files already in a repository, by extension
python3 cli.py add_repo cgltf assets https://github.com/KhronosGroup/glTF-Sample-Assets.git --depth 1
python3 cli.py prepare_repos cgltf
python3 cli.py add_corpus_source cgltf assets gltf glb
python3 cli.py prepare_corpus cgltf

# 5. Build and fuzz
python3 cli.py build_fuzzer cgltf
python3 cli.py run_fuzzer cgltf --time 300
```

Crashing inputs are saved under `cgltf_fuzz/crashes/`.

## Triaging a crash

```sh
# Replay one crash and save its ASan report next to it
python3 cli.py repro_crash cgltf cgltf_fuzz/crashes/crash-<hash>

# Reproduce, shrink, re-reproduce, and confirm both hit the same bug
python3 cli.py triage_crash cgltf cgltf_fuzz/crashes/crash-<hash>

# Delete the other saved crashes that are the same bug as this one
python3 cli.py dedupe_crashes cgltf cgltf_fuzz/crashes/crash-<hash>
```

Deduplication compares the `file:line` frames of the crash stack rather than function
names alone, so two different call sites that end in the same function are kept apart.

## Corpus and coverage

```sh
# Shrink seed_corpus/ to a coverage-equivalent subset, written to min_corpus/
python3 cli.py minimize_corpus cgltf

# Build an instrumented binary and render an HTML line-coverage report
python3 cli.py build_coverage cgltf
python3 cli.py coverage_report cgltf --corpus cgltf_fuzz/min_corpus
```

## Using it on another library

The tooling never hardcodes a target: the library, its corpus sources and the code under
test all come from `fuzzer.json` and from the harness you write. Pointing it at something
else means running `create_fuzzer` with a new name, `add_repo` with that project's URL,
and writing its `harness.c`.

Two things are worth knowing before you do:

- **`extract_glb_json` is glTF-specific.** It pulls the JSON chunk out of a binary `.glb`
  so a crash file can be hand-edited as text. Every other subcommand is format-agnostic.
- **The corpus model assumes seed files live in a git repository** and are selected by
  file extension. A target whose inputs have to be generated instead of collected would
  need a different `prepare_corpus`.

## Development

```sh
./run_tests.sh              # full suite with a coverage summary
./run_tests.sh -k dedupe    # one topic
```

The suite mocks every external command, so it never invokes `clang`, `git` or a fuzz
binary, and never touches the network.

```
cli.py            entry point; a thin wrapper around fuzz_lab.cli
fuzz_lab/
  cli.py          argparse wiring, the only module that reads a command line
  fuzzer.py       Fuzzer facade: owns a fuzzer directory and its fuzzer.json
  fuzzer_config.py  reads/writes fuzzer.json
  git_repo.py     cloning and pulling source repositories
  corpus.py       seed corpus syncing and minimization
  build.py        clang invocations for the fuzz and coverage binaries
  run_fuzzer.py   running the fuzzer, and reproducing/minimizing/deduping crashes
  coverage_report.py  llvm-profdata/llvm-cov reporting
  glb.py          glTF .glb chunk extraction
  proc.py         the subprocess wrapper every external command goes through
tests/            unit tests, one module per fuzz_lab module
```
