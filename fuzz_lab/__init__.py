"""Command-line tooling for running libFuzzer/ASan campaigns against a C library.

The modules here are layered, each one depending only on the ones below it:

    cli             argparse wiring; the only module that reads a command line
    fuzzer          Fuzzer facade: owns a fuzzer directory and its fuzzer.json
    build           corpus          run_fuzzer      coverage_report     glb
    fuzzer_config   git_repo
    proc            subprocess wrapper every external command goes through

Nothing below `fuzzer` imports it back, so each stage (fetch sources, build a
target, fuzz it, analyse a crash) can be used on its own.
"""
