import os
import shutil
from dataclasses import dataclass

from .proc import run

__all__ = ["CorpusSource", "sync_corpus_source", "minimize_corpus"]


@dataclass
class CorpusSource:
    repo_name: str
    extensions: list[str]


def source_prefix(repo_name):
    return f"{repo_name}__"


def sync_corpus_source(source, fuzzer_dir):
    """Copy files matching source.extensions from its repo checkout into seed_corpus/, flattened.

    Every file lands directly at the root of seed_corpus/ (no subdirectories), named
    "<repo_name>__<relative_path_with_double_underscores>". The prefix keeps
    files from different repos apart; folding the relative path into the name
    keeps files that share a basename within one repo apart too. This source
    owns every seed_corpus/ file starting with its prefix: that set is wiped and
    recopied on every call, so files removed or renamed upstream do not linger
    as stale corpus entries.

    Deletions stop at that prefix because a single source cannot know which other
    sources are configured. seed_corpus/ is nonetheless a fully managed directory:
    removing entries that no configured source owns -- including files added by hand --
    belongs to Fuzzer.prepare_corpus(), which is the only caller and the only place
    with the whole configuration in view.
    """
    repo_checkout = os.path.join(fuzzer_dir, source.repo_name)
    if not os.path.isdir(repo_checkout):
        raise SystemExit(f"{repo_checkout} does not exist. Run prepare_repos first.")

    dest_dir = os.path.join(fuzzer_dir, "seed_corpus")
    os.makedirs(dest_dir, exist_ok=True)
    prefix = source_prefix(source.repo_name)

    for filename in os.listdir(dest_dir):
        if filename.startswith(prefix):
            os.remove(os.path.join(dest_dir, filename))

    extensions = {ext.lower() for ext in source.extensions}
    copied = 0
    for root, dirs, files in os.walk(repo_checkout):
        dirs[:] = [d for d in dirs if d != ".git"]
        for filename in files:
            if os.path.splitext(filename)[1].lower() not in extensions:
                continue
            src_path = os.path.join(root, filename)
            rel_path = os.path.relpath(src_path, repo_checkout)
            flat_name = prefix + rel_path.replace(os.sep, "__")
            shutil.copy2(src_path, os.path.join(dest_dir, flat_name))
            copied += 1

    print(f"{source.repo_name}: {copied} file(s) synced to {dest_dir}.")
    return copied


def minimize_corpus(binary_path, fuzzer_dir):
    """Shrink seed_corpus/ down to a subset that keeps the same coverage, via libFuzzer's -merge=1.

    Written to fuzzer_dir/min_corpus (wiped and recreated on every call) rather
    than overwriting seed_corpus/ itself: libFuzzer's -merge mode refuses to write
    into a directory it is also reading input from, and prepare_corpus() would
    resync seed_corpus/ from the configured sources on its next run anyway, undoing
    any in-place minimization.
    """
    if not os.path.isfile(binary_path):
        raise SystemExit(f"{binary_path} not found. Run build_fuzzer first.")

    corpus_dir = os.path.join(fuzzer_dir, "seed_corpus")
    if not os.path.isdir(corpus_dir):
        raise SystemExit(f"{corpus_dir} not found. Run prepare_corpus first.")

    output_dir = os.path.join(fuzzer_dir, "min_corpus")
    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    result = run([binary_path, "-merge=1", output_dir, corpus_dir])
    if result.returncode != 0:
        raise SystemExit(f"{binary_path} exited with code {result.returncode}: minimize failed")

    kept = len(os.listdir(output_dir))
    print(f"{kept} file(s) kept in {output_dir}.")
    return output_dir
