import os
import shutil

from build import build_coverage_target, build_fuzz_target, coverage_target_path, fuzz_target_path
from corpus import CorpusSource, minimize_corpus, sync_corpus_source
from coverage_report import generate_coverage_report
from fuzzer_config import FuzzerConfig
from git_repo import checkout_repo
from run_fuzzer import dedupe_crashes, minimize_crash, reproduce_crash, run_fuzz_target, triage_crash

_HARNESS_TEMPLATE = """\
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    return 0;
}
"""


def fuzzer_dir_for(name, root="."):
    return os.path.join(root, f"{name}_fuzz")


class Fuzzer:

    def __init__(self, fuzzer_dir, config):
        self.fuzzer_dir = fuzzer_dir
        self.config = config

    @classmethod
    def create(cls, name, root="."):
        fuzzer_dir = fuzzer_dir_for(name, root)
        if os.path.exists(fuzzer_dir):
            raise SystemExit(f"{fuzzer_dir} already exists.")

        os.makedirs(fuzzer_dir)
        fuzzer = cls(fuzzer_dir, FuzzerConfig(name=name))
        fuzzer.config.save(fuzzer_dir)
        print(f"{fuzzer.config_path} created.")

        with open(fuzzer.harness_path, "w") as harness:
            harness.write(_HARNESS_TEMPLATE)
        print(f"{fuzzer.harness_path} placeholder harness created.")

        open(fuzzer.dictionary_path, "w").close()
        print(f"{fuzzer.dictionary_path} empty dictionary created.")

        return fuzzer

    @classmethod
    def load(cls, name, root="."):
        fuzzer_dir = fuzzer_dir_for(name, root)
        return cls(fuzzer_dir, FuzzerConfig.load(fuzzer_dir))

    @property
    def harness_path(self):
        return os.path.join(self.fuzzer_dir, "harness.c")

    @property
    def config_path(self):
        return os.path.join(self.fuzzer_dir, "fuzzer.json")

    @property
    def dictionary_path(self):
        return os.path.join(self.fuzzer_dir, "dictionary.dict")

    def add_repo(self, repo):
        if any(existing.name == repo.name for existing in self.config.source_repos):
            raise SystemExit(f"{repo.name} is already a source repo of {self.config.name}")
        self.config.source_repos.append(repo)
        self.config.save(self.fuzzer_dir)

    def remove_repo(self, repo_name):
        """Remove a repo from the config. Does NOT touch the filesystem.

        The matching checkout directory, if any, is only deleted the next time
        prepare_repos() runs. Mirrors add_repo (config-only, no cloning): each
        subcommand does exactly one kind of thing, either edit fuzzer.json or
        touch the filesystem, never both.
        """
        repos_before = self.config.source_repos
        self.config.source_repos = [repo for repo in repos_before if repo.name != repo_name]
        if len(self.config.source_repos) == len(repos_before):
            raise SystemExit(f"{repo_name} is not a source repo of {self.config.name}")
        self.config.save(self.fuzzer_dir)

    def prepare_repos(self):
        """Reconcile the checkouts on disk with what fuzzer.json currently lists.

        Two situations can be out of sync with the config, and we handle both:
        - A repo is listed but not checked out yet (or is, and might be stale)
          -> checkout_repo() clones it if missing, pulls it otherwise.
        - A directory sits on disk but is no longer listed (e.g. after a
          `remove_repo` call, or a hand-edited fuzzer.json) -> we delete it, so
          leftover checkouts never linger silently out of sync with the config.
        """
        configured_names = {repo.name for repo in self.config.source_repos}

        # --- Drop checkouts that are no longer in the config. ---
        for entry_name in os.listdir(self.fuzzer_dir):
            if entry_name in configured_names:
                continue

            entry_path = os.path.join(self.fuzzer_dir, entry_name)
            # Only remove directories that look like a git checkout we made
            # ourselves (they contain a ".git" entry). This is a safety guard:
            # it stops us from ever deleting harness.c, fuzzer.json, or some
            # unrelated directory a human created by hand in the fuzzer dir.
            if not os.path.isdir(os.path.join(entry_path, ".git")):
                continue

            print(f"{entry_path} is no longer configured. Removing checkout...")
            shutil.rmtree(entry_path)

        # --- Clone repos that are missing, pull the ones that already exist. ---
        for repo in self.config.source_repos:
            checkout_repo(repo, self.fuzzer_dir)

    def add_corpus_source(self, repo_name, extensions):
        """Register repo_name (with its extensions) as a base-corpus source.

        repo_name must already be a source repo (added via add_repo): prepare_corpus
        reads files from that repo's checkout under the fuzzer directory, so a corpus
        source with no matching checkout would have nothing to sync from.
        """
        if not any(repo.name == repo_name for repo in self.config.source_repos):
            raise SystemExit(
                f"{repo_name} is not a source repo of {self.config.name}. Add it with add_repo first."
            )
        if any(source.repo_name == repo_name for source in self.config.corpus_sources):
            raise SystemExit(f"{repo_name} is already a corpus source of {self.config.name}")
        self.config.corpus_sources.append(CorpusSource(repo_name, extensions))
        self.config.save(self.fuzzer_dir)

    def edit_corpus_source(self, repo_name, extensions):
        """Replace the extension list of an existing corpus source."""
        for source in self.config.corpus_sources:
            if source.repo_name == repo_name:
                source.extensions = extensions
                self.config.save(self.fuzzer_dir)
                return
        raise SystemExit(f"{repo_name} is not a corpus source of {self.config.name}")

    def remove_corpus_source(self, repo_name):
        """Remove a corpus source from the config. Does NOT touch the filesystem.

        Mirrors remove_repo: the matching seed_corpus/<repo_name>__* files, if any,
        are only deleted the next time prepare_corpus() runs.
        """
        sources_before = self.config.corpus_sources
        self.config.corpus_sources = [
            source for source in sources_before if source.repo_name != repo_name
        ]
        if len(self.config.corpus_sources) == len(sources_before):
            raise SystemExit(f"{repo_name} is not a corpus source of {self.config.name}")
        self.config.save(self.fuzzer_dir)

    def prepare_corpus(self):
        """Reconcile fuzzer_dir/seed_corpus with what fuzzer.json currently lists as corpus sources.

        seed_corpus/ is a fully managed directory: its contents are defined entirely by
        the configured corpus sources, so anything no source owns is removed -- stale
        prefixes from a source that was dropped, leftover subdirectories, and files added
        by hand alike. Keep hand-picked inputs outside seed_corpus/ (they can be fuzzed by
        pointing run_fuzzer --corpus at their own directory).

        seed_corpus/ is flat: every file is named "<repo_name>__<...>" (see corpus.py),
        so a repo no longer configured is identified by that prefix rather than
        by a subdirectory. Mirrors prepare_repos(): drops what is no longer
        configured, then resyncs each source that still is. Requires
        prepare_repos() to have been run first, since it reads files from the
        repo checkouts under the fuzzer directory.
        """
        corpus_dir = os.path.join(self.fuzzer_dir, "seed_corpus")
        os.makedirs(corpus_dir, exist_ok=True)

        configured_names = {source.repo_name for source in self.config.corpus_sources}
        for entry_name in os.listdir(corpus_dir):
            entry_path = os.path.join(corpus_dir, entry_name)
            if os.path.isdir(entry_path):
                # sync_corpus_source() only ever creates flat files directly in
                # seed_corpus/, so any directory here is stale: left over from before
                # seed_corpus/ was flattened, or created by hand. Always drop it.
                shutil.rmtree(entry_path)
                continue
            repo_name = entry_name.split("__", 1)[0]
            if repo_name not in configured_names:
                os.remove(entry_path)

        for source in self.config.corpus_sources:
            sync_corpus_source(source, self.fuzzer_dir)

    def build_fuzz_target(self):
        """Compile harness.c into a libFuzzer+ASan binary under build/."""
        return build_fuzz_target(self.config.name, self.fuzzer_dir, self.config.source_repos)

    def build_coverage_target(self):
        """Compile harness.c with coverage instrumentation into a binary under build/."""
        return build_coverage_target(self.config.name, self.fuzzer_dir, self.config.source_repos)

    def minimize_corpus(self):
        """Shrink seed_corpus/ down to a subset with equivalent coverage, into min_corpus/.

        Requires build_fuzz_target() to have already produced the fuzzer binary.
        """
        binary_path = fuzz_target_path(self.config.name, self.fuzzer_dir)
        return minimize_corpus(binary_path, self.fuzzer_dir)

    def generate_coverage_report(self, corpus_dir=None):
        """Replay a corpus through the coverage binary and render an HTML report under coverage/report.

        corpus_dir defaults to fuzzer_dir/seed_corpus. Requires
        build_coverage_target() to have already produced the coverage binary.
        """
        if corpus_dir is None:
            corpus_dir = os.path.join(self.fuzzer_dir, "seed_corpus")
        binary_path = coverage_target_path(self.config.name, self.fuzzer_dir)
        return generate_coverage_report(binary_path, corpus_dir, self.fuzzer_dir)

    def run_fuzz_target(self, corpus_dir=None, extra_args=None):
        """Launch the fuzz binary against a corpus (default: seed_corpus/), growing it in place.

        Passes -dict=dictionary_path ahead of extra_args whenever the file has content,
        so callers never need to remember to wire it in by hand; editing dictionary_path's
        content is enough to change what gets used. The file is created empty if missing
        (e.g. a fuzzer scaffolded before dictionary_path existed), and -dict is omitted
        in that case: libFuzzer errors out ("file does not exist or is empty") on an
        empty -dict file instead of treating it as zero entries.

        Requires build_fuzz_target() to have already produced the fuzzer binary.
        """
        if corpus_dir is None:
            corpus_dir = os.path.join(self.fuzzer_dir, "seed_corpus")
        if not os.path.isfile(self.dictionary_path):
            open(self.dictionary_path, "w").close()
        binary_path = fuzz_target_path(self.config.name, self.fuzzer_dir)
        dict_args = (
            [f"-dict={self.dictionary_path}"]
            if os.path.getsize(self.dictionary_path) > 0
            else []
        )
        args = [*dict_args, *(extra_args or [])]
        return run_fuzz_target(binary_path, corpus_dir, self.fuzzer_dir, args)

    def reproduce_crash(self, crash_path, output_path=None):
        """Replay a single saved crash file (e.g. fuzzer_dir/crashes/crash-<hash>) against the fuzz binary.

        Requires build_fuzz_target() to have already produced the fuzzer binary.
        """
        binary_path = fuzz_target_path(self.config.name, self.fuzzer_dir)
        return reproduce_crash(binary_path, crash_path, output_path)

    def minimize_crash(self, crash_path, output_path=None, extra_args=None):
        """Shrink crash_path to the smallest input that still triggers the same bug.

        Requires build_fuzz_target() to have already produced the fuzzer binary.
        """
        binary_path = fuzz_target_path(self.config.name, self.fuzzer_dir)
        return minimize_crash(binary_path, crash_path, output_path, extra_args)

    def triage_crash(self, crash_path, min_output_path=None, extra_args=None):
        """Reproduce, minimize, reproduce the minimized input, and confirm both hit the same bug.

        Requires build_fuzz_target() to have already produced the fuzzer binary.
        """
        binary_path = fuzz_target_path(self.config.name, self.fuzzer_dir)
        return triage_crash(binary_path, crash_path, min_output_path, extra_args)

    def dedupe_crashes(self, crash_path):
        """Reproduce crash_path (if needed) and every other crash under crashes/, deleting exact duplicates.

        Requires build_fuzz_target() to have already produced the fuzzer binary.
        """
        binary_path = fuzz_target_path(self.config.name, self.fuzzer_dir)
        return dedupe_crashes(binary_path, crash_path, self.fuzzer_dir)