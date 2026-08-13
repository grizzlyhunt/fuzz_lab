"""Unit tests for fuzzer_config.py.

FuzzerConfig is the on-disk contract for a fuzzer directory: every CLI subcommand starts
by loading it, and several rewrite it. The tests below cover the round trip, the atomic
write, and each way loading is expected to refuse a file it cannot trust.
"""

import json
import os

import pytest

from corpus import CorpusSource
from fuzzer_config import CONFIG_FILENAME, FuzzerConfig
from git_repo import SourceRepo


@pytest.fixture
def fuzzer_dir(tmp_path):
    return str(tmp_path)


def write_config(fuzzer_dir, data):
    """Write raw JSON as fuzzer.json, bypassing FuzzerConfig.save()."""
    path = os.path.join(fuzzer_dir, CONFIG_FILENAME)
    with open(path, "w") as config:
        json.dump(data, config)
    return path


class TestLoad:
    def test_refuses_a_directory_with_no_config(self, fuzzer_dir):
        with pytest.raises(SystemExit, match="is not a fuzzer directory"):
            FuzzerConfig.load(fuzzer_dir)

    def test_refuses_a_config_that_is_not_valid_json(self, fuzzer_dir):
        with open(os.path.join(fuzzer_dir, CONFIG_FILENAME), "w") as config:
            config.write("{not json")

        with pytest.raises(SystemExit, match="is not valid JSON"):
            FuzzerConfig.load(fuzzer_dir)

    def test_refuses_a_config_written_by_a_future_version(self, fuzzer_dir):
        # The version field exists so an older checkout refuses a newer layout rather
        # than silently misreading it.
        write_config(fuzzer_dir, {"version": 99, "name": "cgltf"})

        with pytest.raises(SystemExit, match="unsupported config version 99"):
            FuzzerConfig.load(fuzzer_dir)

    def test_refuses_a_config_with_no_version_at_all(self, fuzzer_dir):
        write_config(fuzzer_dir, {"name": "cgltf"})

        with pytest.raises(SystemExit, match="unsupported config version None"):
            FuzzerConfig.load(fuzzer_dir)

    def test_reads_back_the_fuzzer_name(self, fuzzer_dir):
        write_config(fuzzer_dir, {"version": 1, "name": "cgltf"})
        assert FuzzerConfig.load(fuzzer_dir).name == "cgltf"

    def test_defaults_to_empty_lists_when_the_optional_keys_are_absent(self, fuzzer_dir):
        # A freshly created fuzzer has neither repos nor corpus sources yet.
        write_config(fuzzer_dir, {"version": 1, "name": "cgltf"})
        config = FuzzerConfig.load(fuzzer_dir)

        assert config.source_repos == []
        assert config.corpus_sources == []

    def test_rebuilds_source_repos_as_dataclasses_not_dicts(self, fuzzer_dir):
        # Callers do repo.name / repo.url attribute access, so leaving these as plain
        # dicts would break every consumer.
        write_config(
            fuzzer_dir,
            {
                "version": 1,
                "name": "cgltf",
                "source_repos": [{"name": "cgltf", "url": "https://example.invalid/cgltf", "depth": 1}],
            },
        )
        (repo,) = FuzzerConfig.load(fuzzer_dir).source_repos

        assert repo == SourceRepo("cgltf", "https://example.invalid/cgltf", 1)

    def test_rebuilds_corpus_sources_as_dataclasses_not_dicts(self, fuzzer_dir):
        write_config(
            fuzzer_dir,
            {
                "version": 1,
                "name": "cgltf",
                "corpus_sources": [{"repo_name": "assets", "extensions": [".gltf"]}],
            },
        )
        (source,) = FuzzerConfig.load(fuzzer_dir).corpus_sources

        assert source == CorpusSource("assets", [".gltf"])


class TestSave:
    def test_writes_a_config_that_load_accepts(self, fuzzer_dir):
        FuzzerConfig(name="cgltf").save(fuzzer_dir)
        assert FuzzerConfig.load(fuzzer_dir).name == "cgltf"

    def test_round_trips_repos_and_corpus_sources_unchanged(self, fuzzer_dir):
        # The property that actually matters: whatever the CLI edits and saves has to
        # come back identical on the next subcommand.
        original = FuzzerConfig(
            name="cgltf",
            source_repos=[
                SourceRepo("cgltf", "https://example.invalid/cgltf", 1),
                SourceRepo("assets", "https://example.invalid/assets"),
            ],
            corpus_sources=[CorpusSource("assets", [".gltf", ".glb"])],
        )
        original.save(fuzzer_dir)

        assert FuzzerConfig.load(fuzzer_dir) == original

    def test_stamps_the_current_config_version(self, fuzzer_dir):
        FuzzerConfig(name="cgltf").save(fuzzer_dir)

        with open(os.path.join(fuzzer_dir, CONFIG_FILENAME)) as config:
            assert json.load(config)["version"] == 1

    def test_leaves_no_temp_file_behind(self, fuzzer_dir):
        # save() writes through <path>.tmp and renames; a leftover .tmp would mean the
        # rename never happened.
        FuzzerConfig(name="cgltf").save(fuzzer_dir)

        assert os.listdir(fuzzer_dir) == [CONFIG_FILENAME]

    def test_replaces_an_existing_config_rather_than_appending_to_it(self, fuzzer_dir):
        FuzzerConfig(name="cgltf", source_repos=[SourceRepo("a", "https://example.invalid/a")]).save(fuzzer_dir)
        FuzzerConfig(name="cgltf").save(fuzzer_dir)

        assert FuzzerConfig.load(fuzzer_dir).source_repos == []

    def test_writes_human_editable_json(self, fuzzer_dir):
        # fuzzer.json is meant to be readable and diffable, so it is indented and ends
        # with a newline like any other text file in the tree.
        FuzzerConfig(name="cgltf").save(fuzzer_dir)

        with open(os.path.join(fuzzer_dir, CONFIG_FILENAME)) as config:
            text = config.read()

        assert text.endswith("\n")
        assert "\n  " in text
