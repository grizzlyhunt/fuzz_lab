import json
import os
from dataclasses import asdict, dataclass, field

from .corpus import CorpusSource
from .git_repo import SourceRepo

CONFIG_FILENAME = "fuzzer.json"
_CONFIG_VERSION = 1

@dataclass
class FuzzerConfig:
    name: str
    source_repos: list[SourceRepo] = field(default_factory=list)
    corpus_sources: list[CorpusSource] = field(default_factory=list)

    @classmethod
    def load(cls, fuzzer_dir):
        path = os.path.join(fuzzer_dir, CONFIG_FILENAME)
        try:
            with open(path) as config:
                data = json.load(config)
        except FileNotFoundError:
            raise SystemExit(f"{path} not found: {fuzzer_dir} is not a fuzzer directory")
        except json.JSONDecodeError as err:
            raise SystemExit(f"{path} is not valid JSON: {err}")

        if data.get("version") != _CONFIG_VERSION:
            raise SystemExit(f"{path}: unsupported config version {data.get('version')!r}")

        return cls(
            name=data["name"],
            source_repos=[SourceRepo(**repo) for repo in data.get("source_repos", [])],
            corpus_sources=[CorpusSource(**source) for source in data.get("corpus_sources", [])],
        )

    def save(self, fuzzer_dir):
        path = os.path.join(fuzzer_dir, CONFIG_FILENAME)
        data = {
            "version": _CONFIG_VERSION,
            "name": self.name,
            "source_repos": [asdict(repo) for repo in self.source_repos],
            "corpus_sources": [asdict(source) for source in self.corpus_sources],
        }
        # Write through a temp file so an interrupted save cannot truncate the config.
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w") as config:
            json.dump(data, config, indent=2)
            config.write("\n")
        os.replace(tmp_path, path)