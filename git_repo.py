import os
from dataclasses import dataclass

from proc import run

__all__ = ["SourceRepo", "checkout_repo"]


@dataclass(frozen=True)
class SourceRepo:
    name: str
    url: str
    depth: int | None = None  # None keeps the full history.


def checkout_repo(repo, parent_dir):
    """Clone the repo under parent_dir, or pull it if it is already there."""
    repo_dir = os.path.join(parent_dir, repo.name)

    # Fail right away instead of prompting for credentials when the repo is unreachable.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    depth_args = ["--depth", str(repo.depth)] if repo.depth else []

    if not os.path.exists(repo_dir):
        print(f"Cloning {repo.name} repository...")
        result = run(["git", "clone", *depth_args, repo.url, repo_dir], env=env)
    else:
        print(f"{repo.name} repository already exists. Pulling latest changes...")
        result = run(["git", "-C", repo_dir, "pull", *depth_args], env=env)

    if result.returncode != 0:
        raise SystemExit(f"git exited with code {result.returncode}: {repo.name} checkout failed")

    print(f"{repo.name} repository is ready.")