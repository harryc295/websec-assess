"""Small built-in wordlists, swappable for a custom file via config/CLI.

Lists are intentionally short (tens to ~150 entries): the default profiles
should run fast and stay polite to the target. Point a plugin at a bigger
list explicitly (env var or future config field) when a deep engagement
calls for it -- that's a config value, not new code.
"""
from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path


@lru_cache(maxsize=None)
def load_wordlist(name: str, custom_path: str | None = None) -> tuple[str, ...]:
    if custom_path:
        lines = Path(custom_path).read_text(encoding="utf-8").splitlines()
    else:
        text = resources.files("websec_assess.data").joinpath(name).read_text(encoding="utf-8")
        lines = text.splitlines()
    return tuple(line.strip() for line in lines if line.strip() and not line.startswith("#"))
