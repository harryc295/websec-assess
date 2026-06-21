"""Shared parameter-mutation helpers for the injection-indicator plugins.
Every plugin in this package finds parameterised URLs the same way and
mutates them the same way -- only the payload and the detection differ."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from websec_assess.core.plugin import PluginContext

BUDGET = {"quick": 5, "standard": 20, "deep": 60}


def budget_for(ctx: PluginContext) -> int:
    return BUDGET.get(ctx.profile.value, 20)


def candidate_params(ctx: PluginContext, limit: int) -> list[tuple[str, str, str, dict[str, str]]]:
    """[(base_url_without_query, param_name, original_value, all_params), ...]"""
    candidates: list[tuple[str, str, str, dict[str, str]]] = []
    seen: set[tuple[str, str]] = set()
    for url in ctx.state.urls:
        parts = urlsplit(url)
        if not parts.query:
            continue
        params = dict(parse_qsl(parts.query))
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        for name, value in params.items():
            key = (base, name)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((base, name, value, params))
            if len(candidates) >= limit:
                return candidates
    return candidates


def build_url(base: str, params: dict[str, str], override_name: str, override_value: str) -> str:
    new_params = dict(params)
    new_params[override_name] = override_value
    return f"{base}?{urlencode(new_params)}"
