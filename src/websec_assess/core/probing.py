"""Shared baseline-404 path-probing helper. Used by content-discovery's
directory/file brute-force and cloud_infra's CI/CD-config probing -- same
heuristic (compare against a known-nonexistent path so custom 404 pages
don't produce false positives), different wordlists."""
from __future__ import annotations

import asyncio
import uuid
from urllib.parse import urljoin

import httpx

from websec_assess.core.plugin import PluginContext


async def baseline_404(ctx: PluginContext) -> tuple[int, int]:
    probe = urljoin(ctx.target.base_url + "/", f"__wsa_nonexistent_{uuid.uuid4().hex[:12]}__")
    resp = await ctx.http.get(probe)
    if resp is None:
        return 404, 0
    return resp.status_code, len(resp.text or "")


async def probe_paths(ctx: PluginContext, paths: list[str], concurrency: int = 20) -> list[tuple[str, httpx.Response]]:
    base_status, base_len = await baseline_404(ctx)
    semaphore = asyncio.Semaphore(concurrency)
    found: list[tuple[str, httpx.Response]] = []

    async def check(path: str) -> None:
        url = urljoin(ctx.target.base_url + "/", path.lstrip("/"))
        async with semaphore:
            resp = await ctx.http.get(url)
        if resp is None or resp.status_code == 404:
            return
        if resp.status_code == base_status and len(resp.text or "") == base_len:
            return
        found.append((path, resp))

    await asyncio.gather(*(check(p) for p in paths))
    return found
