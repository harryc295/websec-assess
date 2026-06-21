from __future__ import annotations

import argparse
import asyncio
import sys
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from websec_assess.cli.console import console, err_console, print_plugins_table, print_scan_summary, print_scans_table
from websec_assess.core.config import AppConfig
from websec_assess.core.db.engine import make_engine, make_session_factory
from websec_assess.core.db.repository import Repository
from websec_assess.core.logging import configure_logging
from websec_assess.core.models import ScanProfile, Target
from websec_assess.core.plugin import PluginRegistry
from websec_assess.core.queue import Scheduler
from websec_assess.core.reporting import render_html, render_json, render_markdown
from websec_assess.core.safety import AuthorizationError, ScopeError

_RENDERERS = {"json": render_json, "markdown": render_markdown, "html": render_html}
_EXTENSIONS = {"json": "json", "markdown": "md", "html": "html"}


def make_target(raw: str) -> Target:
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlsplit(candidate)
    if not parsed.hostname:
        raise ValueError(f"Could not parse a target host from '{raw}'")
    return Target(base_url=f"{parsed.scheme}://{parsed.netloc}", host=parsed.hostname)


@contextmanager
def open_repository(config: AppConfig):
    engine = make_engine(config.database.url)
    session = make_session_factory(engine)()
    try:
        yield Repository(session)
    finally:
        session.close()


def write_reports(repo: Repository, scan_id: str, formats: list[str], output_dir: Path) -> list[Path]:
    scan = repo.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"No such scan: {scan_id}")
    findings = repo.list_findings(scan_id)
    assets = repo.list_assets(scan_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in formats:
        content = _RENDERERS[fmt](scan, findings, assets)
        path = output_dir / f"{scan_id}.{_EXTENSIONS[fmt]}"
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.output)
    if path.exists() and not args.force:
        err_console.print(f"[red]{path} already exists.[/] Use --force to overwrite.")
        return 1
    allowed_hosts = [args.target] if args.target else []
    content = f"""\
# websec-assess configuration. See SECURITY.md before changing safety settings.

scope:
  allowed_hosts: {allowed_hosts!r}
  allowed_cidrs: []

rate_limit:
  requests_per_second: 5.0
  burst: 10
  concurrency: 10

safety:
  authorized: false   # set true only once you have written permission to test the hosts above
  dry_run: false
  active_injection_probes: false
  audit_log_path: audit.log

database:
  url: sqlite:///websec_assess.db

scan:
  profile: standard
  output_dir: ./reports
  timeout_seconds: 10.0
"""
    path.write_text(content, encoding="utf-8")
    console.print(f"[green]Wrote config to {path}[/]. Edit scope.allowed_hosts and safety.authorized before scanning.")
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    PluginRegistry.discover()
    plugins = PluginRegistry.all()
    if args.category:
        plugins = [p for p in plugins if p.category == args.category]
    print_plugins_table(plugins)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    configure_logging(level=args.log_level)
    config = AppConfig.load(args.config)
    if args.dry_run:
        config.safety.dry_run = True
    if args.target not in config.scope.allowed_hosts:
        config.scope.allowed_hosts.append(make_target(args.target).host)

    PluginRegistry.discover()
    profile = ScanProfile(args.profile)
    plugin_names = args.plugins.split(",") if args.plugins else None

    try:
        target = make_target(args.target)
        from websec_assess.core.safety import require_authorization

        require_authorization(config, cli_flag=args.i_have_authorization)
    except (ValueError, AuthorizationError) as exc:
        err_console.print(f"[red]{exc}[/]")
        return 1

    with open_repository(config) as repo:
        scheduler = Scheduler(config, repo)
        try:
            scan = asyncio.run(scheduler.run_scan(target, profile, plugin_names))
        except ScopeError as exc:
            err_console.print(f"[red]{exc}[/]")
            return 1

        findings = repo.list_findings(scan.id)
        assets = repo.list_assets(scan.id)
        print_scan_summary(scan, findings, assets)

        formats = args.format.split(",") if args.format else ["json"]
        written = write_reports(repo, scan.id, formats, Path(config.scan.output_dir))
        for path in written:
            console.print(f"Report written: [bold]{path}[/]")
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    configure_logging(level=args.log_level)
    config = AppConfig.load(args.config)
    PluginRegistry.discover()
    with open_repository(config) as repo:
        scheduler = Scheduler(config, repo)
        scan = asyncio.run(scheduler.resume_scan(args.scan_id))
        findings = repo.list_findings(scan.id)
        assets = repo.list_assets(scan.id)
        print_scan_summary(scan, findings, assets)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    config = AppConfig.load(args.config)
    with open_repository(config) as repo:
        formats = args.format.split(",")
        written = write_reports(repo, args.scan_id, formats, Path(args.output_dir or config.scan.output_dir))
        for path in written:
            console.print(f"Report written: [bold]{path}[/]")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    config = AppConfig.load(args.config)
    with open_repository(config) as repo:
        print_scans_table(repo.list_scans())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="websec-assess", description="Modular web application security assessment platform.")
    parser.add_argument("--config", "-c", help="Path to YAML config file", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Write a starter config file")
    p_init.add_argument("--output", "-o", default="websec-assess.yaml")
    p_init.add_argument("--target", help="Host to pre-populate scope.allowed_hosts with")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_plugins = sub.add_parser("plugins", help="List registered plugins")
    p_plugins.add_argument("--category")
    p_plugins.set_defaults(func=cmd_plugins)

    p_scan = sub.add_parser("scan", help="Run a scan against a target")
    p_scan.add_argument("target", help="Base URL or hostname to scan")
    p_scan.add_argument("--profile", choices=[p.value for p in ScanProfile], default="standard")
    p_scan.add_argument("--plugins", help="Comma-separated plugin names to run instead of the full profile")
    p_scan.add_argument("--format", default="json,markdown,html", help="Comma-separated: json,markdown,html")
    p_scan.add_argument("--dry-run", action="store_true")
    p_scan.add_argument("--i-have-authorization", action="store_true", help="Confirm you are authorised to test this target")
    p_scan.add_argument("--log-level", default="INFO")
    p_scan.set_defaults(func=cmd_scan)

    p_resume = sub.add_parser("resume", help="Resume an interrupted scan")
    p_resume.add_argument("scan_id")
    p_resume.add_argument("--log-level", default="INFO")
    p_resume.set_defaults(func=cmd_resume)

    p_report = sub.add_parser("report", help="(Re-)generate reports for a past scan")
    p_report.add_argument("scan_id")
    p_report.add_argument("--format", default="html")
    p_report.add_argument("--output-dir")
    p_report.set_defaults(func=cmd_report)

    p_list = sub.add_parser("list", help="List past scans")
    p_list.set_defaults(func=cmd_list)

    return parser


def _force_utf8_streams() -> None:
    """Windows consoles often default to a legacy codepage (cp1252/cp437),
    which mangles rich's box-drawing/ellipsis characters. Forcing UTF-8 here
    makes output identical across Windows Terminal, cmd.exe, and Linux/macOS
    terminals."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _force_utf8_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        err_console.print("[yellow]Interrupted.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
