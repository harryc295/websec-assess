from __future__ import annotations

import argparse
import asyncio
import sys
import webbrowser
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt

from websec_assess.cli.console import (
    console,
    err_console,
    print_commands_overview,
    print_guide,
    print_plugins_table,
    print_scan_summary,
    print_scans_table,
)
from websec_assess.core.config import AppConfig
from websec_assess.core.db.engine import make_engine, make_session_factory
from websec_assess.core.db.repository import Repository
from websec_assess.core.logging import configure_logging
from websec_assess.core.models import ScanProfile, Target
from websec_assess.core.plugin import Plugin, PluginRegistry
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


def resolve_scan_id(repo: Repository, id_or_prefix: str) -> str:
    """Accepts a full scan ID or an unambiguous prefix -- every place this
    tool prints a scan ID (the summary table, `list`) shows only the first 8
    characters, so that's what needs to actually work when pasted back in."""
    if repo.get_scan(id_or_prefix) is not None:
        return id_or_prefix
    matches = [s.id for s in repo.list_scans() if s.id.startswith(id_or_prefix)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError(f"No scan found matching '{id_or_prefix}'")
    raise ValueError(f"'{id_or_prefix}' matches {len(matches)} scans -- use a longer prefix")


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


_DEPTH_TO_PROFILE = {"light": "quick", "full": "standard", "everything": "deep"}


def expand_plugin_selection(entries: list[str], all_plugins: list[type[Plugin]]) -> tuple[list[str], list[str]]:
    """Each entry can be a category (e.g. 'recon') or an exact plugin name
    (e.g. 'recon.dns_enum'); categories expand to every plugin in them."""
    categories = {p.category for p in all_plugins}
    names = {p.name for p in all_plugins}
    selected: set[str] = set()
    unknown: list[str] = []
    for raw in entries:
        entry = raw.strip()
        if not entry:
            continue
        if entry in categories:
            selected |= {p.name for p in all_plugins if p.category == entry}
        elif entry in names:
            selected.add(entry)
        else:
            unknown.append(entry)
    return sorted(selected), unknown


def _interactive_scan_setup(args: argparse.Namespace, config: AppConfig) -> bool:
    """Walks through target/depth/tool-selection with prompts instead of
    requiring flags up front -- triggered by running `scan` with no target.
    Mutates `config` (rate limit, active_injection_probes) in place since
    those aren't argparse fields. Returns False if the user backs out (e.g.
    won't confirm authorisation). See `websec-assess guide` for what each
    choice here actually means."""
    console.print("[bold cyan]Interactive scan setup[/]  [dim](run `websec-assess guide` for an explanation of these choices)[/]")
    console.print("[dim]Tip: pass arguments directly next time to skip this, e.g.:[/]")
    console.print("[dim]  websec-assess scan https://target.example --profile quick --i-have-authorization[/]")
    console.print()

    args.target = Prompt.ask(
        "Target (IP, hostname, or URL -- include [bold]http://[/] if it's not HTTPS)"
    ).strip()
    if not args.target:
        err_console.print("[red]No target entered -- aborting.[/]")
        return False

    depth = Prompt.ask("Scan depth: light / full / everything", choices=list(_DEPTH_TO_PROFILE), default="full")
    args.profile = _DEPTH_TO_PROFILE[depth]

    ownership = Prompt.ask(
        "Is this a shared/third-party-authorised target (be polite) or your own infrastructure (can go faster)?",
        choices=["shared", "own"], default="shared",
    )
    if ownership == "own":
        config.rate_limit.requests_per_second = max(config.rate_limit.requests_per_second, 20.0)
        config.rate_limit.burst = max(config.rate_limit.burst, 40)
        config.rate_limit.concurrency = max(config.rate_limit.concurrency, 20)

    config.safety.active_injection_probes = Confirm.ask(
        "Enable active injection-indicator checks (XSS/SQLi/CmdI/SSTI/path traversal/XXE/open redirect)? "
        "Only for targets you own or have explicit permission for the most invasive testing",
        default=False,
    )

    PluginRegistry.discover()
    all_plugins = PluginRegistry.all()
    args.plugins = None
    if Confirm.ask("Pick specific tools/categories instead of running the whole profile?", default=False):
        print_plugins_table(all_plugins)
        console.print(f"[dim]Categories: {', '.join(sorted({p.category for p in all_plugins}))}[/]")
        raw = Prompt.ask("Comma-separated plugin names and/or categories to run")
        names, unknown = expand_plugin_selection(raw.split(","), all_plugins)
        if unknown:
            err_console.print(f"[yellow]Ignoring unrecognised entries: {', '.join(unknown)}[/]")
        if not names:
            err_console.print("[red]No valid plugins selected -- aborting.[/]")
            return False
        args.plugins = ",".join(names)

    args.i_have_authorization = Confirm.ask(
        "Do you have explicit, documented authorisation to scan this target?", default=False
    )
    if not args.i_have_authorization:
        err_console.print("[red]Authorisation not confirmed -- aborting.[/]")
        return False

    args.open = Confirm.ask("Open the HTML report in your browser when it's done?", default=True)
    args.dry_run = False
    console.print()
    return True


def cmd_plugins(args: argparse.Namespace) -> int:
    PluginRegistry.discover()
    plugins = PluginRegistry.all()
    if args.category:
        plugins = [p for p in plugins if p.category == args.category]
    print_plugins_table(plugins)
    return 0


def _run_with_progress(coro_factory, scheduler: Scheduler, planned_count: int):
    """Runs a scan/resume coroutine while showing a live spinner + progress
    bar, ticking once per plugin finished/crashed -- otherwise a multi-phase
    scan that can legitimately take a minute or two prints nothing at all
    between the banner and the final table, which looks hung."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} plugins"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=max(1, planned_count))

        def on_event(event: str, plugin_name: str) -> None:
            if event == "plugin_started":
                progress.update(task, description=f"Scanning... ({plugin_name})")
            elif event in ("plugin_finished", "plugin_crashed"):
                progress.advance(task)

        scheduler._on_plugin_event = on_event  # noqa: SLF001 -- CLI-only wiring, not public API
        return asyncio.run(coro_factory())


def _maybe_open_report(written: list[Path], should_open: bool) -> None:
    html_reports = [p for p in written if p.suffix == ".html"]
    if should_open and html_reports:
        webbrowser.open(html_reports[0].resolve().as_uri())


def _print_next_steps(scan_id: str) -> None:
    console.print()
    console.print("[dim]Next steps:[/]")
    console.print(f"[dim]  websec-assess report {scan_id[:8]} --format html --open   (reopen the report)[/]")
    console.print("[dim]  websec-assess list                                       (see all scans)[/]")
    console.print("[dim]  websec-assess plugins                                    (see what ran)[/]")


def cmd_scan(args: argparse.Namespace) -> int:
    configure_logging(level=args.log_level)
    config = AppConfig.load(args.config)
    if not args.target:
        if not _interactive_scan_setup(args, config):
            return 1
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
        planned_count = len(scheduler.plan(profile, plugin_names))
        try:
            scan = _run_with_progress(
                lambda: scheduler.run_scan(target, profile, plugin_names), scheduler, planned_count
            )
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
        _maybe_open_report(written, args.open)
        _print_next_steps(scan.id)
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    configure_logging(level=args.log_level)
    config = AppConfig.load(args.config)
    PluginRegistry.discover()
    with open_repository(config) as repo:
        try:
            scan_id = resolve_scan_id(repo, args.scan_id)
        except ValueError as exc:
            err_console.print(f"[red]{exc}[/]")
            return 1
        scheduler = Scheduler(config, repo)
        remaining_count = len(repo.remaining_plugins(scan_id))
        scan = _run_with_progress(lambda: scheduler.resume_scan(scan_id), scheduler, remaining_count)
        findings = repo.list_findings(scan.id)
        assets = repo.list_assets(scan.id)
        print_scan_summary(scan, findings, assets)
        _print_next_steps(scan.id)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    config = AppConfig.load(args.config)
    with open_repository(config) as repo:
        try:
            scan_id = resolve_scan_id(repo, args.scan_id)
        except ValueError as exc:
            err_console.print(f"[red]{exc}[/]")
            return 1
        formats = args.format.split(",")
        written = write_reports(repo, scan_id, formats, Path(args.output_dir or config.scan.output_dir))
        for path in written:
            console.print(f"Report written: [bold]{path}[/]")
        _maybe_open_report(written, args.open)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    config = AppConfig.load(args.config)
    with open_repository(config) as repo:
        print_scans_table(repo.list_scans())
    return 0


def cmd_help(args: argparse.Namespace) -> int:
    print_commands_overview()
    return 0


def cmd_guide(args: argparse.Namespace) -> int:
    print_guide()
    return 0


_MENU_OPTIONS = [
    ("1", "Run a scan (prompts you for target/depth/tools)"),
    ("2", "List registered plugins/checks"),
    ("3", "List past scans"),
    ("4", "View/open a past report"),
    ("5", "Show full command reference"),
    ("6", "Guide -- what the scan choices actually mean"),
    ("7", "Exit"),
]


def cmd_menu(args: argparse.Namespace) -> int:
    """A loop over the same cmd_* functions the regular subcommands use,
    fed minimal argparse.Namespace stand-ins -- so this is the one place
    that has to stay in sync if a cmd_* function starts reading a new
    attribute off `args`."""
    while True:
        console.print()
        console.print("[bold cyan]websec-assess[/]")
        for key, label in _MENU_OPTIONS:
            console.print(f"  [bold]{key}[/]) {label}")
        choice = Prompt.ask("Choose an option", choices=[k for k, _ in _MENU_OPTIONS], default="1")

        if choice == "1":
            cmd_scan(argparse.Namespace(target=None, config=args.config, format="json,markdown,html", log_level="INFO"))
        elif choice == "2":
            cmd_plugins(argparse.Namespace(category=None, config=args.config))
        elif choice == "3":
            cmd_list(argparse.Namespace(config=args.config))
        elif choice == "4":
            with open_repository(AppConfig.load(args.config)) as repo:
                scans = repo.list_scans()
                if not scans:
                    console.print("[yellow]No scans yet -- run one first.[/]")
                    continue
                print_scans_table(scans)
                scan_id = Prompt.ask("Scan ID (full or short prefix)")
                try:
                    resolved = resolve_scan_id(repo, scan_id)
                except ValueError as exc:
                    err_console.print(f"[red]{exc}[/]")
                    continue
            cmd_report(argparse.Namespace(scan_id=resolved, format="html", output_dir=None, config=args.config, open=True))
        elif choice == "5":
            cmd_help(args)
        elif choice == "6":
            cmd_guide(args)
        else:
            break
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="websec-assess", description="Modular web application security assessment platform.")
    parser.add_argument("--config", "-c", help="Path to YAML config file", default=None)
    sub = parser.add_subparsers(dest="command", required=False)

    p_init = sub.add_parser("init", help="Write a starter config file")
    p_init.add_argument("--output", "-o", default="websec-assess.yaml")
    p_init.add_argument("--target", help="Host to pre-populate scope.allowed_hosts with")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_plugins = sub.add_parser("plugins", help="List registered plugins")
    p_plugins.add_argument("--category")
    p_plugins.set_defaults(func=cmd_plugins)

    p_scan = sub.add_parser("scan", help="Run a scan against a target")
    p_scan.add_argument(
        "target", nargs="?", default=None,
        help="Base URL or hostname to scan. Omit to be prompted interactively.",
    )
    p_scan.add_argument("--profile", choices=[p.value for p in ScanProfile], default="standard")
    p_scan.add_argument("--plugins", help="Comma-separated plugin names to run instead of the full profile")
    p_scan.add_argument("--format", default="json,markdown,html", help="Comma-separated: json,markdown,html")
    p_scan.add_argument("--dry-run", action="store_true")
    p_scan.add_argument("--i-have-authorization", action="store_true", help="Confirm you are authorised to test this target")
    p_scan.add_argument("--open", action="store_true", help="Open the HTML report in your browser when the scan finishes")
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
    p_report.add_argument("--open", action="store_true", help="Open the HTML report in your browser")
    p_report.set_defaults(func=cmd_report)

    p_list = sub.add_parser("list", help="List past scans")
    p_list.set_defaults(func=cmd_list)

    p_help = sub.add_parser("help", help="Show every command and its options")
    p_help.set_defaults(func=cmd_help)

    p_guide = sub.add_parser("guide", help="Explain what the scan choices (depth, politeness, injection probes) mean")
    p_guide.set_defaults(func=cmd_guide)

    p_menu = sub.add_parser("menu", help="Interactive menu (also launched by running with no arguments)")
    p_menu.set_defaults(func=cmd_menu)

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
    func = getattr(args, "func", None) or cmd_menu  # no subcommand given -> menu
    try:
        return func(args)
    except KeyboardInterrupt:
        err_console.print("[yellow]Interrupted.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
