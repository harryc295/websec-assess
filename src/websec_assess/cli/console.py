"""rich-based output. Rich auto-detects terminal capabilities (incl. Windows
Terminal / legacy cmd.exe via colorama) so this looks right on Windows,
Ubuntu, Kali and Mint without any platform branching here.
"""
from __future__ import annotations

from rich.console import Console
from rich.table import Table

from websec_assess.core.models import Asset, Finding, ScanRun
from websec_assess.core.plugin import Plugin
from websec_assess.core.severity import Severity

console = Console()
err_console = Console(stderr=True)

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_scan_summary(scan: ScanRun, findings: list[Finding], assets: list[Asset]) -> None:
    table = Table(title=f"Scan {scan.id[:8]} - {scan.target.host}")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        table.add_row(f"[{_SEVERITY_STYLE[sev]}]{sev.value}[/]", str(counts[sev]))
    console.print(table)
    console.print(
        f"Status: [bold]{scan.status.value}[/]  Assets discovered: [bold]{len(assets)}[/]  "
        f"Plugins run: [bold]{len(scan.plugins_completed)}/{len(scan.plugins_planned)}[/]"
    )


def print_scans_table(scans: list[ScanRun]) -> None:
    table = Table(title="Scans")
    for col in ("ID", "Target", "Profile", "Status", "Started", "Finished"):
        table.add_column(col)
    for s in scans:
        table.add_row(
            s.id[:8], s.target.host, s.profile.value, s.status.value,
            str(s.started_at or "-"), str(s.finished_at or "-"),
        )
    console.print(table)


def print_plugins_table(plugins: list[type[Plugin]]) -> None:
    table = Table(title="Registered plugins")
    for col in ("Name", "Category", "Profiles", "Active probes", "Description"):
        table.add_column(col)
    for p in sorted(plugins, key=lambda p: (p.category, p.name)):
        profiles = ",".join(sorted(pr.value for pr in p.profiles))
        table.add_row(p.name, p.category, profiles, "yes" if p.requires_active_probes else "no", p.description)
    console.print(table)


COMMAND_OVERVIEW: list[tuple[str, str, str]] = [
    ("scan", "Run a scan. Omit the target to be prompted (target, depth, tool selection).",
     "websec-assess scan [TARGET] [--profile quick|standard|deep] [--plugins a,b] [--i-have-authorization] [--open] [--dry-run]"),
    ("init", "Write a starter config file.", "websec-assess init --target HOST [--output FILE] [--force]"),
    ("resume", "Resume an interrupted scan.", "websec-assess resume SCAN_ID"),
    ("report", "(Re-)generate reports for a past scan.", "websec-assess report SCAN_ID [--format json,markdown,html] [--output-dir DIR] [--open]"),
    ("plugins", "List every registered check/plugin.", "websec-assess plugins [--category recon|content_discovery|vuln_assessment|injection|...]"),
    ("list", "List past scans.", "websec-assess list"),
    ("menu", "Interactive menu -- also launched by running with no arguments.", "websec-assess menu"),
    ("guide", "Explain what scan depth, politeness, and injection probes actually mean.", "websec-assess guide"),
    ("help", "Show this overview.", "websec-assess help"),
]


def print_guide() -> None:
    console.print("[bold cyan]Guide[/]")
    console.print()
    console.print("[bold]Scan depth[/] (light / full / everything -> quick / standard / deep)")
    console.print("  Controls wordlist sizes, crawl depth, and Wayback/port-scan limits.")
    console.print("  light:      fastest, smallest wordlists, no port scanning or nuclei templates.")
    console.print("  full:       the default -- bigger wordlists, port scanning + nuclei if installed.")
    console.print("  everything: largest wordlists/limits, deepest crawl.")
    console.print()
    console.print("[bold]Shared/third-party vs. your own infrastructure[/]")
    console.print("  'shared' keeps the default polite rate limit (5 req/s) -- use this for anything")
    console.print("  you don't fully own, e.g. scanme.nmap.org (explicitly open for tool testing, but")
    console.print("  the published policy still asks you not to hammer it or attack it).")
    console.print("  'own' raises the rate limit/concurrency -- only for infrastructure you control.")
    console.print()
    console.print("[bold]Active injection-indicator checks[/] (off by default)")
    console.print("  Sends mutated parameters to probe for XSS/SQLi/CmdI/SSTI/path traversal/XXE/open")
    console.print("  redirect. Detection-only (see SECURITY.md), but it does mutate requests against the")
    console.print("  live target -- only enable this for systems you own or have explicit permission for")
    console.print("  the most invasive testing. Most third-party 'please test me' targets do NOT cover this.")
    console.print()
    console.print("[bold]Authorisation[/]")
    console.print("  Every scan refuses to send a single request unless you confirm authorisation")
    console.print("  (the interactive prompt, or --i-have-authorization / safety.authorized in config).")
    console.print("  Have a signed engagement letter, a bug bounty program's published scope, your own")
    console.print("  lab, a CTF, or (for scanme.nmap.org specifically) the host's own published policy.")
    console.print()
    console.print("[bold]Picking specific tools instead of a whole profile[/]")
    console.print("  Enter a category name (recon, content_discovery, vuln_assessment, api_security,")
    console.print("  auth_access, cloud_infra, passive_intel, integrations, injection) to run every")
    console.print("  plugin in it, an exact plugin name (e.g. recon.dns_enum), or a comma-separated mix.")
    console.print()
    console.print("[dim]See `websec-assess help` for the full command/flag reference.[/]")


def print_commands_overview() -> None:
    table = Table(title="websec-assess -- commands")
    table.add_column("Command")
    table.add_column("What it does")
    table.add_column("Usage")
    for name, desc, usage in COMMAND_OVERVIEW:
        table.add_row(name, desc, usage)
    console.print(table)
    console.print()
    console.print("[dim]Every command also takes --config FILE. Run `websec-assess <command> --help` for the full flag list.[/]")
    console.print("[dim]SCAN_ID accepts the short 8-character ID shown in `list` and scan summaries, not just the full one.[/]")
