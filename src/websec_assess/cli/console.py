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
