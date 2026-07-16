"""Rich terminal output renderer for SOC Box."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from socbox.models import AnalyzerStatus, FeedResult, RiskCategory, ScanReport

console = Console(force_terminal=True)

CATEGORY_COLORS = {
    RiskCategory.SAFE: "green",
    RiskCategory.UNCERTAIN: "yellow",
    RiskCategory.MALICIOUS: "bold red",
    RiskCategory.MALICIOUS_DOWNLOAD: "bold red",
    RiskCategory.SUSPICIOUS_DOWNLOAD: "red",
}

STATUS_SYMBOLS = {
    AnalyzerStatus.COMPLETED: "[green]OK[/green]",
    AnalyzerStatus.SKIPPED: "[yellow]--[/yellow]",
    AnalyzerStatus.ERROR: "[red]ERR[/red]",
}


def render_report(report: ScanReport, verbose: bool = False) -> None:
    """Print the full Rich-formatted scan report to the terminal.

    Args:
        report: The completed ScanReport to render.
        verbose: If True, show detailed findings for each analyzer.
    """
    console.print()
    _render_header(report)
    _render_score_panel(report)
    _render_breakdown_table(report, verbose)

    if report.redirect_chain:
        _render_redirect_chain(report.redirect_chain)

    feed_matches = [fr for fr in report.feed_results if fr.matched]
    if feed_matches:
        _render_feed_matches(feed_matches)

    _render_recommendation(report)
    _render_screenshot_info(report)
    console.print()


def _render_header(report: ScanReport) -> None:
    """Render the scan header with URL and timestamp."""
    console.print(
        Panel(
            f"[bold]Target:[/bold] {report.url}\n"
            f"[bold]Scanned:[/bold] {report.timestamp}",
            title="[bold blue]SOC Box Scan Report[/bold blue]",
            border_style="blue",
        )
    )


def _render_score_panel(report: ScanReport) -> None:
    """Render the classification and confidence percentage."""
    color = CATEGORY_COLORS.get(report.risk_category, "white")
    confidence_text = Text(f"{report.confidence:.0f}%", style=f"bold {color}")
    category_text = Text(f"  {report.risk_category.value}", style=color)

    content = Text.assemble("Confidence: ", confidence_text, category_text)

    console.print(Panel(content, border_style=color))


def _render_breakdown_table(report: ScanReport, verbose: bool) -> None:
    """Render the analyzer breakdown table."""
    table = Table(title="Analyzer Breakdown", show_lines=True)
    table.add_column("Status", justify="center", width=6)
    table.add_column("Analyzer", min_width=25)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Weight", justify="right", width=8)

    if verbose:
        table.add_column("Findings", min_width=40)

    for result in report.analyzer_results:
        status = STATUS_SYMBOLS.get(result.status, "?")
        score_str = f"{result.score:.0f}" if result.status == AnalyzerStatus.COMPLETED else "--"
        weight_str = f"{result.max_weight:.0f}"

        row = [status, result.analyzer_name, score_str, weight_str]

        if verbose:
            if result.status == AnalyzerStatus.ERROR:
                findings_str = f"[red]Error: {result.error_message}[/red]"
            elif result.status == AnalyzerStatus.SKIPPED:
                findings_str = f"[yellow]{result.error_message}[/yellow]"
            elif result.findings:
                findings_str = "\n".join(
                    f"[{_severity_color(f.severity)}]"
                    f"* {f.description}"
                    f"[/{_severity_color(f.severity)}]"
                    for f in result.findings
                )
            else:
                findings_str = "[dim]No findings[/dim]"
            row.append(findings_str)

        table.add_row(*row)

    console.print(table)


def _render_redirect_chain(chain: list[str]) -> None:
    """Render the redirect chain if present."""
    chain_display = " -> ".join(chain)
    console.print(
        Panel(
            f"[bold]Redirect Chain ({len(chain)} hops):[/bold]\n{chain_display}",
            title="[bold yellow]Redirects[/bold yellow]",
            border_style="yellow",
        )
    )


def _render_feed_matches(feed_matches: list[FeedResult]) -> None:
    """Render threat feed matches."""
    lines = []
    for fr in feed_matches:
        lines.append(f"[bold red]! {fr.feed_name}:[/bold red] {fr.details}")

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold red]Threat Feed Matches[/bold red]",
            border_style="red",
        )
    )


def _render_recommendation(report: ScanReport) -> None:
    """Render the recommendation panel."""
    color = CATEGORY_COLORS.get(report.risk_category, "white")
    console.print(
        Panel(
            report.recommendation,
            title="[bold]Recommendation[/bold]",
            border_style=color,
        )
    )


def _render_screenshot_info(report: ScanReport) -> None:
    """Render the screenshot file path or failure notice."""
    if report.screenshot_path:
        console.print(
            Panel(
                f"[bold]Saved to:[/bold] {report.screenshot_path}",
                title="[bold cyan]Screenshot[/bold cyan]",
                border_style="cyan",
            )
        )
    else:
        console.print("[dim]Screenshot: not captured (passive mode or capture failed)[/dim]")


def _severity_color(severity: str) -> str:
    """Map finding severity to a Rich color.

    Args:
        severity: One of 'info', 'low', 'medium', 'high', 'critical'.

    Returns:
        A Rich color string.
    """
    return {
        "info": "dim",
        "low": "cyan",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }.get(severity, "white")
