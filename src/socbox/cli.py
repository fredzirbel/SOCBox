"""CLI entry point for SOC Box."""

from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path

from socbox import __version__
from socbox.config import load_config
from socbox.output import render_report
from socbox.scanner import scan_url


def main() -> None:
    """Parse CLI arguments and run an SOC Box scan."""
    parser = argparse.ArgumentParser(
        prog="socbox",
        description="SOC Box - The SOC Analyst's Toolbox",
    )
    parser.add_argument("url", metavar="URL", help="The URL to analyze")
    parser.add_argument(
        "-c", "--config",
        default=None,
        help="Path to config YAML file (default: config/default.yaml)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed findings for each analyzer",
    )
    parser.add_argument(
        "--no-active",
        action="store_true",
        help="Lexical-only passive mode (disables network/browser analyzers)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help=(
            "Open the browser on-screen and pause on an unsolvable CAPTCHA so "
            "you can solve it by hand; analysis resumes once it clears"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Validate URL has a scheme
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading config: {e}", file=sys.stderr)
        sys.exit(1)

    if args.no_color:
        from socbox.output import console
        console.no_color = True

    # Suppress SSL warnings only when SSL verification is explicitly disabled.
    if not config.get("requests", {}).get("verify_ssl", True):
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    # Set up screenshots directory
    project_root = Path(__file__).resolve().parent.parent.parent
    screenshot_dir = project_root / "screenshots"
    screenshot_dir.mkdir(exist_ok=True)

    report = scan_url(
        url,
        config,
        passive_only=args.no_active,
        screenshot_dir=str(screenshot_dir),
        interactive=args.interactive,
    )
    render_report(report, verbose=args.verbose)


if __name__ == "__main__":
    main()
