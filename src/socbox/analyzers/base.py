"""Base analyzer interface for SOC Box."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from socbox.models import AnalyzerResult


class BaseAnalyzer(ABC):
    """Abstract base class for all SOC Box analyzers.

    Each analyzer inspects a URL from a specific angle (lexical, DNS, SSL, etc.)
    and returns an AnalyzerResult with findings and a score.
    """

    name: str = ""
    weight: float = 0.0

    @abstractmethod
    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Run analysis on the given URL.

        Args:
            url: The URL to analyze.
            config: The loaded SOC Box configuration dictionary.
            browser: Optional shared Playwright Browser instance for
                analyzers that need browser automation.

        Returns:
            An AnalyzerResult with findings and a score for this dimension.
        """
        ...
