"""SOC Box analyzers package."""

from socbox.analyzers.download import DownloadAnalyzer
from socbox.analyzers.http_response import HTTPResponseAnalyzer
from socbox.analyzers.link_discovery import LinkDiscoveryAnalyzer
from socbox.analyzers.page_content import PageContentAnalyzer
from socbox.analyzers.ssl_tls import SSLTLSAnalyzer
from socbox.analyzers.threat_feeds import ThreatFeedAnalyzer
from socbox.analyzers.url_lexical import URLLexicalAnalyzer
from socbox.analyzers.whois_dns import WhoisDNSAnalyzer

ALL_ANALYZERS = [
    URLLexicalAnalyzer,
    WhoisDNSAnalyzer,
    SSLTLSAnalyzer,
    HTTPResponseAnalyzer,
    PageContentAnalyzer,
    DownloadAnalyzer,
    ThreatFeedAnalyzer,
    LinkDiscoveryAnalyzer,
]

__all__ = ["ALL_ANALYZERS"]
