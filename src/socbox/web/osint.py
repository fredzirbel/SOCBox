"""OSINT link generator for SOC Box scan reports."""

from __future__ import annotations

from urllib.parse import quote

import tldextract

from socbox.feeds.virustotal import vt_url_id


def generate_osint_links(
    url: str,
    domain: str,
    ip: str = "",
    redirect_chain: list[str] | None = None,
) -> list[dict[str, str]]:
    """Build clickable OSINT links for external threat-intel tools.

    Args:
        url: The full URL that was scanned.
        domain: The extracted domain (e.g. "example.com").
        ip: The resolved IP address, if available.
        redirect_chain: Optional list of redirect hop URLs.

    Returns:
        A list of dicts with keys: name, url, icon_class, description.
    """
    vt_id = vt_url_id(url)
    encoded_url = quote(url, safe="")

    links: list[dict[str, str]] = [
        {
            "name": "VirusTotal (URL)",
            "url": f"https://www.virustotal.com/gui/url/{vt_id}",
            "icon_class": "vt",
            "description": "Multi-engine URL scan results",
        },
        {
            "name": "VirusTotal (Domain)",
            "url": f"https://www.virustotal.com/gui/domain/{domain}",
            "icon_class": "vt",
            "description": "Domain reputation and history",
        },
        {
            "name": "Google Transparency",
            "url": f"https://transparencyreport.google.com/safe-browsing/search?url={encoded_url}",
            "icon_class": "google",
            "description": "Google Safe Browsing transparency report",
        },
        {
            "name": "who.is",
            "url": f"https://who.is/whois/{domain}",
            "icon_class": "whois",
            "description": "WHOIS registration lookup",
        },
        {
            "name": "URLScan.io",
            "url": f"https://urlscan.io/search/#{encoded_url}",
            "icon_class": "urlscan",
            "description": "Live site scan and analysis",
        },
    ]

    # IP-specific links - only included when an IP is available
    if ip:
        links.insert(
            2,
            {
                "name": "AbuseIPDB",
                "url": f"https://www.abuseipdb.com/check/{ip}",
                "icon_class": "abuseipdb",
                "description": "IP abuse confidence score",
            },
        )

    # Redirect chain OSINT - add VirusTotal links for each redirect hop
    # that differs from the primary scanned URL.
    if redirect_chain:
        seen_urls: set[str] = {url.rstrip("/")}
        seen_domains: set[str] = {domain.lower()}

        for hop in redirect_chain:
            hop_normalised = hop.rstrip("/")
            hop_extracted = tldextract.extract(hop)
            hop_domain = f"{hop_extracted.domain}.{hop_extracted.suffix}"

            # Add VT URL link for each unique redirect hop
            if hop_normalised not in seen_urls:
                seen_urls.add(hop_normalised)
                vt_hop_id = vt_url_id(hop)
                links.append({
                    "name": "VirusTotal (Redirect URL)",
                    "url": f"https://www.virustotal.com/gui/url/{vt_hop_id}",
                    "icon_class": "vt",
                    "description": f"Redirect: {hop_domain}",
                })

            # Add VT domain link for each unique redirect domain
            if hop_domain.lower() not in seen_domains and hop_domain != ".":
                seen_domains.add(hop_domain.lower())
                links.append({
                    "name": "VirusTotal (Redirect Domain)",
                    "url": f"https://www.virustotal.com/gui/domain/{hop_domain}",
                    "icon_class": "vt",
                    "description": f"Redirect domain: {hop_domain}",
                })

    return links
