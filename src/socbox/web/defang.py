"""IOC defanging utilities for SOC Box.

Converts live URLs/domains/IPs into analyst-safe representations
that will not be accidentally clicked or auto-linked by ticketing
systems, email clients, or chat tools.
"""

from __future__ import annotations

import re


def defang(url: str) -> str:
    """Convert a live URL into a defanged IOC representation.

    Transforms protocol schemes and dots in the domain portion
    to prevent accidental hyperlinking in ticketing systems,
    email clients, and chat tools.

    Examples:
        https://evil.com       -> hxxps://evil[.]com
        http://sub.evil.com/p  -> hxxp://sub[.]evil[.]com/p
        ftp://files.bad.org    -> fxp://files[.]bad[.]org
        192.168.1.1            -> 192[.]168[.]1[.]1

    Args:
        url: The original URL, domain, or IP string.

    Returns:
        The defanged string safe for copy-paste into tickets.
    """
    result = url

    # Defang protocol schemes
    result = re.sub(r"^https://", "hxxps://", result, count=1, flags=re.IGNORECASE)
    result = re.sub(r"^http://", "hxxp://", result, count=1, flags=re.IGNORECASE)
    result = re.sub(r"^ftp://", "fxp://", result, count=1, flags=re.IGNORECASE)

    # Defang dots in the domain portion only (not in the path).
    scheme_end = result.find("://")
    if scheme_end != -1:
        after_scheme = scheme_end + 3
        slash_pos = result.find("/", after_scheme)
        if slash_pos == -1:
            # No path — defang all dots in the domain
            domain = result[after_scheme:]
            result = result[:after_scheme] + domain.replace(".", "[.]")
        else:
            domain = result[after_scheme:slash_pos]
            path = result[slash_pos:]
            result = result[:after_scheme] + domain.replace(".", "[.]") + path
    else:
        # No scheme — could be bare domain or IP.
        slash_pos = result.find("/")
        if slash_pos == -1:
            result = result.replace(".", "[.]")
        else:
            domain = result[:slash_pos]
            path = result[slash_pos:]
            result = domain.replace(".", "[.]") + path

    return result


def refang(defanged: str) -> str:
    """Reverse a defanged IOC back to a live URL.

    Useful for internal processing when a defanged string needs
    to be used for actual network operations.

    Args:
        defanged: A defanged URL/domain/IP string.

    Returns:
        The re-fanged (live) URL.
    """
    result = defanged
    result = re.sub(r"^hxxps://", "https://", result, count=1, flags=re.IGNORECASE)
    result = re.sub(r"^hxxp://", "http://", result, count=1, flags=re.IGNORECASE)
    result = re.sub(r"^fxp://", "ftp://", result, count=1, flags=re.IGNORECASE)
    result = result.replace("[.]", ".")
    return result
