"""Tests for the threat-intel feed importer (socbox.feeds_import)."""

from __future__ import annotations

import pytest
import responses

from socbox.feeds_import import (
    OPENPHISH_FEED,
    URLHAUS_RECENT_API,
    fetch_openphish,
    fetch_urlhaus,
)


def test_fetch_urlhaus_requires_key() -> None:
    with pytest.raises(ValueError):
        fetch_urlhaus("", limit=5)


@responses.activate
def test_fetch_urlhaus_filters_online_and_tag() -> None:
    responses.add(
        responses.GET,
        URLHAUS_RECENT_API,
        json={
            "query_status": "ok",
            "urls": [
                {"url": "http://a.test/x", "url_status": "online", "tags": ["ClearFake"]},
                {"url": "http://b.test/x", "url_status": "offline", "tags": ["ClearFake"]},
                {"url": "http://c.test/x", "url_status": "online", "tags": ["Mozi"]},
            ],
        },
        status=200,
    )
    res = fetch_urlhaus("KEY", limit=10, online_only=True, tag="clearfake")
    assert [r["url"] for r in res] == ["http://a.test/x"]  # offline + wrong-tag dropped


@responses.activate
def test_fetch_urlhaus_respects_limit() -> None:
    responses.add(
        responses.GET,
        URLHAUS_RECENT_API,
        json={
            "query_status": "ok",
            "urls": [
                {"url": f"http://x{i}.test", "url_status": "online", "threat": "", "tags": []}
                for i in range(10)
            ],
        },
        status=200,
    )
    assert len(fetch_urlhaus("KEY", limit=3, online_only=True)) == 3


@responses.activate
def test_fetch_urlhaus_raises_on_api_error() -> None:
    responses.add(
        responses.GET, URLHAUS_RECENT_API,
        json={"query_status": "unauthorized"}, status=200,
    )
    with pytest.raises(RuntimeError):
        fetch_urlhaus("BADKEY", limit=5)


@responses.activate
def test_fetch_openphish_limit_and_filtering() -> None:
    responses.add(
        responses.GET, OPENPHISH_FEED,
        body="http://p1.test\nhttp://p2.test\nnot-a-url\nhttp://p3.test\n", status=200,
    )
    assert [r["url"] for r in fetch_openphish(limit=2)] == ["http://p1.test", "http://p2.test"]
