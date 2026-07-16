"""Test the async-scan completion webhook poster."""

from __future__ import annotations

import json

import responses

from socbox.web import app as webapp


@responses.activate
def test_post_webhook_sends_json_payload() -> None:
    responses.add(responses.POST, "http://cb.test/hook", json={"ok": True}, status=200)
    webapp._post_webhook("http://cb.test/hook", {"job_id": "x", "verdict": "Safe"})
    assert len(responses.calls) == 1
    body = json.loads(responses.calls[0].request.body)
    assert body["job_id"] == "x"
    assert body["verdict"] == "Safe"


@responses.activate
def test_post_webhook_swallows_errors() -> None:
    # No mock registered -> connection error; must not raise.
    webapp._post_webhook("http://unreachable.invalid/hook", {"job_id": "y"})
