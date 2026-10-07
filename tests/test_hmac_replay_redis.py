import asyncio
import os

import httpx
import pytest

from tests.test_hmac_middleware import _sign_headers, replay_guarded

TEST_REDIS_URL = os.getenv("TEST_REDIS_URL")

if not TEST_REDIS_URL:
    pytest.skip(
        "TEST_REDIS_URL not set — real-Redis replay tests skipped",
        allow_module_level=True,
    )


def status_on_a_fresh_loop(guard, headers: dict[str, str]) -> int:
    async def call() -> int:
        transport = httpx.ASGITransport(app=guard)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return (await c.get("/protected", headers=headers)).status_code

    return asyncio.run(call())


def test_a_signature_replayed_on_another_event_loop_is_rejected():
    assert TEST_REDIS_URL is not None
    guard = replay_guarded(TEST_REDIS_URL)
    headers = _sign_headers()

    first = status_on_a_fresh_loop(guard, headers)
    replay = status_on_a_fresh_loop(guard, headers)

    assert (first, replay) == (200, 403)
    assert guard.hmac_stats["success"] == 1
    assert guard.hmac_stats["failure_replay"] == 1
    assert guard.hmac_stats["replay_check_skipped"] == 0


def test_distinct_signatures_are_not_replays():
    assert TEST_REDIS_URL is not None
    guard = replay_guarded(TEST_REDIS_URL)

    assert status_on_a_fresh_loop(guard, _sign_headers()) == 200
    assert status_on_a_fresh_loop(guard, _sign_headers()) == 200
