from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from monstr.client.client import ClientPool
from monstr.event.event import Event

from openetr.config import DEFAULT_KIND, DEFAULT_LIMIT, DEFAULT_QUERY_TIMEOUT
from openetr.guards import evaluate_issue_etr_guard
from openetr.helpers import format_object_identifier, format_pubkey, resolve_keys


async def publish_issue_etr(
    filename: str,
    size_bytes: int,
    digest: str,
    relays: str,
    signer_nsec: str,
    comment: str | None,
    publish_wait: float = 2.0,
    timeout: int = DEFAULT_QUERY_TIMEOUT,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    keys = resolve_keys(signer_nsec)
    generated_at = datetime.now(timezone.utc)
    resolved_comment = comment or (
        f"name={filename}; "
        f"digest_generated_at={generated_at.isoformat()}; "
        f"size_bytes={size_bytes}"
    )
    issue_guard = await evaluate_issue_etr_guard(
        relays=relays,
        digest=digest,
        author_pubkey_hex=keys.public_key_hex(),
        query_timeout=timeout,
        limit=limit,
    )

    ok_results: list[dict[str, Any]] = []

    def on_ok(the_client, event_id: str, success: bool, message: str) -> None:
        ok_results.append(
            {
                "event_id": event_id,
                "success": success,
                "message": message,
            }
        )

    event = Event(
        kind=DEFAULT_KIND,
        content=resolved_comment,
        pub_key=keys.public_key_hex(),
        tags=[["d", digest], ["o", digest]],
    )
    event.sign(keys.private_key_hex())

    async with ClientPool(
        relays.split(","),
        on_ok=on_ok,
        timeout=timeout,
        query_timeout=timeout,
    ) as client:
        client.publish(event)
        if publish_wait > 0:
            await asyncio.sleep(publish_wait)
        matching_events = await client.query(
            {
                "authors": [keys.public_key_hex()],
                "kinds": [DEFAULT_KIND],
                "#o": [digest],
                "#d": [digest],
                "limit": limit,
            },
            emulate_single=True,
            wait_connect=True,
            timeout=timeout,
        )

    Event.sort(matching_events, inplace=True, reverse=False)
    return {
        "filename": filename,
        "size_bytes": size_bytes,
        "sha256": digest,
        "object_id": format_object_identifier(digest),
        "event_id": event.id,
        "signer_npub": keys.public_key_bech32(),
        "signer_pubkey": format_pubkey(keys.public_key_hex()),
        "comment": resolved_comment,
        "existing_count_before_publish": issue_guard["existing_count"],
        "existing_latest_event_id": issue_guard["latest_event_id"],
        "query_count_after_publish": len(matching_events),
        "ok_results": ok_results,
    }
