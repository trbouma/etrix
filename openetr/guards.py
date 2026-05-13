from __future__ import annotations

from typing import Any

from monstr.client.client import ClientPool
from monstr.event.event import Event

from openetr.config import DEFAULT_KIND
from openetr.helpers import assert_hex_object_identifier, assert_hex_pubkey, format_object_identifier, format_pubkey


async def find_existing_origin_records_for_object(
    relays: str,
    digest: str,
    query_timeout: int,
    limit: int,
) -> list[Event]:
    assert_hex_object_identifier(digest)
    async with ClientPool(
        relays.split(","),
        timeout=query_timeout,
        query_timeout=query_timeout,
    ) as client:
        events = await client.query(
            {
                "kinds": [DEFAULT_KIND],
                "#o": [digest],
                "limit": limit,
            },
            emulate_single=True,
            wait_connect=True,
            timeout=query_timeout,
        )

    Event.sort(events, inplace=True, reverse=True)
    return events


async def evaluate_issue_etr_guard(
    relays: str,
    digest: str,
    author_pubkey_hex: str,
    query_timeout: int,
    limit: int,
) -> dict[str, Any]:
    assert_hex_object_identifier(digest)
    assert_hex_pubkey(author_pubkey_hex)

    existing_events = await find_existing_origin_records_for_object(
        relays=relays,
        digest=digest,
        query_timeout=query_timeout,
        limit=limit,
    )

    latest = existing_events[0] if existing_events else None
    same_author = bool(latest and latest.pub_key == author_pubkey_hex)
    warning_message = None
    if latest is not None:
        warning_message = (
            "WARNING: this file has already been issued as an ETR. "
            "Issuing it again may create a competing or conflicting origin record for the same object."
        )
        if same_author:
            warning_message = (
                "WARNING: this file has already been issued as an ETR by the current signer. "
                "Issuing it again may overwrite or conflict with the existing origin record."
            )

    return {
        "should_warn": latest is not None,
        "warning_message": warning_message,
        "existing_count": len(existing_events),
        "same_author": same_author,
        "latest_event_id": latest.id if latest else None,
        "latest_issuer_hex": latest.pub_key if latest else None,
        "latest_issuer_npub": format_pubkey(latest.pub_key) if latest else None,
        "object_id": format_object_identifier(digest),
    }
