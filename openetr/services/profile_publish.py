from __future__ import annotations

import asyncio
import json
from typing import Any

from monstr.client.client import ClientPool
from monstr.event.event import Event

from openetr.config import DEFAULT_QUERY_TIMEOUT
from openetr.helpers import format_pubkey, resolve_lei, resolve_keys
from openetr.services.query_etr import fetch_profile

PROFILE_FIELDS = [
    "name",
    "display_name",
    "about",
    "address",
    "picture",
    "banner",
    "website",
    "nip05",
    "lud16",
    "lud06",
    "lei",
]


def sanitize_profile_updates(values: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    updates: dict[str, str] = {}
    removals: list[str] = []
    for field in PROFILE_FIELDS:
        raw_value = values.get(field)
        if raw_value is None:
            continue
        value = raw_value.strip()
        if not value:
            removals.append(field)
            continue
        if field == "lei":
            value = resolve_lei(value)
        updates[field] = value
    return updates, removals


async def publish_profile_content(
    relays: str,
    signer_nsec: str,
    content: dict[str, Any],
    publish_wait: float = 2.0,
    query_timeout: int = DEFAULT_QUERY_TIMEOUT,
) -> dict[str, Any]:
    keys = resolve_keys(signer_nsec)
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
        kind=0,
        content=json.dumps(content, separators=(",", ":"), ensure_ascii=True),
        pub_key=keys.public_key_hex(),
    )
    event.sign(keys.private_key_hex())

    async with ClientPool(
        relays.split(","),
        on_ok=on_ok,
        timeout=query_timeout,
        query_timeout=query_timeout,
    ) as client:
        client.publish(event)
        if publish_wait > 0:
            await asyncio.sleep(publish_wait)
        events = await client.query(
            {
                "authors": [keys.public_key_hex()],
                "kinds": [0],
                "limit": 1,
            },
            emulate_single=True,
            wait_connect=True,
            timeout=query_timeout,
        )

    Event.sort(events, inplace=True, reverse=True)
    latest = events[0] if events else None
    latest_content = {}
    if latest and latest.content:
        try:
            latest_content = json.loads(latest.content)
        except json.JSONDecodeError:
            latest_content = {}

    return {
        "event_id": event.id,
        "signer_npub": keys.public_key_bech32(),
        "signer_pubkey": format_pubkey(keys.public_key_hex()),
        "published_content": content,
        "latest_event_id": latest.id if latest else None,
        "latest_content": latest_content,
        "exact_match": bool(latest and latest.id == event.id),
        "ok_results": ok_results,
    }


async def publish_profile_updates(
    relays: str,
    signer_nsec: str,
    field_values: dict[str, str],
    replace: bool = False,
    publish_wait: float = 2.0,
    query_timeout: int = DEFAULT_QUERY_TIMEOUT,
) -> dict[str, Any]:
    keys = resolve_keys(signer_nsec)
    current_profile = {} if replace else (
        await fetch_profile(
            relays=relays,
            pubkey_hex=keys.public_key_hex(),
            timeout=query_timeout,
            ssl_disable_verify=False,
        ) or {}
    )
    updates, removals = sanitize_profile_updates(field_values)
    merged_profile = {} if replace else dict(current_profile)
    for field in removals:
        merged_profile.pop(field, None)
    merged_profile.update(updates)
    result = await publish_profile_content(
        relays=relays,
        signer_nsec=signer_nsec,
        content=merged_profile,
        publish_wait=publish_wait,
        query_timeout=query_timeout,
    )
    result["replace"] = replace
    result["current_profile_before_publish"] = current_profile
    result["removed_fields"] = removals
    result["updated_fields"] = sorted(updates.keys())
    return result
