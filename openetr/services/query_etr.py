from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from monstr.client.client import ClientPool
from monstr.event.event import Event

from openetr.config import DEFAULT_KIND, DEFAULT_LIMIT, DEFAULT_QUERY_TIMEOUT
from openetr.helpers import format_event_reference, format_object_identifier, format_pubkey

CONTROL_TRANSFER_KIND = 31416
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


async def fetch_profile(
    relays: str,
    pubkey_hex: str,
    timeout: int,
    ssl_disable_verify: bool,
) -> dict | None:
    ssl = False if ssl_disable_verify else None

    async with ClientPool(
        relays.split(","),
        query_timeout=timeout,
        timeout=timeout,
        ssl=ssl,
    ) as client:
        events = await client.query(
            {
                "authors": [pubkey_hex],
                "kinds": [0],
                "limit": 1,
            },
            emulate_single=True,
            wait_connect=True,
            timeout=timeout,
        )

    Event.sort(events, inplace=True, reverse=True)
    if not events or not events[0].content:
        return None

    try:
        profile = json.loads(events[0].content)
    except json.JSONDecodeError:
        return None

    return profile or None


def compact_profile(profile: dict | None) -> list[tuple[str, Any]]:
    if not profile:
        return []
    return [(field, profile.get(field)) for field in PROFILE_FIELDS if profile.get(field)]


def first_tag_value(event: Event, tag_name: str) -> str | None:
    values = event.get_tags_value(tag_name)
    return values[0] if values else None


def transfer_party_from_p_tag(event: Event) -> str | None:
    candidate = first_tag_value(event, "p")
    if candidate is None or len(candidate) != 64:
        return None
    try:
        int(candidate, 16)
    except ValueError:
        return None
    return candidate.lower()


def group_transfer_events(transfer_events: list[Event]) -> tuple[list[Event], dict[str, list[Event]]]:
    by_id = {evt.id: evt for evt in transfer_events}
    children: dict[str, list[Event]] = {}
    roots: list[Event] = []

    for evt in transfer_events:
        parent_id = first_tag_value(evt, "e")
        if parent_id and parent_id in by_id:
            children.setdefault(parent_id, []).append(evt)
        else:
            roots.append(evt)

    def sort_key(evt: Event) -> tuple[int, str]:
        return (evt.created_at or 0, evt.id)

    roots.sort(key=sort_key)
    for event_id in children:
        children[event_id].sort(key=sort_key)

    return roots, children


def profile_chain_label(pubkey_hex: str, profile: dict | None) -> str:
    name = None
    if profile:
        name = profile.get("display_name") or profile.get("name")
    if not name:
        name = "Unknown"
    return f"{name}({format_pubkey(pubkey_hex)})"


def event_timestamp_seconds(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    return None


def format_event_date_compact(value) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y%m%d")
    return "unknown"


def format_elapsed_compact(previous_value, current_value) -> str:
    previous_seconds = event_timestamp_seconds(previous_value)
    current_seconds = event_timestamp_seconds(current_value)
    if previous_seconds is None or current_seconds is None:
        return "?"

    delta = max(0.0, current_seconds - previous_seconds)
    if delta < 60:
        return f"{delta:.0f}s"

    minutes = delta / 60
    if minutes < 60:
        return f"{minutes:.1f}m" if minutes < 10 and minutes % 1 else f"{minutes:.0f}m"

    hours = delta / 3600
    if hours < 24:
        return f"{hours:.1f}h" if hours < 10 or hours % 1 else f"{hours:.0f}h"

    days = delta / 86400
    return f"{days:.1f}d" if days < 10 or days % 1 else f"{days:.0f}d"


def summary_token_for_control_event(action: str | None, elapsed: str, label: str) -> str:
    if action == "accept":
        return f"transfer accept/{elapsed}:{label}"
    if action == "terminate":
        return f"terminate/{elapsed}:{label}"
    return f"transfer initiate/{elapsed}:{label}"


def event_to_view(evt: Event) -> dict[str, Any]:
    transferee_hex = transfer_party_from_p_tag(evt)
    return {
        "raw_event": evt,
        "id": evt.id,
        "event_ref": format_event_reference(evt.id),
        "author_hex": evt.pub_key,
        "author_npub": format_pubkey(evt.pub_key),
        "created_at": evt.created_at,
        "kind": evt.kind,
        "d_values": evt.get_tags_value("d"),
        "o_values": evt.get_tags_value("o"),
        "content": evt.content,
        "action": first_tag_value(evt, "action"),
        "prior_event_id": first_tag_value(evt, "e"),
        "transferee_hex": transferee_hex,
        "transferee_npub": format_pubkey(transferee_hex) if transferee_hex else None,
    }


async def build_query_etr_result(
    digest: str,
    relays: str,
    timeout: int = DEFAULT_QUERY_TIMEOUT,
    limit: int = DEFAULT_LIMIT,
    author_pubkey_hex: str | None = None,
    ssl_disable_verify: bool = False,
) -> dict[str, Any]:
    all_events_filter = {"kinds": [DEFAULT_KIND], "#o": [digest], "limit": limit}
    transfer_filter = {"kinds": [CONTROL_TRANSFER_KIND], "#o": [digest], "limit": limit}

    ssl = False if ssl_disable_verify else None
    async with ClientPool(
        relays.split(","),
        query_timeout=timeout,
        timeout=timeout,
        ssl=ssl,
    ) as client:
        all_events = await client.query(
            all_events_filter,
            emulate_single=True,
            wait_connect=True,
            timeout=timeout,
        )
        events = await client.query(
            all_events_filter,
            emulate_single=True,
            wait_connect=True,
            timeout=timeout,
        )
        transfer_events = await client.query(
            transfer_filter,
            emulate_single=True,
            wait_connect=True,
            timeout=timeout,
        )

    Event.sort(all_events, inplace=True, reverse=False)
    Event.sort(events, inplace=True, reverse=False)
    Event.sort(transfer_events, inplace=True, reverse=False)

    profile_cache: dict[str, dict | None] = {}

    async def cached_profile(pubkey_hex: str) -> dict | None:
        if pubkey_hex not in profile_cache:
            profile_cache[pubkey_hex] = await fetch_profile(
                relays=relays,
                pubkey_hex=pubkey_hex,
                timeout=timeout,
                ssl_disable_verify=ssl_disable_verify,
            )
        return profile_cache[pubkey_hex]

    result: dict[str, Any] = {
        "relay_filter": all_events_filter,
        "transfer_filter": transfer_filter,
        "count": len(events),
        "current_profile_author_npub": format_pubkey(author_pubkey_hex) if author_pubkey_hex else None,
        "warning_multiple_origin_events": len(all_events) > 1,
        "no_events": not events,
        "initial_event": None,
        "initial_profile": [],
        "origin_events": [],
        "transfer_groups": [],
        "summary_control_chains": [],
        "current_controller": None,
    }
    if not events:
        return result

    initial_event = events[0]
    initial_profile = await cached_profile(initial_event.pub_key)
    result["initial_event"] = event_to_view(initial_event)
    result["initial_profile"] = compact_profile(initial_profile)
    result["initial_event"]["is_current_profile_author"] = (
        author_pubkey_hex is not None and initial_event.pub_key == author_pubkey_hex
    )

    for evt in events:
        issuer_profile = await cached_profile(evt.pub_key)
        result["origin_events"].append(
            {
                "event": event_to_view(evt),
                "issuer_profile": compact_profile(issuer_profile),
                "is_current_profile_author": author_pubkey_hex is not None and evt.pub_key == author_pubkey_hex,
            }
        )

    if not transfer_events:
        result["summary_control_chains"] = [
            {
                "label": "control chain 1",
                "steps": [
                    {
                        "marker": "++",
                        "label": f"origin/{format_event_date_compact(initial_event.created_at)}:"
                        f"{profile_chain_label(initial_event.pub_key, initial_profile)}",
                    }
                ],
            }
        ]
        result["current_controller"] = {
            "npub": format_pubkey(initial_event.pub_key),
            "basis": "origin issuer",
            "profile": compact_profile(initial_profile),
        }
        return result

    roots, children = group_transfer_events(transfer_events)

    async def transfer_node(evt: Event, row_label: str) -> dict[str, Any]:
        signer_profile = await cached_profile(evt.pub_key)
        transferee_hex = transfer_party_from_p_tag(evt)
        transferee_profile = await cached_profile(transferee_hex) if transferee_hex else None
        return {
            "row_label": row_label,
            "event": event_to_view(evt),
            "signer_profile": compact_profile(signer_profile),
            "transferee_profile": compact_profile(transferee_profile),
            "is_current_profile_author": author_pubkey_hex is not None and evt.pub_key == author_pubkey_hex,
            "children": [
                await transfer_node(child_evt, f"{row_label}.{index}")
                for index, child_evt in enumerate(children.get(evt.id, []), start=1)
            ],
        }

    async def chain_paths_from_event(evt: Event) -> list[list[Event]]:
        child_events = children.get(evt.id, [])
        if not child_events:
            return [[evt]]

        paths: list[list[Event]] = []
        for child_evt in child_events:
            for child_path in await chain_paths_from_event(child_evt):
                paths.append([evt, *child_path])
        return paths

    issuer_label = profile_chain_label(initial_event.pub_key, initial_profile)
    origin_date = format_event_date_compact(initial_event.created_at)

    for group_index, root_evt in enumerate(roots, start=1):
        result["transfer_groups"].append(
            {
                "index": group_index,
                "root_prior_event_id": first_tag_value(root_evt, "e"),
                "root": await transfer_node(root_evt, str(group_index)),
            }
        )

        root_paths = await chain_paths_from_event(root_evt)
        for path_index, event_path in enumerate(root_paths, start=1):
            steps = [{"marker": "++", "label": f"origin/{origin_date}:{issuer_label}"}]
            previous_event = initial_event
            previous_controller_pubkey_hex = initial_event.pub_key
            for evt in event_path:
                transferee_pubkey_hex = transfer_party_from_p_tag(evt) or evt.pub_key
                action = first_tag_value(evt, "action")
                if action != "terminate" and transferee_pubkey_hex == previous_controller_pubkey_hex:
                    previous_event = evt
                    continue
                label = profile_chain_label(
                    transferee_pubkey_hex,
                    await cached_profile(transferee_pubkey_hex),
                )
                elapsed = format_elapsed_compact(previous_event.created_at, evt.created_at)
                token = summary_token_for_control_event(action, elapsed, label)
                marker = "->"
                if token.startswith("terminate/"):
                    marker = "--"
                elif token.startswith("attest "):
                    marker = "=>"
                steps.append({"marker": marker, "label": token})
                previous_event = evt
                previous_controller_pubkey_hex = transferee_pubkey_hex

            label = f"control chain {group_index}"
            if len(root_paths) > 1:
                label = f"{label}.{path_index}"
            result["summary_control_chains"].append({"label": label, "steps": steps})

    latest_transfer_event = max(
        transfer_events,
        key=lambda evt: ((evt.created_at or 0), evt.id),
    )
    latest_action = first_tag_value(latest_transfer_event, "action")
    if latest_action == "terminate":
        current_controller_pubkey_hex = None
        current_controller_basis = "latest control event is a termination"
        current_controller_profile = None
    else:
        current_controller_pubkey_hex = transfer_party_from_p_tag(latest_transfer_event)
        current_controller_basis = "latest control event transferee"
        if current_controller_pubkey_hex is None:
            current_controller_pubkey_hex = latest_transfer_event.pub_key
            current_controller_basis = "latest control event signer (no p tag present)"
        current_controller_profile = await cached_profile(current_controller_pubkey_hex)

    result["current_controller"] = {
        "npub": format_pubkey(current_controller_pubkey_hex) if current_controller_pubkey_hex else None,
        "basis": current_controller_basis,
        "profile": compact_profile(current_controller_profile),
    }
    return result
