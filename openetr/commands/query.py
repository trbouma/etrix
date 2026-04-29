import asyncio
import json
import logging
from pathlib import Path

import click
from monstr.client.client import ClientPool
from monstr.event.event import Event

from openetr.config import (
    CONFIG_AS_USER_KEY,
    DEFAULT_KIND,
    DEFAULT_LIMIT,
    DEFAULT_QUERY_OUTPUT,
    DEFAULT_QUERY_TIMEOUT,
    DEFAULT_RELAYS,
    get_active_profile_name,
    get_profile_config,
    USER_CONFIG_PATH,
    load_user_config,
)

CONTROL_TRANSFER_KIND = 31416
from openetr.helpers import (
    assert_hex_object_identifier,
    assert_hex_pubkey,
    format_event_reference,
    format_object_identifier,
    format_pubkey,
    parse_authors,
    print_event,
    resolve_author,
    resolve_keys,
    resolve_query_digest,
)


def _normalize_nip05(value: str) -> str:
    return value.strip().lower()


async def _fetch_profile(
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

    if not profile:
        return None

    return profile


async def _run_verify_nip05(
    relays: str,
    nip05: str,
    timeout: int,
    ssl_disable_verify: bool,
) -> None:
    try:
        resolved_pubkey_hex = resolve_author(nip05)
    except click.ClickException:
        click.echo("fail")
        raise SystemExit(1)
    resolved_nip05 = _normalize_nip05(nip05)

    profile = await _fetch_profile(
        relays=relays,
        pubkey_hex=resolved_pubkey_hex,
        timeout=timeout,
        ssl_disable_verify=ssl_disable_verify,
    )
    if not profile:
        click.echo("fail")
        raise SystemExit(1)

    profile_nip05 = profile.get("nip05")
    if not profile_nip05:
        click.echo("fail")
        raise SystemExit(1)

    normalized_profile_nip05 = _normalize_nip05(str(profile_nip05))

    if normalized_profile_nip05 != resolved_nip05:
        click.echo("fail")
        raise SystemExit(1)

    click.echo("pass")


def _print_profile(profile: dict) -> None:
    click.echo("profile:")
    for field in ["name", "display_name", "about", "address", "picture", "banner", "website", "nip05", "lud16", "lud06", "lei"]:
        value = profile.get(field)
        if value:
            click.echo(f"  {field}: {value}")

    remaining = {
        key: value
        for key, value in profile.items()
        if key not in {"name", "display_name", "about", "address", "picture", "banner", "website", "nip05", "lud16", "lud06", "lei"}
    }
    for key, value in remaining.items():
        click.echo(f"  {key}: {value}")


def _transfer_party_from_p_tag(event: Event) -> str | None:
    candidate = _first_tag_value(event, "p")
    if candidate is None:
        return None
    if len(candidate) != 64:
        return None
    try:
        int(candidate, 16)
    except ValueError:
        return None
    return candidate.lower()


def _first_tag_value(event: Event, tag_name: str) -> str | None:
    values = event.get_tags_value(tag_name)
    return values[0] if values else None


def _group_transfer_events(transfer_events: list[Event]) -> tuple[list[Event], dict[str, list[Event]]]:
    by_id = {evt.id: evt for evt in transfer_events}
    children: dict[str, list[Event]] = {}
    roots: list[Event] = []

    for evt in transfer_events:
        parent_id = _first_tag_value(evt, "e")
        if parent_id and parent_id in by_id:
            children.setdefault(parent_id, []).append(evt)
        else:
            roots.append(evt)

    def _sort_key(evt: Event) -> tuple[int, str]:
        return (evt.created_at or 0, evt.id)

    roots.sort(key=_sort_key)
    for event_id in children:
        children[event_id].sort(key=_sort_key)

    return roots, children


def _print_event_details(evt: Event, output: str, indent: str = "") -> None:
    if output == "raw":
        click.echo(f"{indent}event:")
        click.echo(f"{indent}{evt.event_data()}")
        click.echo(f"{indent}tags: {evt.tags}")
        click.echo(f"{indent}content: {evt.content}")
        return

    if output == "tags":
        click.echo(f"{indent}event: {evt}")
        click.echo(f"{indent}content: {evt.content}")
        click.echo(f"{indent}tags:")
        for tag in evt.tags:
            click.echo(f"{indent}  {tag}")
        click.echo(f"{indent}total {len(evt.tags)}")
        return

    click.echo(f"{indent}event: {evt}")
    if output == "full":
        click.echo(f"{indent}content payload:")
        for line in evt.content.splitlines() or [""]:
            click.echo(f"{indent}  {line}")
        return

    click.echo(f"{indent}content: {evt.content}")


async def _run_query_object(
    relays: str,
    digest: str,
    authors: list[str] | None,
    limit: int,
    timeout: int,
    output: str,
    ssl_disable_verify: bool,
    digest_file: Path | None,
) -> None:
    ssl = False if ssl_disable_verify else None
    assert_hex_object_identifier(digest)
    if authors:
        for author in authors:
            assert_hex_pubkey(author)

    query_filter = {
        "kinds": [DEFAULT_KIND],
        "#d": [digest],
        "limit": limit,
    }
    if authors:
        query_filter["authors"] = authors

    click.echo(f"Relay filter: {query_filter}")
    if digest_file is not None:
        click.echo(f"Digest source: sha256({digest_file})")

    async with ClientPool(
        relays.split(","),
        query_timeout=timeout,
        timeout=timeout,
        ssl=ssl,
    ) as client:
        events = await client.query(
            query_filter,
            emulate_single=True,
            wait_connect=True,
            timeout=timeout,
        )

    Event.sort(events, inplace=True, reverse=False)
    click.echo(f"Returned {len(events)} event(s)")

    if not events:
        click.echo("0 events found")
        return

    for evt in events:
        d_values = evt.get_tags_value("d")
        o_values = evt.get_tags_value("o")
        click.echo(f"author: {format_pubkey(evt.pub_key)}")
        profile = await _fetch_profile(
            relays=relays,
            pubkey_hex=evt.pub_key,
            timeout=timeout,
            ssl_disable_verify=ssl_disable_verify,
        )
        if profile:
            _print_profile(profile)
        click.echo(f"d values: {d_values}")
        click.echo(f"o values: {o_values}")
        print_event(evt, output)


async def _run_query_etr(
    relays: str,
    digest: str,
    author_pubkey_hex: str | None,
    highlight_profile_author: bool,
    origin_only: bool,
    limit: int,
    timeout: int,
    output: str,
    ssl_disable_verify: bool,
    digest_file: Path | None,
) -> None:
    assert_hex_object_identifier(digest)
    if author_pubkey_hex is not None:
        assert_hex_pubkey(author_pubkey_hex)
    ssl = False if ssl_disable_verify else None
    all_events_filter = {
        "kinds": [DEFAULT_KIND],
        "#o": [digest],
        "limit": limit,
    }
    query_filter = {
        "kinds": [DEFAULT_KIND],
        "#o": [digest],
        "limit": limit,
    }
    if author_pubkey_hex is not None:
        query_filter["authors"] = [author_pubkey_hex]
    transfer_events_filter = {
        "kinds": [CONTROL_TRANSFER_KIND],
        "#o": [digest],
        "limit": limit,
    }
    if author_pubkey_hex is not None:
        transfer_events_filter["authors"] = [author_pubkey_hex]

    click.echo(f"Relays: {relays}")
    click.echo(f"Scope: {'all matching authors' if author_pubkey_hex is None else format_pubkey(author_pubkey_hex)}")
    click.echo(f"Relay filter: {query_filter}")
    click.echo(f"Transfer filter: {transfer_events_filter}")
    if digest_file is not None:
        click.echo(f"Digest source: sha256({digest_file})")

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
            query_filter,
            emulate_single=True,
            wait_connect=True,
            timeout=timeout,
        )
        transfer_events = await client.query(
            transfer_events_filter,
            emulate_single=True,
            wait_connect=True,
            timeout=timeout,
        )

    Event.sort(all_events, inplace=True, reverse=False)
    Event.sort(events, inplace=True, reverse=False)
    Event.sort(transfer_events, inplace=True, reverse=False)
    click.echo(f"Returned {len(events)} event(s)")

    if not events:
        click.echo("0 events found")
        return

    if len(all_events) > 1:
        click.secho(
            "WARNING: multiple ETR origin events (kind 31415) were found for this object. "
            "These records are distinguished by issuer and should not be assumed to represent the same ETR. "
            "Use --all to see all of the origin records in question.",
            fg="yellow",
            bold=True,
        )

    initial_event = events[0]
    click.echo("initial etr origin event (kind 31415):")
    click.echo("-" * 72)
    click.echo(f"object id: {format_object_identifier(digest)}")
    click.echo(f"origin event id: {format_event_reference(initial_event.id)}")
    click.echo(f"issuer: {format_pubkey(initial_event.pub_key)}")
    if highlight_profile_author and author_pubkey_hex is not None and initial_event.pub_key == author_pubkey_hex:
        click.secho("current profile author", fg="blue", bold=True)
    profile = await _fetch_profile(
        relays=relays,
        pubkey_hex=initial_event.pub_key,
        timeout=timeout,
        ssl_disable_verify=ssl_disable_verify,
    )
    if profile:
        click.echo("originator social profile:")
        for field in ["name", "display_name", "about", "address", "picture", "banner", "website", "nip05", "lud16", "lud06", "lei"]:
            value = profile.get(field)
            if value:
                click.echo(f"  {field}: {value}")
    else:
        click.echo("originator social profile: none found")

    d_values = initial_event.get_tags_value("d")
    o_values = initial_event.get_tags_value("o")
    click.echo(f"d values: {d_values}")
    click.echo(f"o values: {o_values}")
    print_event(initial_event, output)

    if len(events) > 1:
        click.echo()
        click.echo("matching etr origin events (kind 31415) for these control events:")
        for index, evt in enumerate(events, start=1):
            click.echo("-" * 72)
            click.echo(f"row: {index}")
            click.echo(f"origin event id: {format_event_reference(evt.id)}")
            click.echo(f"issuer: {format_pubkey(evt.pub_key)}")
            if highlight_profile_author and author_pubkey_hex is not None and evt.pub_key == author_pubkey_hex:
                click.secho("current profile author", fg="blue", bold=True)
            click.echo(f"created_at: {evt.created_at}")
            click.echo(f"object id: {format_object_identifier(digest)}")
            issuer_profile = await _fetch_profile(
                relays=relays,
                pubkey_hex=evt.pub_key,
                timeout=timeout,
                ssl_disable_verify=ssl_disable_verify,
            )
            if issuer_profile:
                click.echo("originator social profile:")
                for field in ["name", "display_name", "about", "address", "picture", "banner", "website", "nip05", "lud16", "lud06", "lei"]:
                    value = issuer_profile.get(field)
                    if value:
                        click.echo(f"  {field}: {value}")
            else:
                click.secho("WARNING: no originator social profile found for this issuer.", fg="yellow", bold=True)

    if origin_only:
        return

    click.echo()
    click.echo("matching control events (kind 31416):")
    if not transfer_events:
        click.echo("No control transfer events were found for this object.")
        return

    roots, children = _group_transfer_events(transfer_events)

    async def _print_transfer_event(evt: Event, row_label: str, depth: int) -> None:
        indent = "  " * depth
        click.echo(f"{indent}event {row_label}:")
        click.echo(f"{indent}  event id: {format_event_reference(evt.id)}")
        click.echo(f"{indent}  author: {format_pubkey(evt.pub_key)}")
        if highlight_profile_author and author_pubkey_hex is not None and evt.pub_key == author_pubkey_hex:
            click.secho(f"{indent}  current profile author", fg="blue", bold=True)
        click.echo(f"{indent}  created_at: {evt.created_at}")
        click.echo(f"{indent}  object id: {format_object_identifier(digest)}")
        action = _first_tag_value(evt, "action")
        if action:
            click.echo(f"{indent}  action: {action}")
        prior_event_id = _first_tag_value(evt, "e")
        if prior_event_id:
            click.echo(f"{indent}  prior event id: {format_event_reference(prior_event_id)}")

        issuer_profile = await _fetch_profile(
            relays=relays,
            pubkey_hex=evt.pub_key,
            timeout=timeout,
            ssl_disable_verify=ssl_disable_verify,
        )
        if issuer_profile:
            click.echo(f"{indent}  social profile:")
            for field in ["name", "display_name", "about", "address", "picture", "banner", "website", "nip05", "lud16", "lud06", "lei"]:
                value = issuer_profile.get(field)
                if value:
                    click.echo(f"{indent}    {field}: {value}")
        else:
            click.secho(f"{indent}  WARNING: no social profile found for this author.", fg="yellow", bold=True)

        d_values = evt.get_tags_value("d")
        o_values = evt.get_tags_value("o")
        transferee_pubkey_hex = _transfer_party_from_p_tag(evt)
        if transferee_pubkey_hex is not None:
            click.echo(f"{indent}  transferee: {format_pubkey(transferee_pubkey_hex)}")
            transferee_profile = await _fetch_profile(
                relays=relays,
                pubkey_hex=transferee_pubkey_hex,
                timeout=timeout,
                ssl_disable_verify=ssl_disable_verify,
            )
            if transferee_profile:
                click.echo(f"{indent}  transferee social profile:")
                for field in ["name", "display_name", "about", "address", "picture", "banner", "website", "nip05", "lud16", "lud06", "lei"]:
                    value = transferee_profile.get(field)
                    if value:
                        click.echo(f"{indent}    {field}: {value}")
            else:
                click.secho(f"{indent}  WARNING: no social profile found for the transferee.", fg="yellow", bold=True)
        click.echo(f"{indent}  d values: {d_values}")
        click.echo(f"{indent}  o values: {o_values}")
        _print_event_details(evt, output, indent=f"{indent}  ")

        for child_index, child_evt in enumerate(children.get(evt.id, []), start=1):
            await _print_transfer_event(child_evt, f"{row_label}.{child_index}", depth + 1)

    for group_index, root_evt in enumerate(roots, start=1):
        click.echo("=" * 72)
        click.echo(f"control event group {group_index}:")
        root_prior_event_id = _first_tag_value(root_evt, "e")
        if root_prior_event_id:
            click.echo(f"  root prior event id: {format_event_reference(root_prior_event_id)}")
        click.echo("  control chain:")
        await _print_transfer_event(root_evt, str(group_index), 0)

def _resolve_profile_pubkey(profile: str, author: str | None, as_user: str | None) -> str:
    if author is not None:
        return resolve_author(author)

    if as_user is not None:
        return resolve_keys(as_user).public_key_hex()

    profile_config = get_profile_config(profile, load_user_config())
    configured_key = profile_config.get(CONFIG_AS_USER_KEY)
    if configured_key:
        return resolve_keys(configured_key).public_key_hex()

    raise click.ClickException(
        f"No --author or --as-user value was supplied and no key exists in {USER_CONFIG_PATH}."
    )


def _confirm_temporary_identity_override(profile: str, as_user: str | None, force: bool) -> None:
    if as_user is None:
        return

    profile_config = get_profile_config(profile, load_user_config())
    configured_key = profile_config.get(CONFIG_AS_USER_KEY)
    if not configured_key:
        return

    configured_keys = resolve_keys(configured_key)
    override_keys = resolve_keys(as_user)
    if configured_keys.public_key_hex() == override_keys.public_key_hex() or force:
        return

    click.secho(
        "WARNING: this command is using a temporary identity that differs from the current profile.",
        fg="yellow",
        bold=True,
    )
    click.echo(f"Profile:          {profile}")
    click.echo(f"Profile signer:   {configured_keys.public_key_bech32()}")
    click.echo(f"Temporary signer: {override_keys.public_key_bech32()}")
    click.confirm(
        click.style("Continue with the temporary identity override?", fg="yellow", bold=True),
        default=False,
        abort=True,
    )


async def _run_query_profile(
    relays: str,
    pubkey_hex: str,
    timeout: int,
    ssl_disable_verify: bool,
) -> None:
    ssl = False if ssl_disable_verify else None
    assert_hex_pubkey(pubkey_hex)

    query_filter = {
        "authors": [pubkey_hex],
        "kinds": [0],
        "limit": 1,
    }

    click.echo(f"Pubkey:  {format_pubkey(pubkey_hex)}")
    click.echo(f"Relay filter: {query_filter}")

    profile = await _fetch_profile(
        relays=relays,
        pubkey_hex=pubkey_hex,
        timeout=timeout,
        ssl_disable_verify=ssl_disable_verify,
    )

    if not profile:
        click.echo("No kind 0 profile event found.")
        return

    _print_profile(profile)


@click.command("query-object")
@click.option("--profile", default=None, help="Profile to use; defaults to the active profile.")
@click.option("--relays", default=None, help="Comma separated relay URLs to query.")
@click.option("--digest", default=None, help="nobj or 64-character hex digest to query for.")
@click.option(
    "--digest-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a file to hash with SHA-256 and use as the d filter value.",
)
@click.option(
    "--authors",
    default=None,
    help="Comma separated npub author pubkeys to narrow the query.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Result limit.",
)
@click.option(
    "--timeout",
    type=int,
    default=None,
    help="Query timeout in seconds.",
)
@click.option(
    "--output",
    type=click.Choice(["heads", "full", "raw", "tags"]),
    default=None,
    help="Output format.",
)
@click.option("--ssl-disable-verify", is_flag=True, help="Disable SSL certificate verification.")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def query_object(
    profile: str | None,
    relays: str | None,
    digest: str | None,
    digest_file: Path | None,
    authors: str | None,
    limit: int | None,
    timeout: int | None,
    output: str | None,
    ssl_disable_verify: bool,
    debug: bool,
) -> None:
    """Query for replaceable kind 31415 events using the d tag value."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    profile_config = get_profile_config(profile or get_active_profile_name())
    resolved_relays = relays or profile_config.get("relays", DEFAULT_RELAYS)
    resolved_limit = limit if limit is not None else profile_config.get("limit", DEFAULT_LIMIT)
    resolved_timeout = timeout if timeout is not None else profile_config.get("query_timeout", DEFAULT_QUERY_TIMEOUT)
    resolved_output = output or profile_config.get("query_output", DEFAULT_QUERY_OUTPUT)

    resolved_digest, resolved_file = resolve_query_digest(digest, digest_file)
    parsed_authors = parse_authors(authors)

    asyncio.run(
        _run_query_object(
            relays=resolved_relays,
            digest=resolved_digest,
            authors=parsed_authors,
            limit=resolved_limit,
            timeout=resolved_timeout,
            output=resolved_output,
            ssl_disable_verify=ssl_disable_verify,
            digest_file=resolved_file,
        )
    )


@click.command("query-etr")
@click.option("--profile", default=None, help="Profile to use; defaults to the active profile.")
@click.option("--relays", default=None, help="Comma separated relay URLs to query.")
@click.option("--digest", default=None, help="nobj or 64-character hex digest to query for.")
@click.option(
    "--digest-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a file to hash with SHA-256 and use as the d filter value.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Result limit.",
)
@click.option(
    "--timeout",
    type=int,
    default=None,
    help="Query timeout in seconds.",
)
@click.option(
    "--output",
    type=click.Choice(["heads", "full", "raw", "tags"]),
    default=None,
    help="Output format.",
)
@click.option("--origin", is_flag=True, help="Restrict output to origin records only.")
@click.option("--all", "show_all", is_flag=True, help="Show ETR events from all authors instead of only the current profile.")
@click.option("--ssl-disable-verify", is_flag=True, help="Disable SSL certificate verification.")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def query_etr(
    profile: str | None,
    relays: str | None,
    digest: str | None,
    digest_file: Path | None,
    limit: int | None,
    timeout: int | None,
    output: str | None,
    origin: bool,
    show_all: bool,
    ssl_disable_verify: bool,
    debug: bool,
) -> None:
    """Query an ETR object and display its initial record and issuer profile."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    profile_name = profile or get_active_profile_name()
    profile_config = get_profile_config(profile_name)
    resolved_relays = relays or profile_config.get("relays", DEFAULT_RELAYS)
    resolved_limit = limit if limit is not None else profile_config.get("limit", DEFAULT_LIMIT)
    resolved_timeout = timeout if timeout is not None else profile_config.get("query_timeout", DEFAULT_QUERY_TIMEOUT)
    resolved_output = output or profile_config.get("query_output", DEFAULT_QUERY_OUTPUT)

    resolved_digest, resolved_file = resolve_query_digest(digest, digest_file)
    author_pubkey_hex = None
    if not show_all:
        configured_key = profile_config.get(CONFIG_AS_USER_KEY)
        if not configured_key:
            raise click.ClickException(
            "the current profile has no as_user key; use --all or set an nsec for this profile"
        )
        author_pubkey_hex = resolve_keys(configured_key).public_key_hex()

    if origin:
        click.echo("Mode: origin records only")

    asyncio.run(
        _run_query_etr(
            relays=resolved_relays,
            digest=resolved_digest,
            author_pubkey_hex=author_pubkey_hex,
            highlight_profile_author=show_all,
            origin_only=origin,
            limit=resolved_limit,
            timeout=resolved_timeout,
            output=resolved_output,
            ssl_disable_verify=ssl_disable_verify,
            digest_file=resolved_file,
        )
    )


@click.command("query-profile")
@click.option("--profile", default=None, help="Profile to use; defaults to the active profile.")
@click.option("--relays", default=None, help="Comma separated relay URLs to query.")
@click.option(
    "--as-user",
    default=None,
    help="nsec private key to look up; loaded from config if omitted.",
)
@click.option("--force", is_flag=True, help="Suppress confirmation prompts.")
@click.option(
    "--author",
    default=None,
    help="npub public key to look up; takes precedence over --as-user if supplied.",
)
@click.option(
    "--timeout",
    type=int,
    default=None,
    help="Query timeout in seconds.",
)
@click.option("--ssl-disable-verify", is_flag=True, help="Disable SSL certificate verification.")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def query_profile(
    profile: str | None,
    relays: str | None,
    as_user: str | None,
    force: bool,
    author: str | None,
    timeout: int | None,
    ssl_disable_verify: bool,
    debug: bool,
) -> None:
    """Look up the Nostr kind 0 social profile for an npub, NIP-05 name, or nsec."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    profile_config = get_profile_config(profile or get_active_profile_name())
    resolved_relays = relays or profile_config.get("relays", DEFAULT_RELAYS)
    resolved_timeout = timeout if timeout is not None else profile_config.get("query_timeout", DEFAULT_QUERY_TIMEOUT)

    profile_name = profile or get_active_profile_name()
    _confirm_temporary_identity_override(profile_name, as_user, force)
    pubkey_hex = _resolve_profile_pubkey(profile_name, author, as_user)
    asyncio.run(
        _run_query_profile(
            relays=resolved_relays,
            pubkey_hex=pubkey_hex,
            timeout=resolved_timeout,
            ssl_disable_verify=ssl_disable_verify,
        )
    )


@click.command("verify")
@click.option("--profile", default=None, help="Profile to use; defaults to the active profile.")
@click.option("--relays", default=None, help="Comma separated relay URLs to query.")
@click.option("--nip05", default=None, help="NIP-05 address to resolve and verify against kind 0 metadata.")
@click.option(
    "--timeout",
    type=int,
    default=None,
    help="Query timeout in seconds.",
)
@click.option("--ssl-disable-verify", is_flag=True, help="Disable SSL certificate verification.")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def verify(
    profile: str | None,
    relays: str | None,
    nip05: str | None,
    timeout: int | None,
    ssl_disable_verify: bool,
    debug: bool,
) -> None:
    """Verify a NIP-05 identifier against the resolved pubkey and its kind 0 profile metadata."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    if not nip05:
        raise click.ClickException("supply --nip05 with the NIP-05 identifier to verify")

    profile_config = get_profile_config(profile or get_active_profile_name())
    resolved_relays = relays or profile_config.get("relays", DEFAULT_RELAYS)
    resolved_timeout = timeout if timeout is not None else profile_config.get("query_timeout", DEFAULT_QUERY_TIMEOUT)

    asyncio.run(
        _run_verify_nip05(
            relays=resolved_relays,
            nip05=nip05,
            timeout=resolved_timeout,
            ssl_disable_verify=ssl_disable_verify,
        )
    )
