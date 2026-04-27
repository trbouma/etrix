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
from openetr.helpers import (
    format_object_identifier,
    format_pubkey,
    parse_authors,
    print_event,
    resolve_author,
    resolve_keys,
    resolve_query_digest,
)


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


def _print_profile(profile: dict) -> None:
    click.echo("profile:")
    for field in ["name", "display_name", "about", "picture", "banner", "website", "nip05", "lud16", "lud06"]:
        value = profile.get(field)
        if value:
            click.echo(f"  {field}: {value}")

    remaining = {
        key: value
        for key, value in profile.items()
        if key not in {"name", "display_name", "about", "picture", "banner", "website", "nip05", "lud16", "lud06"}
    }
    for key, value in remaining.items():
        click.echo(f"  {key}: {value}")


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
        click.echo(f"d values: {[format_object_identifier(value) for value in d_values]}")
        click.echo(f"o values: {[format_object_identifier(value) for value in o_values]}")
        print_event(evt, output)

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


async def _run_query_profile(
    relays: str,
    pubkey_hex: str,
    timeout: int,
    ssl_disable_verify: bool,
) -> None:
    ssl = False if ssl_disable_verify else None

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


@click.command("query-profile")
@click.option("--profile", default=None, help="Profile to use; defaults to the active profile.")
@click.option("--relays", default=None, help="Comma separated relay URLs to query.")
@click.option(
    "--as-user",
    default=None,
    help="nsec private key to look up; loaded from config if omitted.",
)
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
    pubkey_hex = _resolve_profile_pubkey(profile_name, author, as_user)
    asyncio.run(
        _run_query_profile(
            relays=resolved_relays,
            pubkey_hex=pubkey_hex,
            timeout=resolved_timeout,
            ssl_disable_verify=ssl_disable_verify,
        )
    )
