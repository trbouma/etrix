import asyncio
import json
import logging
from pathlib import Path
from typing import Any

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
from openetr.services.query_etr import build_query_etr_result


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


def _print_event_details(evt: Event, output: str, indent: str = "", verbose: bool = False) -> None:
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

    if verbose:
        click.echo(f"{indent}event: {evt}")
    if output == "full":
        click.echo(f"{indent}content:")
        for line in evt.content.splitlines() or [""]:
            click.echo(f"{indent}  {line}")
        return

    click.echo(f"{indent}content: {evt.content}")


def _print_separator(indent: str = "", width: int = 72, char: str = "-") -> None:
    click.echo(f"{indent}{char * width}")


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
        click.echo(f"d value: {d_values}")
        click.echo(f"o value: {o_values}")
        print_event(evt, output)


async def _run_query_etr(
    relays: str,
    digest: str,
    author_pubkey_hex: str | None,
    origin_only: bool,
    verbose: bool,
    limit: int,
    timeout: int,
    output: str,
    ssl_disable_verify: bool,
    digest_file: Path | None,
) -> None:
    assert_hex_object_identifier(digest)
    if author_pubkey_hex is not None:
        assert_hex_pubkey(author_pubkey_hex)
    result = await build_query_etr_result(
        digest=digest,
        relays=relays,
        timeout=timeout,
        limit=limit,
        author_pubkey_hex=author_pubkey_hex,
        ssl_disable_verify=ssl_disable_verify,
    )

    if verbose:
        click.echo(f"Relays: {relays}")
        click.echo("Scope: object-wide")
        if author_pubkey_hex is not None:
            click.echo(f"Current profile: {format_pubkey(author_pubkey_hex)}")
        click.echo(f"Relay filter: {result['relay_filter']}")
        click.echo(f"Transfer filter: {result['transfer_filter']}")
        if digest_file is not None:
            click.echo(f"Digest source: sha256({digest_file})")
        click.echo(f"Returned {result['count']} event(s)")

    if result["no_events"]:
        click.echo("0 events found")
        return

    if result["warning_multiple_origin_events"]:
        click.secho(
            "WARNING: multiple ETR origin events (kind 31415) were found for this object. "
            "These records are distinguished by issuer and should not be assumed to represent the same ETR. "
            "Use --all to see all of the origin records in question.",
            fg="yellow",
            bold=True,
        )

    initial_event = result["initial_event"]
    click.echo("initial etr origin event (kind 31415):")
    _print_separator()
    click.echo(f"object id: {format_object_identifier(digest)}")
    click.echo(f"origin event id: {initial_event['event_ref']}")
    click.echo(f"issuer: {initial_event['author_npub']}")
    if initial_event.get("is_current_profile_author"):
        click.secho("current profile author", fg="blue", bold=True)
    if result["initial_profile"]:
        click.echo("issuer social profile:")
        for field, value in result["initial_profile"]:
            click.echo(f"  {field}: {value}")
    else:
        click.echo("issuer social profile: none found")

    click.echo(f"d value: {initial_event['d_values']}")
    click.echo(f"o value: {initial_event['o_values']}")
    print_event(initial_event["raw_event"], output)
    _print_separator()

    if len(result["origin_events"]) > 1:
        click.echo()
        click.echo("matching etr origin events (kind 31415) for these control events:")
        for index, item in enumerate(result["origin_events"], start=1):
            evt = item["event"]
            _print_separator()
            click.echo(f"row: {index}")
            click.echo(f"origin event id: {evt['event_ref']}")
            click.echo(f"issuer: {evt['author_npub']}")
            if item.get("is_current_profile_author"):
                click.secho("current profile author", fg="blue", bold=True)
            click.echo(f"created_at: {evt['created_at']}")
            click.echo(f"object id: {format_object_identifier(digest)}")
            if item["issuer_profile"]:
                click.echo("issuer social profile:")
                for field, value in item["issuer_profile"]:
                    click.echo(f"  {field}: {value}")
            else:
                click.secho("WARNING: no issuer social profile found for this issuer.", fg="yellow", bold=True)
            _print_separator()

    if origin_only:
        click.echo()
        click.echo("current controller:")
        click.echo(f"  npub: {result['current_controller']['npub']}")
        click.echo(f"  basis: {result['current_controller']['basis']}")
        if result["current_controller"]["profile"]:
            click.echo("  current controller social profile:")
            for field, value in result["current_controller"]["profile"]:
                click.echo(f"    {field}: {value}")
        return

    click.echo()
    click.echo("matching control events (kind 31416):")
    if not result["transfer_groups"]:
        click.echo("No control transfer events were found for this object.")
        click.echo()
        click.echo("current controller:")
        click.echo(f"  npub: {result['current_controller']['npub']}")
        click.echo(f"  basis: {result['current_controller']['basis']}")
        if result["current_controller"]["profile"]:
            click.echo("  current controller social profile:")
            for field, value in result["current_controller"]["profile"]:
                click.echo(f"    {field}: {value}")
        return

    def _print_transfer_node(node: dict[str, Any], depth: int = 0) -> None:
        indent = "  " * depth
        evt = node["event"]
        _print_separator(indent)
        click.echo(f"{indent}event {node['row_label']}:")
        click.echo(f"{indent}  event id: {evt['event_ref']}")
        click.echo(f"{indent}  author: {evt['author_npub']}")
        if node.get("is_current_profile_author"):
            click.secho(f"{indent}  current profile author", fg="blue", bold=True)
        click.echo(f"{indent}  created_at: {evt['created_at']}")
        click.echo(f"{indent}  object id: {format_object_identifier(digest)}")
        if evt["action"]:
            click.echo(f"{indent}  action: {evt['action']}")
        if evt["prior_event_id"]:
            click.echo(f"{indent}  prior event id: {format_event_reference(evt['prior_event_id'])}")
        if node["signer_profile"]:
            click.echo(f"{indent}  transfer event signer social profile:")
            for field, value in node["signer_profile"]:
                click.echo(f"{indent}    {field}: {value}")
        else:
            click.secho(f"{indent}  WARNING: no transfer event signer social profile found for this author.", fg="yellow", bold=True)
        if evt["transferee_npub"] is not None:
            click.echo(f"{indent}  transferee: {evt['transferee_npub']}")
            if node["transferee_profile"]:
                click.echo(f"{indent}  transferee social profile:")
                for field, value in node["transferee_profile"]:
                    click.echo(f"{indent}    {field}: {value}")
            else:
                click.secho(f"{indent}  WARNING: no social profile found for the transferee.", fg="yellow", bold=True)
        click.echo(f"{indent}  d value: {evt['d_values']}")
        click.echo(f"{indent}  o value: {evt['o_values']}")
        _print_event_details(evt["raw_event"], output, indent=f"{indent}  ", verbose=verbose)
        _print_separator(indent)
        for child in node["children"]:
            _print_transfer_node(child, depth + 1)

    for group in result["transfer_groups"]:
        click.echo("=" * 72)
        click.echo(f"control event group {group['index']}:")
        root_prior_event_id = group["root_prior_event_id"]
        if root_prior_event_id:
            click.echo(f"  root prior event id: {format_event_reference(root_prior_event_id)}")
        click.echo("  control chain:")
        _print_transfer_node(group["root"], 0)

    click.echo()
    if digest_file is not None:
        click.echo(f"summary control chain for {digest_file}:")
    else:
        click.echo("summary control chain:")
    click.echo("  legend: ++ origin, -> transfer initiate/accept, -- terminate, => attest initiate/accept")
    for chain in result["summary_control_chains"]:
        click.echo(f"  {chain['label']}:")
        for step in chain["steps"]:
            click.echo(f"    {step['marker']} {step['label']}")

    current_controller = result["current_controller"]
    click.echo()
    click.echo("current controller:")
    if current_controller["npub"] is None:
        click.secho("  npub: none", fg="yellow", bold=True)
    else:
        click.echo(f"  npub: {current_controller['npub']}")
    if current_controller["npub"] is None:
        click.secho(f"  basis: {current_controller['basis']}", fg="yellow", bold=True)
    else:
        click.echo(f"  basis: {current_controller['basis']}")
    if current_controller["npub"] is not None and current_controller["profile"]:
            click.echo("  current controller social profile:")
            for field, value in current_controller["profile"]:
                click.echo(f"    {field}: {value}")

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
@click.argument("digest_file", required=False, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--profile", default=None, help="Profile to use; defaults to the active profile.")
@click.option("--relays", default=None, help="Comma separated relay URLs to query.")
@click.option("--digest", default=None, help="nobj or 64-character hex digest to query for.")
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
@click.option("--verbose", is_flag=True, help="Show relay, filter, and query diagnostics.")
@click.option("--origin", is_flag=True, help="Restrict output to origin records only.")
@click.option("--all", "show_all", is_flag=True, help="Deprecated; query-etr is object-wide by default.")
@click.option("--ssl-disable-verify", is_flag=True, help="Disable SSL certificate verification.")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def query_etr(
    digest_file: Path | None,
    profile: str | None,
    relays: str | None,
    digest: str | None,
    limit: int | None,
    timeout: int | None,
    output: str | None,
    verbose: bool,
    origin: bool,
    show_all: bool,
    ssl_disable_verify: bool,
    debug: bool,
) -> None:
    """Query an ETR object and display its initial record and issuer profile."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    if digest is not None and digest_file is not None:
        raise click.ClickException("supply either DIGEST_FILE as an argument or --digest, not both")

    profile_name = profile or get_active_profile_name()
    profile_config = get_profile_config(profile_name)
    resolved_relays = relays or profile_config.get("relays", DEFAULT_RELAYS)
    resolved_limit = limit if limit is not None else profile_config.get("limit", DEFAULT_LIMIT)
    resolved_timeout = timeout if timeout is not None else profile_config.get("query_timeout", DEFAULT_QUERY_TIMEOUT)
    resolved_output = output or profile_config.get("query_output", DEFAULT_QUERY_OUTPUT)

    resolved_digest, resolved_file = resolve_query_digest(digest, digest_file)
    configured_key = profile_config.get(CONFIG_AS_USER_KEY)
    author_pubkey_hex = resolve_keys(configured_key).public_key_hex() if configured_key else None

    if origin:
        click.echo("Mode: origin records only")

    asyncio.run(
        _run_query_etr(
            relays=resolved_relays,
            digest=resolved_digest,
            author_pubkey_hex=author_pubkey_hex,
            origin_only=origin,
            verbose=verbose,
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
