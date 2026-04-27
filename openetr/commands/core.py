from importlib.metadata import PackageNotFoundError, metadata as package_metadata, version as package_version
from importlib.resources import files
import asyncio
import json
from pathlib import Path
from random import choice

import click
from monstr.client.client import ClientPool
from monstr.event.event import Event
import yaml

from openetr.config import (
    CONFIG_AS_USER_KEY,
    DEFAULT_QUERY_TIMEOUT,
    DEFAULT_RELAYS,
    ACTIVE_PROFILE_KEY,
    DEFAULT_PROFILE_NAME,
    PROFILES_KEY,
    USER_CONFIG_DIR,
    USER_CONFIG_PATH,
    delete_profile,
    ensure_profile,
    get_active_profile_name,
    get_profile_config,
    list_profiles,
    load_user_config,
    render_user_config_template,
    set_active_profile,
    upsert_profile_config,
    write_user_config,
)
from openetr.helpers import (
    GENERATE_LEI_SENTINEL,
    format_object_identifier,
    format_pubkey,
    parse_authors,
    resolve_lei,
    resolve_keys,
    resolve_query_digest,
    validate_lei,
    validate_npub,
)

MLETR_TRIVIA_PATH = files("openetr").joinpath("mletr_trivia.yaml")


def _load_mletr_trivia_facts() -> list[str]:
    with MLETR_TRIVIA_PATH.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    facts = data.get("facts", [])
    if not facts:
        raise click.ClickException("No MLETR trivia facts were found in the packaged data file.")

    return [str(fact) for fact in facts]


def _normalize_relays(relays: str) -> str:
    normalized = []
    for item in relays.split(","):
        cleaned = item.strip()
        if not cleaned:
            continue
        if not cleaned.startswith("wss://") and not cleaned.startswith("ws://"):
            cleaned = f"wss://{cleaned}"
        normalized.append(cleaned)

    if not normalized:
        raise click.ClickException("relays must contain at least one relay URL")

    return ",".join(normalized)


def _profile_updates(
    as_user: str | None,
    relays: str | None,
    kind: int | None,
    query_timeout: int | None,
    publish_wait: float | None,
    limit: int | None,
    query_output: str | None,
    authors: str | None,
    lei: str | None,
) -> dict:
    updates = {}

    if as_user is not None:
        updates["as_user"] = resolve_keys(as_user).private_key_bech32()
    if relays is not None:
        updates["relays"] = _normalize_relays(relays)
    if kind is not None:
        updates["kind"] = kind
    if query_timeout is not None:
        updates["query_timeout"] = query_timeout
    if publish_wait is not None:
        updates["publish_wait"] = publish_wait
    if limit is not None:
        updates["limit"] = limit
    if query_output is not None:
        updates["query_output"] = query_output
    if authors is not None:
        parse_authors(authors)
        updates["authors"] = [author.strip() for author in authors.split(",") if author.strip()]
    if lei is not None:
        updates["lei"] = resolve_lei(lei)

    return updates


def _print_profile_config(profile: str, resolved: dict, is_active: bool) -> None:
    marker = " (active)" if is_active else ""
    click.echo(f"{profile}{marker}:")
    for key, value in resolved.items():
        click.echo(f"  {key}: {value}")


async def _fetch_kind0_profile(relays: str, pubkey_hex: str, timeout: int) -> dict | None:
    async with ClientPool(
        relays.split(","),
        query_timeout=timeout,
        timeout=timeout,
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


def _print_social_profile(profile: dict) -> None:
    click.echo("social profile:")
    ordered_fields = [
        "name",
        "display_name",
        "about",
        "picture",
        "banner",
        "website",
        "nip05",
        "lud16",
        "lud06",
    ]
    for field in ordered_fields:
        value = profile.get(field)
        if value:
            click.echo(f"  {field}: {value}")

    for key, value in profile.items():
        if key not in set(ordered_fields) and value:
            click.echo(f"  {key}: {value}")


def _package_info() -> dict[str, str]:
    fallback = {
        "name": "openetr",
        "version": "0.1.0",
        "summary": "openetr - durable control portable records",
        "license": "MIT License",
        "author": "trbouma <trbouma@gmail.com>",
    }

    try:
        meta = package_metadata("openetr")
    except PackageNotFoundError:
        return fallback

    return {
        "name": meta.get("Name", fallback["name"]),
        "version": meta.get("Version", fallback["version"]),
        "summary": meta.get("Summary", fallback["summary"]),
        "license": meta.get("License", fallback["license"]),
        "author": meta.get("Author-email", meta.get("Author", fallback["author"])),
    }


@click.command()
@click.option("--banner", is_flag=True, help="Display the OpenETR banner.")
def version(banner: bool) -> None:
    """Show the CLI version."""
    try:
        current_version = package_version("openetr")
    except PackageNotFoundError:
        current_version = "0.1.0"

    if banner:
        click.echo(
            "\n".join(
                [
                    "  ____                   ______ _______ ____  ",
                    " / __ \\____  ___  ____  / ____//_  __// __ \\ ",
                    "/ / / / __ \\/ _ \\/ __ \\/ __/    / /  / /_/ / ",
                    "/ /_/ / /_/ /  __/ / / / /___   / /  / _, _/  ",
                    "\\____/ .___/\\___/_/ /_/_____/  /_/  /_/ |_|   ",
                    "    /_/                                        ",
                    "",
                    f"OpenETR {current_version}",
                ]
            )
        )
        return

    click.echo(f"openetr {current_version}")


@click.command("info")
def info() -> None:
    """Show package, license, release, and local runtime information."""
    package = _package_info()
    config = load_user_config()
    profiles = list_profiles(config)
    active_profile = get_active_profile_name(config)
    active_profile_config = get_profile_config(active_profile, config)

    click.echo("OpenETR")
    click.echo(f"  Name: {package['name']}")
    click.echo(f"  Current release: {package['version']}")
    click.echo(f"  Summary: {package['summary']}")
    click.echo(f"  License: {package['license']}")
    click.echo(f"  Author: {package['author']}")
    click.echo("  Entry point: openetr")
    click.echo("")
    click.echo("Resources")
    click.echo(f"  Packaged defaults: {files('openetr').joinpath('defaults.yaml')}")
    click.echo(f"  Packaged trivia: {MLETR_TRIVIA_PATH}")
    click.echo(f"  MLETR trivia facts: {len(_load_mletr_trivia_facts())}")
    click.echo("")
    click.echo("Config")
    click.echo(f"  Config directory: {USER_CONFIG_DIR}")
    click.echo(f"  Config file: {USER_CONFIG_PATH}")
    click.echo(f"  Config exists: {'yes' if USER_CONFIG_PATH.exists() else 'no'}")
    click.echo(f"  Active profile: {active_profile}")
    click.echo(f"  Profiles: {', '.join(profiles)}")
    click.echo(f"  Active relays: {active_profile_config.get('relays')}")
    click.echo(f"  Default kind: {active_profile_config.get('kind')}")
    click.echo(f"  Query timeout: {active_profile_config.get('query_timeout')}")
    click.echo(f"  Publish wait: {active_profile_config.get('publish_wait')}")
    click.echo(f"  Query limit: {active_profile_config.get('limit')}")
    click.echo(f"  Query output: {active_profile_config.get('query_output')}")


@click.command("get-object-id")
@click.option(
    "--digest-file",
    required=True,
    type=click.Path(exists=False, dir_okay=False, path_type=str),
    help="Path to the file to hash with SHA-256.",
)
@click.option("--bech32", is_flag=True, help="Return the object identifier as an nobj bech32 value.")
def get_object_id(digest_file: str, bech32: bool) -> None:
    """Return the object identifier for a file in a pipe-friendly format."""
    digest_hex, _ = resolve_query_digest(digest=None, digest_file=Path(digest_file))
    click.echo(format_object_identifier(digest_hex) if bech32 else digest_hex)


@click.command("validate")
@click.option("--lei", default=None, help="Validate a Legal Entity Identifier.")
@click.option("--npub", default=None, help="Validate a Nostr npub bech32 public key.")
def validate(lei: str | None, npub: str | None) -> None:
    """Validate a supported identifier and return a pipe-friendly result."""
    if (lei is None and npub is None) or (lei is not None and npub is not None):
        raise click.ClickException("supply exactly one of --lei or --npub")

    is_valid = validate_lei(lei) if lei is not None else validate_npub(npub)
    click.echo("valid" if is_valid else "invalid")
    if not is_valid:
        raise SystemExit(1)


@click.command("init-config")
@click.option("--force", is_flag=True, help="Overwrite an existing ~/.openetr/config.yaml file.")
def init_config(force: bool) -> None:
    """Create a user config file at ~/.openetr/config.yaml."""
    if USER_CONFIG_PATH.exists() and not force:
        raise click.ClickException(
            f"Config already exists at {USER_CONFIG_PATH}. Use --force to overwrite it."
        )

    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    USER_CONFIG_PATH.write_text(render_user_config_template(), encoding="utf-8")
    click.echo(f"Wrote config to {USER_CONFIG_PATH}")


@click.group("profile")
def profile_group() -> None:
    """Manage OpenETR profiles."""


@profile_group.command("list")
def profile_list() -> None:
    """List configured profiles."""
    config = load_user_config()
    active = get_active_profile_name(config)
    profiles = list_profiles(config)

    click.echo(f"Profiles in {USER_CONFIG_PATH}:")
    for name in profiles:
        marker = " *" if name == active else ""
        click.echo(f"  {name}{marker}")


@profile_group.command("show")
@click.argument("profile", required=False)
def profile_show(profile: str | None) -> None:
    """Show the resolved config for a profile."""
    config = load_user_config()
    profile_name = profile or get_active_profile_name(config)
    resolved = get_profile_config(profile_name, config)
    _print_profile_config(profile_name, resolved, profile_name == get_active_profile_name(config))

    configured_key = resolved.get(CONFIG_AS_USER_KEY)
    if not configured_key:
        return

    pubkey_hex = resolve_keys(configured_key).public_key_hex()
    resolved_relays = resolved.get("relays", DEFAULT_RELAYS)
    resolved_timeout = resolved.get("query_timeout", DEFAULT_QUERY_TIMEOUT)

    click.echo(f"pubkey: {format_pubkey(pubkey_hex)}")
    social_profile = asyncio.run(
        _fetch_kind0_profile(
            relays=resolved_relays,
            pubkey_hex=pubkey_hex,
            timeout=resolved_timeout,
        )
    )
    if social_profile:
        _print_social_profile(social_profile)
    else:
        click.echo("social profile: none found")


@profile_group.command("use")
@click.argument("profile")
def profile_use(profile: str) -> None:
    """Set the active profile."""
    set_active_profile(profile)
    click.echo(f"Active profile set to {profile}")


@profile_group.command("delete")
@click.argument("profile")
@click.option("--force", is_flag=True, help="Delete the profile without confirmation.")
def profile_delete(profile: str, force: bool) -> None:
    """Delete a profile."""
    if profile == DEFAULT_PROFILE_NAME and not force:
        raise click.ClickException("Refusing to delete the default profile without --force.")

    if not force:
        click.confirm(f"Delete profile '{profile}'?", abort=True)

    delete_profile(profile)
    click.echo(f"Deleted profile {profile}")


@profile_group.command("set")
@click.argument("profile", required=False)
@click.option("--as-user", default=None, help="Set the default nsec private key.")
@click.option("--relays", default=None, help="Set the default relay URL or comma-separated relay pool.")
@click.option("--kind", type=int, default=None, help="Set the default event kind.")
@click.option("--query-timeout", type=int, default=None, help="Set the default query timeout in seconds.")
@click.option("--publish-wait", type=float, default=None, help="Set the default publish wait in seconds.")
@click.option("--limit", type=int, default=None, help="Set the default query result limit.")
@click.option(
    "--query-output",
    type=click.Choice(["heads", "full", "raw", "tags"]),
    default=None,
    help="Set the default query output format.",
)
@click.option("--authors", default=None, help="Validate one or more comma-separated npub values before saving.")
@click.option(
    "--lei",
    default=None,
    flag_value=GENERATE_LEI_SENTINEL,
    help="Set a legal entity identifier, or pass --lei with no value to generate an example LEI.",
)
def profile_set(
    profile: str | None,
    as_user: str | None,
    relays: str | None,
    kind: int | None,
    query_timeout: int | None,
    publish_wait: float | None,
    limit: int | None,
    query_output: str | None,
    authors: str | None,
    lei: str | None,
) -> None:
    """Update or show a profile."""
    config = load_user_config()
    profile_name = profile or get_active_profile_name(config)
    profile_exists = profile_name in config.get(PROFILES_KEY, {})
    updates = _profile_updates(
        as_user=as_user,
        relays=relays,
        kind=kind,
        query_timeout=query_timeout,
        publish_wait=publish_wait,
        limit=limit,
        query_output=query_output,
        authors=authors,
        lei=lei,
    )

    if not updates:
        if profile is not None and not profile_exists:
            config = ensure_profile(profile_name, config)
            write_user_config(config)
            click.echo(f"Created profile {profile_name} in {USER_CONFIG_PATH}")
        resolved = get_profile_config(profile_name, config)
        _print_profile_config(profile_name, resolved, profile_name == get_active_profile_name(config))
        return

    upsert_profile_config(profile_name, updates, config)
    click.echo(f"Updated profile {profile_name} in {USER_CONFIG_PATH}")


@click.command("set-config")
@click.argument("profile", required=False)
@click.option("--as-user", default=None, help="Set the default nsec private key.")
@click.option("--relays", default=None, help="Set the default relay URL or comma-separated relay pool.")
@click.option("--kind", type=int, default=None, help="Set the default event kind.")
@click.option("--query-timeout", type=int, default=None, help="Set the default query timeout in seconds.")
@click.option("--publish-wait", type=float, default=None, help="Set the default publish wait in seconds.")
@click.option("--limit", type=int, default=None, help="Set the default query result limit.")
@click.option(
    "--query-output",
    type=click.Choice(["heads", "full", "raw", "tags"]),
    default=None,
    help="Set the default query output format.",
)
@click.option("--authors", default=None, help="Validate one or more comma-separated npub values before saving.")
@click.option(
    "--lei",
    default=None,
    flag_value=GENERATE_LEI_SENTINEL,
    help="Set a legal entity identifier, or pass --lei with no value to generate an example LEI.",
)
def set_config(
    profile: str | None,
    as_user: str | None,
    relays: str | None,
    kind: int | None,
    query_timeout: int | None,
    publish_wait: float | None,
    limit: int | None,
    query_output: str | None,
    authors: str | None,
    lei: str | None,
) -> None:
    """Update or show the active profile config."""
    ctx = click.get_current_context()
    ctx.invoke(
        profile_set,
        profile=profile,
        as_user=as_user,
        relays=relays,
        kind=kind,
        query_timeout=query_timeout,
        publish_wait=publish_wait,
        limit=limit,
        query_output=query_output,
        authors=authors,
        lei=lei,
    )


@click.command("trivia")
def trivia() -> None:
    """Print a random MLETR fact."""
    click.echo(f"MLETR trivia: {choice(_load_mletr_trivia_facts())}")
