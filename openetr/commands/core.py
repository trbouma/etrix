from importlib.metadata import PackageNotFoundError, metadata as package_metadata, version as package_version
from importlib.resources import files
import asyncio
import json
from pathlib import Path
from random import choice

import click
from monstr.client.client import ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event
import yaml

from openetr.config import (
    ALIASES_KEY,
    CONFIG_AS_USER_KEY,
    DEFAULT_QUERY_TIMEOUT,
    DEFAULT_RELAYS,
    ACTIVE_PROFILE_KEY,
    DEFAULT_PROFILE_NAME,
    PROFILES_KEY,
    USER_CONFIG_DIR,
    USER_CONFIG_PATH,
    delete_alias,
    delete_profile,
    delete_profile_secret,
    ensure_root_bootstrap,
    ensure_profile,
    get_active_profile_name,
    get_aliases,
    get_profile_config,
    get_profile_signer_nsec,
    hydrate_local_profiles_from_index,
    list_profiles,
    load_raw_user_config,
    load_user_config,
    remove_local_profile_secret,
    render_user_config_template,
    set_active_profile,
    sync_aliases_index,
    sync_profile_record,
    store_profile_secret,
    sync_profiles_index,
    upsert_alias,
    upsert_profile_config,
    write_bootstrap_config,
    write_user_config,
)
from openetr.helpers import (
    GENERATE_LEI_SENTINEL,
    format_object_identifier,
    format_pubkey,
    normalize_alias,
    parse_authors,
    resolve_lei,
    resolve_keys,
    resolve_query_digest,
    resolve_author,
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


def _generated_profile_key_update(profile_exists: bool, as_user: str | None) -> dict:
    if profile_exists or as_user is not None:
        return {}

    generated_keys = Keys()
    return {CONFIG_AS_USER_KEY: generated_keys.private_key_bech32()}


def _print_profile_config(profile: str, resolved: dict, is_active: bool, show_nsec: bool = False) -> None:
    marker = " (active)" if is_active else ""
    click.echo(f"{profile}{marker}:")
    for key, value in resolved.items():
        if key == CONFIG_AS_USER_KEY and value:
            signer_npub = resolve_keys(value).public_key_bech32()
            click.echo(f"  signer_npub: {signer_npub}")
            if show_nsec:
                click.echo(f"  {CONFIG_AS_USER_KEY}: {value}")
            continue
        click.echo(f"  {key}: {value}")


def _print_alias_entries(config: dict) -> None:
    aliases = get_aliases(config)
    if not aliases:
        click.echo("No aliases found in relay-backed configuration.")
        return

    width = max((len(alias) for alias in aliases), default=0)
    click.echo("Aliases in relay-backed configuration:")
    for alias in sorted(aliases):
        click.echo(f"  {alias:<{width}}  {aliases[alias]}")


def _sync_profile_alias(profile: str, config: dict) -> dict:
    configured_key = get_profile_signer_nsec(profile, config)
    if not configured_key:
        return config

    normalized_alias = normalize_alias(profile)
    config = dict(config)
    aliases = config.setdefault(ALIASES_KEY, {})
    aliases[normalized_alias] = resolve_keys(configured_key).public_key_bech32()
    return config


def _profile_list_entries(config: dict, include_active: bool = True) -> list[str]:
    active = get_active_profile_name(config)
    profiles = list_profiles(config)
    names = profiles if include_active else [name for name in profiles if name != active]
    width = max((len(name) for name in names), default=0)
    entries = []
    for name in names:
        marker = "*" if name == active else " "
        configured_key = get_profile_signer_nsec(name, config)
        label = f"{marker} {name:<{width}}".rstrip()
        if configured_key:
            npub = resolve_keys(configured_key).public_key_bech32()
            entries.append(f"  {label}  {npub}")
        else:
            entries.append(f"  {label}")
    return entries


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
        "address",
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
    config = hydrate_local_profiles_from_index(load_user_config())
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
    rendered = render_user_config_template()
    USER_CONFIG_PATH.write_text(rendered, encoding="utf-8")
    config = load_user_config()
    config, changes = ensure_root_bootstrap(config)
    click.echo(f"Wrote config to {USER_CONFIG_PATH}")
    if changes.get("root_recovery_phrase") or changes.get("root_recovery_phrase_unavailable"):
        click.echo("Root CLI bootstrap created:")
        click.echo(f"  home relays: {config['home_relay']}")
        click.echo(f"  root nsec: {config['root_nsec']}")
        if changes.get("root_recovery_phrase"):
            click.echo("  recovery phrase:")
            click.echo(f"    {changes['root_recovery_phrase']}")
        else:
            click.echo("  recovery phrase: unavailable until the 'mnemonic' dependency is installed")


@click.command("bootstrap")
@click.option("--root-nsec", default=None, help="Set the root bootstrap nsec.")
@click.option("--home-relays", default=None, help="Set the home relays for relay-backed config recovery.")
@click.option("--force", is_flag=True, help="Overwrite the existing bootstrap values without confirmation.")
def bootstrap(root_nsec: str | None, home_relays: str | None, force: bool) -> None:
    """Show or set the minimal local bootstrap config."""
    raw_config = load_raw_user_config()
    config = load_user_config()

    if root_nsec is None and home_relays is None:
        config, _ = ensure_root_bootstrap(config)
        click.echo("Bootstrap")
        click.echo(f"  root_nsec: {config.get('root_nsec')}")
        click.echo(f"  home_relays: {config.get('home_relay')}")
        return

    updated_root_nsec = raw_config.get("root_nsec") or config.get("root_nsec")
    updated_home_relay = raw_config.get("home_relay") or config.get("home_relay")
    changed = []

    if root_nsec is not None:
        normalized_root = resolve_keys(root_nsec).private_key_bech32()
        if updated_root_nsec and updated_root_nsec != normalized_root and not force:
            click.confirm(
                "Replace the existing root bootstrap nsec?",
                default=False,
                abort=True,
            )
        updated_root_nsec = normalized_root
        changed.append("root_nsec")

    if home_relays is not None:
        normalized_home_relay = _normalize_relays(home_relays)
        if updated_home_relay and updated_home_relay != normalized_home_relay and not force:
            click.confirm(
                "Replace the existing home relays?",
                default=False,
                abort=True,
            )
        updated_home_relay = normalized_home_relay
        changed.append("home_relays")

    write_bootstrap_config(updated_root_nsec, updated_home_relay)
    click.echo(f"Updated bootstrap in {USER_CONFIG_PATH}")
    if changed:
        click.echo(f"  changed: {', '.join(changed)}")
    click.echo(f"  root_nsec: {updated_root_nsec}")
    click.echo(f"  home_relays: {updated_home_relay}")


@click.command("migrate-config")
@click.option("--prune", is_flag=True, help="After migration, reduce config.yaml to only root_nsec and home_relay.")
def migrate_config(prune: bool) -> None:
    """Migrate local profile settings into relay-backed records."""
    config = hydrate_local_profiles_from_index(load_user_config())
    config, _ = ensure_root_bootstrap(config)

    profile_names = sorted(config.get(PROFILES_KEY, {}).keys())
    migrated_secrets = 0
    migrated_profile_records = 0

    for profile_name in profile_names:
        local_secret = config.get(PROFILES_KEY, {}).get(profile_name, {}).get(CONFIG_AS_USER_KEY)
        if local_secret:
            store_profile_secret(profile_name, local_secret, config)
            config = remove_local_profile_secret(profile_name, config)
            migrated_secrets += 1

        sync_profile_record(profile_name, config)
        migrated_profile_records += 1

    for profile_name in profile_names:
        config = _sync_profile_alias(profile_name, config)

    write_user_config(config)
    _, alias_index = sync_aliases_index(config)
    _, profiles_index = sync_profiles_index(config)

    if prune:
        pruned_config = {
            "root_nsec": config["root_nsec"],
            "home_relay": config["home_relay"],
        }
        write_user_config(pruned_config)

    click.echo("Migrated local configuration to relay-backed records.")
    click.echo(f"  home relays: {config['home_relay']}")
    click.echo(f"  profile records synced: {migrated_profile_records}")
    click.echo(f"  profile signer secrets migrated: {migrated_secrets}")
    click.echo(f"  aliases indexed: {len(alias_index.aliases)}")
    click.echo(f"  profiles indexed: {len(profiles_index.profiles)}")
    if prune:
        click.echo("  local config pruned to bootstrap minimum")


@click.group("profile", invoke_without_command=True)
@click.pass_context
def profile_group(ctx: click.Context) -> None:
    """Manage OpenETR profiles."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(profile_show, profile=None)


@click.group("alias", invoke_without_command=True)
@click.pass_context
def alias_group(ctx: click.Context) -> None:
    """Manage global npub aliases."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(alias_list)


@alias_group.command("list")
def alias_list() -> None:
    """List configured aliases."""
    _print_alias_entries(load_user_config())


@alias_group.command("set")
@click.argument("alias")
@click.argument("target")
def alias_set(alias: str, target: str) -> None:
    """Set a global alias that maps to an npub."""
    normalized_alias = normalize_alias(alias)
    target_hex = resolve_author(target)
    target_npub = Keys.hex_to_bech32(target_hex, prefix="npub")
    upsert_alias(normalized_alias, target_npub)
    click.echo(f"Set alias {normalized_alias} -> {target_npub}")


@alias_group.command("delete")
@click.argument("alias")
@click.option("--force", is_flag=True, help="Delete the alias without confirmation.")
def alias_delete(alias: str, force: bool) -> None:
    """Delete a global alias."""
    normalized_alias = normalize_alias(alias)
    aliases = get_aliases()
    if normalized_alias not in aliases:
        raise click.ClickException(f"alias '{normalized_alias}' was not found in {USER_CONFIG_PATH}")
    if not force:
        click.confirm(f"Delete alias '{normalized_alias}'?", abort=True)
    delete_alias(normalized_alias)
    click.echo(f"Deleted alias {normalized_alias}")


@profile_group.command("list")
def profile_list() -> None:
    """List configured profiles."""
    config = hydrate_local_profiles_from_index(load_user_config())
    click.echo("Profiles in relay-backed configuration:")
    for entry in _profile_list_entries(config):
        click.echo(entry)


@click.command("whoami")
@click.option("--nsec", "show_nsec", is_flag=True, help="Display the resolved signer nsec for the current profile.")
def whoami(show_nsec: bool) -> None:
    """Show the active profile details and other profiles available to switch to."""
    config = hydrate_local_profiles_from_index(load_user_config())
    active_profile = get_active_profile_name(config)
    resolved = get_profile_config(active_profile, config)

    click.echo("Current profile")
    _print_profile_config(active_profile, resolved, True, show_nsec=show_nsec)

    configured_key = get_profile_signer_nsec(active_profile, config)
    if configured_key:
        pubkey_hex = resolve_keys(configured_key).public_key_hex()
        click.echo(f"pubkey: {format_pubkey(pubkey_hex)}")
        resolved_relays = resolved.get("relays", DEFAULT_RELAYS)
        resolved_timeout = resolved.get("query_timeout", DEFAULT_QUERY_TIMEOUT)
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

    other_profiles = _profile_list_entries(config, include_active=False)
    click.echo("")
    click.echo("Other profiles you can switch to:")
    if other_profiles:
        for entry in other_profiles:
            click.echo(entry)
    else:
        click.echo("  none")


@profile_group.command("show")
@click.argument("profile", required=False)
@click.option("--nsec", "show_nsec", is_flag=True, help="Display the resolved signer nsec for the profile.")
def profile_show(profile: str | None, show_nsec: bool) -> None:
    """Show the resolved config for a profile."""
    config = hydrate_local_profiles_from_index(load_user_config())
    profile_name = profile or get_active_profile_name(config)
    resolved = get_profile_config(profile_name, config)
    _print_profile_config(
        profile_name,
        resolved,
        profile_name == get_active_profile_name(config),
        show_nsec=show_nsec,
    )

    configured_key = get_profile_signer_nsec(profile_name, config)
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
    config = hydrate_local_profiles_from_index(load_user_config())
    if profile not in list_profiles(config):
        raise click.ClickException(f"profile '{profile}' was not found in {USER_CONFIG_PATH}")
    set_active_profile(profile, config)
    click.echo(f"Active profile set to {profile}")


@profile_group.command("delete")
@click.argument("profile")
@click.option("--force", is_flag=True, help="Delete the profile without confirmation.")
def profile_delete(profile: str, force: bool) -> None:
    """Delete a profile."""
    config = hydrate_local_profiles_from_index(load_user_config())
    if profile not in list_profiles(config):
        raise click.ClickException(f"profile '{profile}' was not found in {USER_CONFIG_PATH}")
    if profile == DEFAULT_PROFILE_NAME and not force:
        raise click.ClickException("Refusing to delete the default profile without --force.")

    if not force:
        click.confirm(f"Delete profile '{profile}'?", abort=True)

    normalized_alias = normalize_alias(profile)
    aliases = get_aliases()
    delete_profile_secret(profile, config)
    delete_profile(profile, config)
    if normalized_alias in aliases:
        delete_alias(normalized_alias)
        click.echo(f"Deleted alias {normalized_alias}")
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
    config = hydrate_local_profiles_from_index(load_user_config())
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
    generated_key_update = _generated_profile_key_update(profile_exists, as_user)
    secret_value = updates.pop(CONFIG_AS_USER_KEY, None)
    generated_secret = generated_key_update.pop(CONFIG_AS_USER_KEY, None)

    if not updates and secret_value is None and generated_secret is None:
        if profile is not None and not profile_exists:
            config = ensure_profile(profile_name, config)
            profile_values = config.setdefault(PROFILES_KEY, {}).setdefault(profile_name, {})
            if generated_key_update:
                profile_values.update(generated_key_update)
            write_user_config(config)
            if generated_secret:
                store_profile_secret(profile_name, generated_secret, config)
                config = remove_local_profile_secret(profile_name, config)
            sync_profile_record(profile_name, config)
            config = _sync_profile_alias(profile_name, load_user_config())
            write_user_config(config)
            sync_aliases_index(config)
            sync_profiles_index(config)
            click.echo(f"Created profile {profile_name} in {USER_CONFIG_PATH}")
            if generated_secret:
                click.echo("Generated a new nsec for the profile.")
                click.echo(f"Added alias {normalize_alias(profile_name)} for the profile signer.")
        elif profile is not None and profile_exists:
            local_secret = config.get(PROFILES_KEY, {}).get(profile_name, {}).get(CONFIG_AS_USER_KEY)
            if local_secret:
                store_profile_secret(profile_name, local_secret, config)
                config = remove_local_profile_secret(profile_name, config)
                sync_profile_record(profile_name, config)
                config = _sync_profile_alias(profile_name, load_user_config())
                write_user_config(config)
                sync_aliases_index(config)
                sync_profiles_index(config)
                click.echo(f"Migrated profile signer for {profile_name} to relay-backed storage.")
        resolved = get_profile_config(profile_name, config)
        _print_profile_config(
            profile_name,
            resolved,
            profile_name == get_active_profile_name(config),
            show_nsec=False,
        )
        return

    config = upsert_profile_config(profile_name, updates, config)
    if secret_value:
        store_profile_secret(profile_name, secret_value, config)
        config = remove_local_profile_secret(profile_name, load_user_config())
    elif generated_secret:
        store_profile_secret(profile_name, generated_secret, config)
        config = remove_local_profile_secret(profile_name, load_user_config())
    config = _sync_profile_alias(profile_name, load_user_config())
    write_user_config(config)
    sync_aliases_index(config)
    sync_profiles_index(config)
    action = "Created" if not profile_exists else "Updated"
    click.echo(f"{action} profile {profile_name} in {USER_CONFIG_PATH}")
    if generated_secret:
        click.echo("Generated a new nsec for the profile.")
        click.echo(f"Added alias {normalize_alias(profile_name)} for the profile signer.")
    elif secret_value:
        click.echo("Stored the profile signer in relay-backed encrypted storage.")


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
