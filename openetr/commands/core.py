from importlib.metadata import PackageNotFoundError, version as package_version

import click

from openetr.config import (
    USER_CONFIG_DIR,
    USER_CONFIG_PATH,
    load_user_config,
    packaged_defaults_text,
    upsert_user_config,
)
from openetr.helpers import parse_authors, resolve_keys


def _normalize_relays(relay: str) -> str:
    relays = []
    for item in relay.split(","):
        cleaned = item.strip()
        if not cleaned:
            continue
        if not cleaned.startswith("wss://") and not cleaned.startswith("ws://"):
            cleaned = f"wss://{cleaned}"
        relays.append(cleaned)

    if not relays:
        raise click.ClickException("relay must contain at least one relay URL")

    return ",".join(relays)


@click.command()
def version() -> None:
    """Show the CLI version."""
    try:
        current_version = package_version("openetr")
    except PackageNotFoundError:
        current_version = "0.1.0"

    click.echo(f"openetr {current_version}")


@click.command("init-config")
@click.option("--force", is_flag=True, help="Overwrite an existing ~/.openetr/config.yaml file.")
def init_config(force: bool) -> None:
    """Create a user config file at ~/.openetr/config.yaml."""
    if USER_CONFIG_PATH.exists() and not force:
        raise click.ClickException(
            f"Config already exists at {USER_CONFIG_PATH}. Use --force to overwrite it."
        )

    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    USER_CONFIG_PATH.write_text(packaged_defaults_text(), encoding="utf-8")
    click.echo(f"Wrote config to {USER_CONFIG_PATH}")


@click.command("set-config")
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
def set_config(
    as_user: str | None,
    relays: str | None,
    kind: int | None,
    query_timeout: int | None,
    publish_wait: float | None,
    limit: int | None,
    query_output: str | None,
    authors: str | None,
) -> None:
    """Update values in ~/.openetr/config.yaml, or show them if no options are provided."""
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

    if not updates:
        stored_config = load_user_config()
        if not stored_config:
            click.echo(f"No stored config found at {USER_CONFIG_PATH}")
            return

        click.echo(f"Stored config at {USER_CONFIG_PATH}:")
        for key, value in stored_config.items():
            click.echo(f"  {key}: {value}")
        return

    upsert_user_config(updates)
    click.echo(f"Updated config at {USER_CONFIG_PATH}")


@click.command()
@click.argument("name", required=False, default="world")
def hello(name: str) -> None:
    """Print a friendly greeting."""
    click.echo(f"Hello, {name}.")
