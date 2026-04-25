import asyncio
import hashlib
import logging
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path

import click
from monstr.client.client import Client, ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event

DEFAULT_RELAY = "wss://relay.getsafebox.app/"
DEFAULT_KIND = 31415
DEFAULT_QUERY_TIMEOUT = 10
DEFAULT_PUBLISH_WAIT = 2.0
DEFAULT_LIMIT = 20


def _resolve_keys(as_user: str | None) -> Keys:
    if as_user is None:
        return Keys()

    key = Keys.get_key(as_user)
    if key is None or key.private_key_hex() is None:
        raise click.ClickException("as-user must be a valid private key in nsec or hex form")
    return key


def _build_digest(
    digest: str | None,
    digest_file: str | None,
    keys: Keys,
) -> tuple[str, datetime, Path | None, int | None]:
    generated_at = datetime.now(timezone.utc)
    resolved_file = None
    file_size = None

    if digest_file is not None:
        resolved_file = Path(digest_file).expanduser()
        if not resolved_file.is_file():
            raise click.ClickException(
                f"digest-file does not exist or is not a file: {resolved_file}"
            )

        file_size = resolved_file.stat().st_size
        file_hash = hashlib.sha256()
        with resolved_file.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                file_hash.update(chunk)
        digest = file_hash.hexdigest()
    elif digest is None:
        seed = f"monstr-replaceable-o-tag:{time.time_ns()}:{keys.public_key_hex()}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()

    if len(digest) != 64:
        raise click.ClickException("digest must be exactly 64 hex characters")

    try:
        int(digest, 16)
    except ValueError as exc:
        raise click.ClickException("digest must be valid lowercase or uppercase hex") from exc

    return digest.lower(), generated_at, resolved_file, file_size


def _build_comment(
    comment: str | None,
    digest: str,
    generated_at: datetime,
    digest_file: Path | None,
    digest_file_size: int | None,
) -> str:
    if comment is not None:
        return comment

    generated_at_iso = generated_at.isoformat()
    if digest_file is not None:
        return (
            f"name={digest_file.name}; "
            f"digest_generated_at={generated_at_iso}; "
            f"size_bytes={digest_file_size}"
        )

    return (
        f"kind={DEFAULT_KIND} replaceable probe; "
        f"d={digest}; "
        f"o={digest}; "
        f"generated_at={generated_at_iso}"
    )


def _resolve_query_digest(
    digest: str | None,
    digest_file: Path | None,
) -> tuple[str, Path | None]:
    resolved_file = None

    if digest_file is not None:
        resolved_file = digest_file.expanduser()
        if not resolved_file.is_file():
            raise click.ClickException(
                f"digest-file does not exist or is not a file: {resolved_file}"
            )

        file_hash = hashlib.sha256()
        with resolved_file.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                file_hash.update(chunk)
        digest = file_hash.hexdigest()

    if digest is None:
        raise click.ClickException("you must supply either --digest or --digest-file")

    if len(digest) != 64:
        raise click.ClickException("digest must be exactly 64 hex characters")

    try:
        int(digest, 16)
    except ValueError as exc:
        raise click.ClickException("digest must be valid hex") from exc

    return digest.lower(), resolved_file


def _parse_authors(authors: str | None) -> list[str] | None:
    if not authors:
        return None

    parsed_authors = [author.strip() for author in authors.split(",") if author.strip()]
    return parsed_authors or None


def _print_event(evt: Event, output: str) -> None:
    if output == "raw":
        click.echo(evt.event_data())
        click.echo(evt.tags)
        click.echo(f"content: {evt.content}")
        return

    if output == "tags":
        click.echo(evt)
        click.echo(f"content: {evt.content}")
        for tag in evt.tags:
            click.echo(tag)
        click.echo(f"total {len(evt.tags)}")
        return

    click.echo(evt)
    click.echo(f"content: {evt.content}")
    if output == "full":
        click.echo("-" * 80)
        click.echo(evt.content)
        click.echo()


async def _run_publish_probe(
    relay: str,
    digest: str,
    keys: Keys,
    comment: str,
    publish_wait: float,
    query_timeout: int,
    limit: int,
    digest_file: Path | None,
) -> None:
    ok_results = []

    def on_ok(the_client: Client, event_id: str, success: bool, message: str) -> None:
        ok_results.append(
            {
                "event_id": event_id,
                "success": success,
                "message": message,
            }
        )
        click.echo(f"OK from relay for {event_id}: success={success} message={message}")

    event = Event(
        kind=DEFAULT_KIND,
        content=comment,
        pub_key=keys.public_key_hex(),
        tags=[["d", digest], ["o", digest]],
    )
    event.sign(keys.private_key_hex())

    click.echo(f"Relay:   {relay}")
    click.echo(f"Pubkey:  {keys.public_key_hex()}")
    click.echo(f"Event ID:{event.id}")
    click.echo(f"Kind:    {event.kind}")
    click.echo(f"d tag:   {digest}")
    click.echo(f"o tag:   {digest}")
    if digest_file is not None:
        click.echo(f"Source:  sha256({digest_file})")
    click.echo(f"Content: {event.content}")
    click.echo("Event content payload:")
    click.echo(event.content)
    click.echo()

    async with Client(
        relay,
        on_ok=on_ok,
        timeout=query_timeout,
        query_timeout=query_timeout,
    ) as client:
        click.echo("Publishing event...")
        client.publish(event)

        if publish_wait > 0:
            click.echo(f"Waiting {publish_wait:.1f}s for relay indexing...")
            await asyncio.sleep(publish_wait)

        query_filter = {
            "authors": [keys.public_key_hex()],
            "kinds": [DEFAULT_KIND],
            "#o": [digest],
            "#d": [digest],
            "limit": limit,
        }

        click.echo(f"Querying with filter: {query_filter}")
        events = await client.query(query_filter, wait_connect=True, timeout=query_timeout)

    click.echo()
    click.echo(f"Query returned {len(events)} event(s)")

    matched = []
    for evt in events:
        d_values = evt.get_tags_value("d")
        o_values = evt.get_tags_value("o")
        has_tag_match = digest in d_values and digest in o_values
        same_event = evt.id == event.id
        click.echo(
            f"- id={evt.id} created_at={evt.created_at} kind={evt.kind} "
            f"author={evt.pub_key} d_values={d_values} o_values={o_values}"
        )
        click.echo(f"  content={evt.content}")
        if has_tag_match:
            matched.append(evt)
        if same_event:
            click.echo("  exact published event matched")

    click.echo()
    if matched:
        click.echo("PASS: relay returned at least one event for the combined #d and #o filter.")
        if any(evt.id == event.id for evt in matched):
            click.echo("PASS: the exact event we published was returned by the combined #d and #o filter.")
        else:
            click.echo("PARTIAL: query matched the d/o tags, but not the exact event id we just published.")
    else:
        click.echo("FAIL: relay did not return any events for the combined #d and #o filter.")

    if ok_results:
        last_ok = ok_results[-1]
        click.echo(
            f"Last OK status: success={last_ok['success']} "
            f"event_id={last_ok['event_id']} message={last_ok['message']}"
        )
    else:
        click.echo("No OK message was observed from the relay before the script exited.")


async def _run_query_probe(
    relay: str,
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
        relay.split(","),
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
        click.echo(f"d values: {d_values}")
        click.echo(f"o values: {o_values}")
        _print_event(evt, output)


@click.group()
def main() -> None:
    """ETRix command line utility."""


@main.command()
def version() -> None:
    """Show the CLI version."""
    try:
        current_version = package_version("etrix")
    except PackageNotFoundError:
        current_version = "0.1.0"

    click.echo(f"etrix {current_version}")


@main.command()
@click.argument("name", required=False, default="world")
def hello(name: str) -> None:
    """Print a friendly greeting."""
    click.echo(f"Hello, {name}.")


@main.command("publish-probe")
@click.option("--relay", default=DEFAULT_RELAY, show_default=True, help="Relay to test.")
@click.option(
    "--digest",
    default=None,
    help="32-byte hex digest to use as the d and o tag values; autogenerated if omitted.",
)
@click.option(
    "--digest-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a file to hash with SHA-256 and use as the d and o tag values.",
)
@click.option(
    "--as-user",
    default=None,
    help="nsec or hex private key to publish with; autogenerated if omitted.",
)
@click.option(
    "--comment",
    default=None,
    help="Comment string to publish as event content; autogenerated if omitted.",
)
@click.option(
    "--publish-wait",
    type=float,
    default=DEFAULT_PUBLISH_WAIT,
    show_default=True,
    help="Seconds to wait after publish before querying.",
)
@click.option(
    "--query-timeout",
    type=int,
    default=DEFAULT_QUERY_TIMEOUT,
    show_default=True,
    help="Seconds to wait for the query to complete.",
)
@click.option(
    "--limit",
    type=int,
    default=DEFAULT_LIMIT,
    show_default=True,
    help="Query result limit.",
)
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def publish_probe(
    relay: str,
    digest: str | None,
    digest_file: Path | None,
    as_user: str | None,
    comment: str | None,
    publish_wait: float,
    query_timeout: int,
    limit: int,
    debug: bool,
) -> None:
    """Publish and query a replaceable event with matching d and o tags."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    keys = _resolve_keys(as_user)
    resolved_digest, generated_at, resolved_file, file_size = _build_digest(
        digest=digest,
        digest_file=str(digest_file) if digest_file is not None else None,
        keys=keys,
    )
    resolved_comment = _build_comment(
        comment=comment,
        digest=resolved_digest,
        generated_at=generated_at,
        digest_file=resolved_file,
        digest_file_size=file_size,
    )

    asyncio.run(
        _run_publish_probe(
            relay=relay,
            digest=resolved_digest,
            keys=keys,
            comment=resolved_comment,
            publish_wait=publish_wait,
            query_timeout=query_timeout,
            limit=limit,
            digest_file=resolved_file,
        )
    )


@main.command("query-probe")
@click.option("--relay", default=DEFAULT_RELAY, show_default=True, help="Comma separated relay URLs to query.")
@click.option("--digest", default=None, help="64-character hex digest to query for.")
@click.option(
    "--digest-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a file to hash with SHA-256 and use as the d filter value.",
)
@click.option(
    "--authors",
    default=None,
    help="Comma separated author pubkeys to narrow the query.",
)
@click.option(
    "--limit",
    type=int,
    default=DEFAULT_LIMIT,
    show_default=True,
    help="Result limit.",
)
@click.option(
    "--timeout",
    type=int,
    default=DEFAULT_QUERY_TIMEOUT,
    show_default=True,
    help="Query timeout in seconds.",
)
@click.option(
    "--output",
    type=click.Choice(["heads", "full", "raw", "tags"]),
    default="full",
    show_default=True,
    help="Output format.",
)
@click.option("--ssl-disable-verify", is_flag=True, help="Disable SSL certificate verification.")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def query_probe(
    relay: str,
    digest: str | None,
    digest_file: Path | None,
    authors: str | None,
    limit: int,
    timeout: int,
    output: str,
    ssl_disable_verify: bool,
    debug: bool,
) -> None:
    """Query for replaceable kind 31415 events using the d tag value."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    resolved_digest, resolved_file = _resolve_query_digest(digest, digest_file)
    parsed_authors = _parse_authors(authors)

    asyncio.run(
        _run_query_probe(
            relay=relay,
            digest=resolved_digest,
            authors=parsed_authors,
            limit=limit,
            timeout=timeout,
            output=output,
            ssl_disable_verify=ssl_disable_verify,
            digest_file=resolved_file,
        )
    )
