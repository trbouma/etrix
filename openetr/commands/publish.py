import asyncio
import logging
from pathlib import Path

import click
from monstr.client.client import ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event

from openetr.config import (
    CONFIG_AS_USER_KEY,
    DEFAULT_KIND,
    DEFAULT_LIMIT,
    DEFAULT_PUBLISH_WAIT,
    DEFAULT_QUERY_TIMEOUT,
    DEFAULT_RELAYS,
    USER_CONFIG_PATH,
    load_user_config,
    upsert_user_config,
)
from openetr.helpers import build_comment, build_digest, format_object_identifier, format_pubkey, resolve_keys


async def _run_publish_object(
    relay: str,
    digest: str,
    as_user,
    comment: str,
    publish_wait: float,
    query_timeout: int,
    limit: int,
    digest_file: Path | None,
) -> None:
    ok_results = []

    def on_ok(the_client, event_id: str, success: bool, message: str) -> None:
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
        pub_key=as_user.public_key_hex(),
        tags=[["d", digest], ["o", digest]],
    )
    event.sign(as_user.private_key_hex())

    click.echo(f"Relays:  {relay}")
    click.echo(f"Pubkey:  {format_pubkey(as_user.public_key_hex())}")
    click.echo(f"Event ID:{event.id}")
    click.echo(f"Object:  {format_object_identifier(digest)}")
    click.echo(f"Kind:    {event.kind}")
    click.echo(f"d tag:   {format_object_identifier(digest)}")
    click.echo(f"o tag:   {format_object_identifier(digest)}")
    if digest_file is not None:
        click.echo(f"Source:  sha256({digest_file})")
    click.echo(f"Content: {event.content}")
    click.echo("Event content payload:")
    click.echo(event.content)
    click.echo()

    async with ClientPool(
        relay.split(","),
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
            "authors": [as_user.public_key_hex()],
            "kinds": [DEFAULT_KIND],
            "#o": [digest],
            "#d": [digest],
            "limit": limit,
        }

        click.echo(f"Querying with filter: {query_filter}")
        events = await client.query(
            query_filter,
            emulate_single=True,
            wait_connect=True,
            timeout=query_timeout,
        )

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
            f"author={format_pubkey(evt.pub_key)} "
            f"d_values={[format_object_identifier(value) for value in d_values]} "
            f"o_values={[format_object_identifier(value) for value in o_values]}"
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


def _resolve_publish_key(as_user: str | None) -> Keys:
    if as_user is not None:
        keys = resolve_keys(as_user)
        upsert_user_config({CONFIG_AS_USER_KEY: keys.private_key_bech32()})
        return keys

    user_config = load_user_config()
    configured_key = user_config.get(CONFIG_AS_USER_KEY)
    if configured_key:
        return resolve_keys(configured_key)

    click.confirm(
        f"No --as-user value was supplied and no key exists in {USER_CONFIG_PATH}. "
        "Generate a new key and save it to config.yaml?",
        default=True,
        abort=True,
    )
    keys = Keys()
    upsert_user_config({CONFIG_AS_USER_KEY: keys.private_key_bech32()})
    click.echo(f"Generated a new key and saved it to {USER_CONFIG_PATH}")
    return keys


@click.command("publish-object")
@click.option("--relay", default=DEFAULT_RELAYS, show_default=True, help="Comma separated relay URLs to use.")
@click.option(
    "--digest",
    default=None,
    help="nobj or 32-byte hex digest to use as the d and o tag values; autogenerated if omitted.",
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
    help="nsec private key to publish with; loaded from config or generated if omitted.",
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
def publish_object(
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

    keys = _resolve_publish_key(as_user)
    resolved_digest, generated_at, resolved_file, file_size = build_digest(
        digest=digest,
        digest_file=str(digest_file) if digest_file is not None else None,
        keys=keys,
    )
    resolved_comment = build_comment(
        comment=comment,
        digest=resolved_digest,
        generated_at=generated_at,
        digest_file=resolved_file,
        digest_file_size=file_size,
    )

    asyncio.run(
        _run_publish_object(
            relay=relay,
            digest=resolved_digest,
            as_user=keys,
            comment=resolved_comment,
            publish_wait=publish_wait,
            query_timeout=query_timeout,
            limit=limit,
            digest_file=resolved_file,
        )
    )
