import asyncio
import json
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
    get_profile_config,
    USER_CONFIG_PATH,
    get_active_profile_name,
    load_user_config,
    upsert_profile_config,
)
from openetr.helpers import (
    GENERATE_LEI_SENTINEL,
    build_comment,
    build_digest,
    format_object_identifier,
    format_pubkey,
    resolve_keys,
    resolve_lei,
)


async def _run_publish_object(
    relays: str,
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

    click.echo(f"Relays:  {relays}")
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
        relays.split(","),
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


async def _fetch_current_profile(
    relays: str,
    pubkey_hex: str,
    query_timeout: int,
) -> dict:
    async with ClientPool(
        relays.split(","),
        timeout=query_timeout,
        query_timeout=query_timeout,
    ) as client:
        events = await client.query(
            {
                "authors": [pubkey_hex],
                "kinds": [0],
                "limit": 1,
            },
            emulate_single=True,
            wait_connect=True,
            timeout=query_timeout,
        )

    Event.sort(events, inplace=True, reverse=True)
    if not events or not events[0].content:
        return {}

    try:
        return json.loads(events[0].content)
    except json.JSONDecodeError:
        return {}


async def _run_publish_profile(
    relays: str,
    as_user,
    content: dict,
    publish_wait: float,
    query_timeout: int,
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
        kind=0,
        content=json.dumps(content, separators=(",", ":"), ensure_ascii=True),
        pub_key=as_user.public_key_hex(),
    )
    event.sign(as_user.private_key_hex())

    click.echo(f"Relays:  {relays}")
    click.echo(f"Pubkey:  {format_pubkey(as_user.public_key_hex())}")
    click.echo(f"Event ID:{event.id}")
    click.echo("Kind:    0")
    click.echo("Profile content:")
    click.echo(event.content)
    click.echo()

    async with ClientPool(
        relays.split(","),
        on_ok=on_ok,
        timeout=query_timeout,
        query_timeout=query_timeout,
    ) as client:
        click.echo("Publishing profile event...")
        client.publish(event)

        if publish_wait > 0:
            click.echo(f"Waiting {publish_wait:.1f}s for relay indexing...")
            await asyncio.sleep(publish_wait)

        events = await client.query(
            {
                "authors": [as_user.public_key_hex()],
                "kinds": [0],
                "limit": 1,
            },
            emulate_single=True,
            wait_connect=True,
            timeout=query_timeout,
        )

    Event.sort(events, inplace=True, reverse=True)
    click.echo()
    click.echo(f"Query returned {len(events)} event(s)")

    if events:
        latest = events[0]
        click.echo(f"Latest profile event: {latest.id}")
        click.echo(latest.content)
        if latest.id == event.id:
            click.echo("PASS: the exact profile event we published was returned.")
        else:
            click.echo("PARTIAL: a profile event was returned, but it was not the exact new event id.")
    else:
        click.echo("FAIL: no kind 0 profile event was returned after publish.")

    if ok_results:
        last_ok = ok_results[-1]
        click.echo(
            f"Last OK status: success={last_ok['success']} "
            f"event_id={last_ok['event_id']} message={last_ok['message']}"
        )
    else:
        click.echo("No OK message was observed from the relay before the command exited.")


def _resolve_publish_key(profile: str, as_user: str | None) -> Keys:
    if as_user is not None:
        keys = resolve_keys(as_user)
        upsert_profile_config(profile, {CONFIG_AS_USER_KEY: keys.private_key_bech32()})
        return keys

    profile_config = get_profile_config(profile, load_user_config())
    configured_key = profile_config.get(CONFIG_AS_USER_KEY)
    if configured_key:
        return resolve_keys(configured_key)

    click.confirm(
        f"No --as-user value was supplied and no key exists in {USER_CONFIG_PATH}. "
        "Generate a new key and save it to config.yaml?",
        default=True,
        abort=True,
    )
    keys = Keys()
    upsert_profile_config(profile, {CONFIG_AS_USER_KEY: keys.private_key_bech32()})
    click.echo(f"Generated a new key and saved it to {USER_CONFIG_PATH}")
    return keys


def _profile_updates(
    name: str | None,
    display_name: str | None,
    about: str | None,
    picture: str | None,
    banner: str | None,
    website: str | None,
    nip05: str | None,
    lud16: str | None,
    lud06: str | None,
    lei: str | None,
) -> dict:
    updates = {}
    if name is not None:
        updates["name"] = name
    if display_name is not None:
        updates["display_name"] = display_name
    if about is not None:
        updates["about"] = about
    if picture is not None:
        updates["picture"] = picture
    if banner is not None:
        updates["banner"] = banner
    if website is not None:
        updates["website"] = website
    if nip05 is not None:
        updates["nip05"] = nip05
    if lud16 is not None:
        updates["lud16"] = lud16
    if lud06 is not None:
        updates["lud06"] = lud06
    if lei is not None:
        updates["lei"] = resolve_lei(lei)
    return updates


@click.command("publish-object")
@click.option("--profile", default=None, help="Profile to use; defaults to the active profile.")
@click.option("--relays", default=None, help="Comma separated relay URLs to use.")
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
    default=None,
    help="Seconds to wait after publish before querying.",
)
@click.option(
    "--query-timeout",
    type=int,
    default=None,
    help="Seconds to wait for the query to complete.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Query result limit.",
)
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def publish_object(
    profile: str | None,
    relays: str | None,
    digest: str | None,
    digest_file: Path | None,
    as_user: str | None,
    comment: str | None,
    publish_wait: float | None,
    query_timeout: int | None,
    limit: int | None,
    debug: bool,
) -> None:
    """Publish and query a replaceable event with matching d and o tags."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    profile_name = profile or get_active_profile_name()
    profile_config = get_profile_config(profile_name)
    resolved_relays = relays or profile_config.get("relays", DEFAULT_RELAYS)
    resolved_publish_wait = publish_wait if publish_wait is not None else profile_config.get("publish_wait", DEFAULT_PUBLISH_WAIT)
    resolved_query_timeout = query_timeout if query_timeout is not None else profile_config.get("query_timeout", DEFAULT_QUERY_TIMEOUT)
    resolved_limit = limit if limit is not None else profile_config.get("limit", DEFAULT_LIMIT)

    keys = _resolve_publish_key(profile_name, as_user)
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
            relays=resolved_relays,
            digest=resolved_digest,
            as_user=keys,
            comment=resolved_comment,
            publish_wait=resolved_publish_wait,
            query_timeout=resolved_query_timeout,
            limit=resolved_limit,
            digest_file=resolved_file,
        )
    )


@click.command("publish-profile")
@click.option("--profile", default=None, help="Profile to use; defaults to the active profile.")
@click.option("--relays", default=None, help="Comma separated relay URLs to use.")
@click.option(
    "--as-user",
    default=None,
    help="nsec private key to publish with; loaded from config or generated if omitted.",
)
@click.option("--name", default=None, help="Profile name.")
@click.option("--display-name", default=None, help="Profile display_name.")
@click.option("--about", default=None, help="Profile about text.")
@click.option("--picture", default=None, help="Profile picture URL.")
@click.option("--banner", default=None, help="Profile banner image URL.")
@click.option("--website", default=None, help="Profile website URL.")
@click.option("--nip05", default=None, help="Profile NIP-05 identifier.")
@click.option("--lud16", default=None, help="Lightning address.")
@click.option("--lud06", default=None, help="LNURL pay string.")
@click.option(
    "--lei",
    default=None,
    flag_value=GENERATE_LEI_SENTINEL,
    help="Profile legal entity identifier, or pass --lei with no value to generate an example LEI.",
)
@click.option("--replace", is_flag=True, help="Replace the entire profile instead of merging with the current one.")
@click.option(
    "--publish-wait",
    type=float,
    default=None,
    help="Seconds to wait after publish before querying.",
)
@click.option(
    "--query-timeout",
    type=int,
    default=None,
    help="Seconds to wait for the query to complete.",
)
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def publish_profile(
    profile: str | None,
    relays: str | None,
    as_user: str | None,
    name: str | None,
    display_name: str | None,
    about: str | None,
    picture: str | None,
    banner: str | None,
    website: str | None,
    nip05: str | None,
    lud16: str | None,
    lud06: str | None,
    lei: str | None,
    replace: bool,
    publish_wait: float | None,
    query_timeout: int | None,
    debug: bool,
) -> None:
    """Publish a Nostr kind 0 profile event."""
    logging.getLogger().setLevel(logging.DEBUG if debug else logging.INFO)

    updates = _profile_updates(
        name=name,
        display_name=display_name,
        about=about,
        picture=picture,
        banner=banner,
        website=website,
        nip05=nip05,
        lud16=lud16,
        lud06=lud06,
        lei=lei,
    )
    if not updates:
        raise click.ClickException("No profile fields supplied. Pass at least one profile option to publish.")

    profile_name = profile or get_active_profile_name()
    profile_config = get_profile_config(profile_name)
    resolved_relays = relays or profile_config.get("relays", DEFAULT_RELAYS)
    resolved_publish_wait = publish_wait if publish_wait is not None else profile_config.get("publish_wait", DEFAULT_PUBLISH_WAIT)
    resolved_query_timeout = query_timeout if query_timeout is not None else profile_config.get("query_timeout", DEFAULT_QUERY_TIMEOUT)

    keys = _resolve_publish_key(profile_name, as_user)

    async def _publish() -> None:
        current_profile = {} if replace else await _fetch_current_profile(
            relays=resolved_relays,
            pubkey_hex=keys.public_key_hex(),
            query_timeout=resolved_query_timeout,
        )
        merged_profile = dict(current_profile)
        merged_profile.update(updates)
        await _run_publish_profile(
            relays=resolved_relays,
            as_user=keys,
            content=merged_profile,
            publish_wait=resolved_publish_wait,
            query_timeout=resolved_query_timeout,
        )

    asyncio.run(_publish())
