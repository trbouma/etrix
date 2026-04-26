import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path

import bech32
import click
from monstr.encrypt import Keys
from monstr.event.event import Event

from openetr.config import DEFAULT_KIND

NOBJ_PREFIX = "nobj"


def resolve_keys(as_user: str | None) -> Keys:
    if as_user is None:
        return Keys()

    if not as_user.startswith("nsec"):
        raise click.ClickException("as-user must be provided in nsec bech32 format")

    key = Keys.get_key(as_user)
    if key is None or key.private_key_hex() is None:
        raise click.ClickException("as-user must be a valid nsec private key")
    return key


def build_digest(
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

    digest = normalize_object_identifier(digest)

    return digest.lower(), generated_at, resolved_file, file_size


def build_comment(
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
        f"object={format_object_identifier(digest)}; "
        f"generated_at={generated_at_iso}"
    )


def normalize_object_identifier(identifier: str) -> str:
    if identifier.startswith(NOBJ_PREFIX):
        hrp, data = bech32.bech32_decode(identifier)
        if hrp != NOBJ_PREFIX or data is None:
            raise click.ClickException("object identifier must be a valid nobj value")

        as_bytes = bech32.convertbits(data, 5, 8, False)
        if as_bytes is None:
            raise click.ClickException("object identifier must be a valid nobj value")

        digest = "".join(f"{part:02x}" for part in as_bytes)
    else:
        digest = identifier

    if len(digest) != 64:
        raise click.ClickException("object identifier must be exactly 64 hex characters or a valid nobj")

    try:
        int(digest, 16)
    except ValueError as exc:
        raise click.ClickException("object identifier must be valid hex or a valid nobj") from exc

    return digest.lower()


def format_object_identifier(digest_hex: str, prefix: str = NOBJ_PREFIX) -> str:
    as_int = [int(digest_hex[i:i + 2], 16) for i in range(0, len(digest_hex), 2)]
    data = bech32.convertbits(as_int, 8, 5)
    return bech32.bech32_encode(prefix, data)


def resolve_query_digest(
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
    return normalize_object_identifier(digest), resolved_file


def parse_authors(authors: str | None) -> list[str] | None:
    if not authors:
        return None

    parsed_authors = [author.strip() for author in authors.split(",") if author.strip()]
    resolved_authors = []
    for author in parsed_authors:
        if not author.startswith("npub"):
            raise click.ClickException("authors must be supplied in npub bech32 format")

        author_hex = Keys.bech32_to_hex(author)
        if author_hex is None:
            raise click.ClickException(f"invalid npub author key: {author}")
        resolved_authors.append(author_hex)

    return resolved_authors or None


def resolve_author(author: str) -> str:
    if not author.startswith("npub"):
        raise click.ClickException("author must be supplied in npub bech32 format")

    author_hex = Keys.bech32_to_hex(author)
    if author_hex is None:
        raise click.ClickException(f"invalid npub author key: {author}")
    return author_hex


def format_pubkey(pubkey_hex: str) -> str:
    return Keys.hex_to_bech32(pubkey_hex, prefix="npub")


def print_event(evt: Event, output: str) -> None:
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
