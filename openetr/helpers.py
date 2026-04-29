import hashlib
import json
import random
import string
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import bech32
import click
from monstr.encrypt import Keys
from monstr.event.event import Event

from openetr.config import DEFAULT_KIND

NOBJ_PREFIX = "nobj"
NEVENT_PREFIX = "nevent"
GENERATE_LEI_SENTINEL = "__GENERATE_LEI__"


def _lei_char_to_int(char: str) -> str:
    if char.isdigit():
        return char
    return str(ord(char) - 55)


def _prepare_lei_for_mod97(value: str) -> str:
    return "".join(_lei_char_to_int(char) for char in value)


def _lei_mod97(value: str) -> int:
    remainder = 0
    for char in value:
        remainder = (remainder * 10 + int(char)) % 97
    return remainder


def _compute_lei_check_digits(base: str) -> str:
    prepared = _prepare_lei_for_mod97(base + "00")
    return str(98 - _lei_mod97(prepared)).zfill(2)


def generate_example_lei() -> str:
    lou = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    entity = "".join(random.choices(string.ascii_uppercase + string.digits, k=14))
    base = lou + entity
    return base + _compute_lei_check_digits(base)


def validate_lei(value: str) -> bool:
    lei_value = value.strip().upper()
    if len(lei_value) != 20:
        return False
    if not all(char.isdigit() or char.isalpha() for char in lei_value):
        return False
    if not lei_value[-2:].isdigit():
        return False
    return _lei_mod97(_prepare_lei_for_mod97(lei_value)) == 1


def validate_npub(value: str) -> bool:
    npub_value = value.strip()
    if not npub_value.startswith("npub"):
        return False

    try:
        pubkey_hex = Keys.bech32_to_hex(npub_value)
    except Exception:
        return False
    if pubkey_hex is None or len(pubkey_hex) != 64:
        return False

    try:
        int(pubkey_hex, 16)
    except ValueError:
        return False

    return True


def resolve_lei(value: str | None) -> str | None:
    if value is None:
        return None
    if value == GENERATE_LEI_SENTINEL:
        return generate_example_lei()

    lei_value = value.strip().upper()
    if not validate_lei(lei_value):
        raise click.ClickException("lei must be a valid 20-character Legal Entity Identifier")
    return lei_value


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


def assert_hex_object_identifier(value: str) -> str:
    normalized = normalize_object_identifier(value)
    if normalized != value:
        raise click.ClickException("internal error: object identifier must be normalized to lowercase hex")
    return value


def assert_hex_pubkey(value: str) -> str:
    if len(value) != 64:
        raise click.ClickException("internal error: pubkey must be 64 hex characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise click.ClickException("internal error: pubkey must be hex") from exc
    if value.lower() != value:
        raise click.ClickException("internal error: pubkey must be normalized to lowercase hex")
    return value


def normalize_event_reference(identifier: str) -> str:
    if identifier.startswith(NEVENT_PREFIX):
        hrp, data = bech32.bech32_decode(identifier)
        if hrp != NEVENT_PREFIX or data is None:
            raise click.ClickException("event reference must be a valid nevent value")

        as_bytes = bech32.convertbits(data, 5, 8, False)
        if as_bytes is None:
            raise click.ClickException("event reference must be a valid nevent value")

        event_id = "".join(f"{part:02x}" for part in as_bytes)
    else:
        event_id = identifier

    if len(event_id) != 64:
        raise click.ClickException("event reference must be exactly 64 hex characters or a valid nevent")

    try:
        int(event_id, 16)
    except ValueError as exc:
        raise click.ClickException("event reference must be valid hex or a valid nevent") from exc

    return event_id.lower()


def assert_hex_event_id(value: str) -> str:
    normalized = normalize_event_reference(value)
    if normalized != value:
        raise click.ClickException("internal error: event id must be normalized to lowercase hex")
    return value


def format_object_identifier(digest_hex: str, prefix: str = NOBJ_PREFIX) -> str:
    as_int = [int(digest_hex[i:i + 2], 16) for i in range(0, len(digest_hex), 2)]
    data = bech32.convertbits(as_int, 8, 5)
    return bech32.bech32_encode(prefix, data)


def format_event_reference(event_id_hex: str, prefix: str = NEVENT_PREFIX) -> str:
    as_int = [int(event_id_hex[i:i + 2], 16) for i in range(0, len(event_id_hex), 2)]
    data = bech32.convertbits(as_int, 8, 5)
    return bech32.bech32_encode(NEVENT_PREFIX, data)


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
    if author.startswith("npub"):
        author_hex = Keys.bech32_to_hex(author)
        if author_hex is None:
            raise click.ClickException(f"invalid npub author key: {author}")
        return author_hex

    normalized_author = author.strip().lower()

    if "@" not in normalized_author:
        raise click.ClickException("author must be supplied in npub bech32 or NIP-05 format")

    local_part, domain = normalized_author.split("@", 1)
    if not local_part or not domain:
        raise click.ClickException(f"invalid NIP-05 identifier: {author}")

    lookup_url = f"https://{domain}/.well-known/nostr.json?{urlencode({'name': local_part})}"
    request = Request(
        lookup_url,
        headers={
            "User-Agent": "openetr/0.1 (+https://github.com/trbouma/openetr)",
            "Accept": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=10) as response:
            payload = json.load(response)
    except Exception as exc:
        raise click.ClickException(f"failed to resolve NIP-05 identifier {author}: {exc}") from exc

    names = payload.get("names", {})
    author_hex = names.get(local_part)
    if not author_hex:
        raise click.ClickException(f"NIP-05 identifier not found: {author}")

    if len(author_hex) != 64:
        raise click.ClickException(f"NIP-05 identifier resolved to an invalid pubkey: {author}")

    try:
        int(author_hex, 16)
    except ValueError as exc:
        raise click.ClickException(f"NIP-05 identifier resolved to an invalid pubkey: {author}") from exc

    return author_hex.lower()


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
