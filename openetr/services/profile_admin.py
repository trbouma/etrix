from __future__ import annotations

from monstr.encrypt import Keys

from openetr.config import (
    DEFAULT_RELAYS,
    ProfileConfigRecord,
    ProfilesIndexRecord,
    _async_load_profiles_index,
    _async_store_profile_record,
    _async_store_profile_secret,
    _async_store_profiles_index,
)
from openetr.helpers import format_pubkey


async def create_relay_backed_profile(
    profile_name: str,
    relays: str | None,
    config: dict,
) -> dict:
    normalized_name = profile_name.strip()
    if not normalized_name:
        raise ValueError("profile name must not be empty")

    existing_index = await _async_load_profiles_index(config)
    current_profiles = sorted(existing_index.profiles) if existing_index else []
    active_profile = existing_index.active_profile if existing_index else "default"

    if normalized_name in current_profiles:
        raise ValueError(f"profile '{normalized_name}' already exists")

    signer_keys = Keys()
    await _async_store_profile_secret(normalized_name, signer_keys.private_key_bech32(), config)
    await _async_store_profile_record(
        normalized_name,
        ProfileConfigRecord(
            profile=normalized_name,
            relays=(relays or DEFAULT_RELAYS).strip() or DEFAULT_RELAYS,
        ).model_dump(exclude_none=True),
        config,
    )

    updated_profiles = sorted({*current_profiles, normalized_name})
    await _async_store_profiles_index(
        ProfilesIndexRecord(
            active_profile=active_profile,
            profiles=updated_profiles,
        ),
        config,
    )

    return {
        "profile_name": normalized_name,
        "signer_nsec": signer_keys.private_key_bech32(),
        "signer_npub": signer_keys.public_key_bech32(),
        "signer_pubkey": format_pubkey(signer_keys.public_key_hex()),
        "relays": (relays or DEFAULT_RELAYS).strip() or DEFAULT_RELAYS,
    }
