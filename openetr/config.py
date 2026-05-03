import asyncio
from copy import deepcopy
from importlib.resources import files
import hashlib
import json
from pathlib import Path

import click
from monstr.client.client import ClientPool
from monstr.encrypt import Keys
from monstr.encrypt import NIP44Encrypt
from monstr.event.event import Event
from pydantic import BaseModel
import yaml

PACKAGED_DEFAULTS_PATH = files("openetr").joinpath("defaults.yaml")
USER_CONFIG_DIR = Path.home() / ".openetr"
USER_CONFIG_PATH = USER_CONFIG_DIR / "config.yaml"
CONFIG_AS_USER_KEY = "as_user"
ACTIVE_PROFILE_KEY = "active_profile"
PROFILES_KEY = "profiles"
ALIASES_KEY = "aliases"
ROOT_NSEC_KEY = "root_nsec"
HOME_RELAY_KEY = "home_relay"
PROFILE_SECRET_KIND = 31500
DEFAULT_PROFILE_NAME = "default"
PROFILE_KEYS = {
    "as_user",
    "relays",
    "kind",
    "query_timeout",
    "publish_wait",
    "limit",
    "query_output",
    "authors",
    "lei",
}


def _normalize_relays(relays: str | list[str] | tuple[str, ...] | None) -> list[str]:
    if relays is None:
        return []

    if isinstance(relays, (list, tuple)):
        candidates = [str(item) for item in relays]
    else:
        candidates = str(relays).split(",")

    normalized = []
    for item in candidates:
        cleaned = str(item or "").strip()
        if not cleaned:
            continue
        normalized.append(_normalize_relay_url(cleaned))
    return normalized


def _runtime_bootstrap_overrides() -> dict[str, str]:
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return {}
    return dict(ctx.obj or {})


def runtime_bootstrap_enabled() -> bool:
    overrides = _runtime_bootstrap_overrides()
    return bool(overrides.get(ROOT_NSEC_KEY) and overrides.get(HOME_RELAY_KEY))


def resolve_root_nsec(config: dict | None = None) -> str | None:
    overrides = _runtime_bootstrap_overrides()
    if overrides.get(ROOT_NSEC_KEY):
        return overrides[ROOT_NSEC_KEY]
    config = config or load_user_config()
    return config.get(ROOT_NSEC_KEY)


def resolve_home_relays(config: dict | None = None) -> list[str]:
    overrides = _runtime_bootstrap_overrides()
    if overrides.get(HOME_RELAY_KEY):
        return _normalize_relays(overrides[HOME_RELAY_KEY])
    config = config or load_user_config()
    configured = config.get(HOME_RELAY_KEY)
    if configured:
        return _normalize_relays(configured)
    return [_default_home_relay(config)]


def resolve_home_relays_value(config: dict | None = None) -> str:
    return ",".join(resolve_home_relays(config))


def packaged_defaults() -> dict:
    with PACKAGED_DEFAULTS_PATH.open("r", encoding="utf-8") as handle:
        defaults = yaml.safe_load(handle) or {}

    return {
        "relays": defaults.get("relays", defaults.get("relay")),
        "kind": defaults["kind"],
        "query_timeout": defaults["query_timeout"],
        "publish_wait": defaults["publish_wait"],
        "limit": defaults["limit"],
        "query_output": defaults["query_output"],
    }


def _normalize_relay_url(relay: str) -> str:
    cleaned = str(relay or "").strip()
    if not cleaned:
        raise click.ClickException("relay value must not be empty")
    if cleaned.startswith("wss://") or cleaned.startswith("ws://"):
        return cleaned
    return f"wss://{cleaned}"


def _default_home_relay(config: dict | None = None) -> str:
    config = config or {}
    profiles = config.get(PROFILES_KEY, {})
    active_profile = config.get(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME)
    active_profile_config = profiles.get(active_profile, {})
    relay_values = active_profile_config.get("relays") or packaged_defaults().get("relays") or ""
    if isinstance(relay_values, str):
        first = next((item.strip() for item in relay_values.split(",") if item.strip()), "")
    elif isinstance(relay_values, list):
        first = next((str(item).strip() for item in relay_values if str(item).strip()), "")
    else:
        first = ""
    return _normalize_relay_url(first)


def generate_recovery_phrase_from_nsec(nsec: str) -> str | None:
    try:
        from mnemonic import Mnemonic
    except ModuleNotFoundError:
        return None

    key = Keys.get_key(nsec)
    if key is None or key.private_key_hex() is None:
        raise click.ClickException("root nsec is invalid and cannot be converted to a recovery phrase")

    mnemonic = Mnemonic("english")
    return mnemonic.to_mnemonic(bytes.fromhex(key.private_key_hex()))


def _legacy_profile_values(raw_config: dict) -> dict:
    values = {}
    for key in PROFILE_KEYS:
        if key in raw_config:
            values[key] = raw_config[key]
    if "relay" in raw_config and "relays" not in values:
        values["relays"] = raw_config["relay"]
    return values


def normalize_user_config(raw_config: dict | None) -> dict:
    raw_config = raw_config or {}
    default_profile_defaults = packaged_defaults()

    if PROFILES_KEY in raw_config:
        normalized = deepcopy(raw_config)
        normalized.setdefault(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME)
        normalized.setdefault(PROFILES_KEY, {})
        normalized.setdefault(ALIASES_KEY, {})
        normalized[PROFILES_KEY].setdefault(DEFAULT_PROFILE_NAME, deepcopy(default_profile_defaults))
        return normalized

    legacy_values = _legacy_profile_values(raw_config)
    if not legacy_values:
        return {
            ROOT_NSEC_KEY: raw_config.get(ROOT_NSEC_KEY),
            HOME_RELAY_KEY: raw_config.get(HOME_RELAY_KEY),
            ACTIVE_PROFILE_KEY: DEFAULT_PROFILE_NAME,
            ALIASES_KEY: {},
            PROFILES_KEY: {
                DEFAULT_PROFILE_NAME: deepcopy(default_profile_defaults),
            },
        }

    return {
        ROOT_NSEC_KEY: raw_config.get(ROOT_NSEC_KEY),
        HOME_RELAY_KEY: raw_config.get(HOME_RELAY_KEY),
        ACTIVE_PROFILE_KEY: raw_config.get(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME),
        ALIASES_KEY: raw_config.get(ALIASES_KEY, {}),
        PROFILES_KEY: {
            raw_config.get(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME): legacy_values,
        },
    }


def load_raw_user_config() -> dict:
    if not USER_CONFIG_PATH.exists():
        return {}

    with USER_CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_user_config() -> dict:
    return normalize_user_config(load_raw_user_config())


def write_bootstrap_config(root_nsec: str, home_relay: str) -> None:
    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        ROOT_NSEC_KEY: root_nsec,
        HOME_RELAY_KEY: home_relay,
    }
    with USER_CONFIG_PATH.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False)


def write_user_config(config: dict) -> None:
    if runtime_bootstrap_enabled():
        return
    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    normalized = normalize_user_config(config)
    with USER_CONFIG_PATH.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(normalized, handle, sort_keys=False)


def ensure_root_bootstrap(config: dict | None = None, *, write: bool = True) -> tuple[dict, dict]:
    resolved = deepcopy(config or load_user_config())
    changes: dict = {}
    default_profile_defaults = packaged_defaults()
    overrides = _runtime_bootstrap_overrides()
    using_runtime_bootstrap = bool(overrides.get(ROOT_NSEC_KEY) and overrides.get(HOME_RELAY_KEY))

    profiles = resolved.setdefault(PROFILES_KEY, {})
    if DEFAULT_PROFILE_NAME not in profiles or not profiles.get(DEFAULT_PROFILE_NAME):
        profiles[DEFAULT_PROFILE_NAME] = deepcopy(default_profile_defaults)
        changes["default_profile_initialized"] = True

    if overrides.get(ROOT_NSEC_KEY):
        resolved[ROOT_NSEC_KEY] = overrides[ROOT_NSEC_KEY]
    if overrides.get(HOME_RELAY_KEY):
        resolved[HOME_RELAY_KEY] = overrides[HOME_RELAY_KEY]

    if not resolved.get(ROOT_NSEC_KEY):
        keys = Keys()
        resolved[ROOT_NSEC_KEY] = keys.private_key_bech32()
        changes[ROOT_NSEC_KEY] = resolved[ROOT_NSEC_KEY]
        recovery_phrase = generate_recovery_phrase_from_nsec(resolved[ROOT_NSEC_KEY])
        if recovery_phrase:
            changes["root_recovery_phrase"] = recovery_phrase
        else:
            changes["root_recovery_phrase_unavailable"] = True

    if not resolved.get(HOME_RELAY_KEY):
        resolved[HOME_RELAY_KEY] = _default_home_relay(resolved)
        changes[HOME_RELAY_KEY] = resolved[HOME_RELAY_KEY]

    if changes and write and not using_runtime_bootstrap:
        raw_existing = load_raw_user_config()
        if not raw_existing:
            write_bootstrap_config(resolved[ROOT_NSEC_KEY], resolved[HOME_RELAY_KEY])
        else:
            write_user_config(resolved)

    return resolved, changes


def get_active_profile_name(config: dict | None = None) -> str:
    config = config or load_user_config()
    index = load_profiles_index(config)
    if index and index.active_profile:
        return index.active_profile
    return config.get(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME)


def list_profiles(config: dict | None = None) -> list[str]:
    config = config or load_user_config()
    index = load_profiles_index(config)
    if index and index.profiles:
        return sorted(index.profiles)
    return sorted(config.get(PROFILES_KEY, {}).keys())


def get_profile_config(profile: str | None = None, config: dict | None = None) -> dict:
    config = config or load_user_config()
    profile_name = profile or get_active_profile_name(config)
    profiles = config.get(PROFILES_KEY, {})
    if profile_name not in profiles:
        index = load_profiles_index(config)
        if index is None or profile_name not in index.profiles:
            raise click.ClickException(f"profile '{profile_name}' was not found in {USER_CONFIG_PATH}")
        profile_values = {}
    else:
        profile_values = deepcopy(profiles.get(profile_name, {}))
    remote_profile_values = load_profile_record(profile_name, config)
    if remote_profile_values:
        remote_profile_values.pop("schema_version", None)
        remote_profile_values.pop("profile", None)
        profile_values.update(remote_profile_values)

    if CONFIG_AS_USER_KEY not in profile_values:
        signer_nsec = get_profile_signer_nsec(profile_name, config)
        if signer_nsec:
            profile_values[CONFIG_AS_USER_KEY] = signer_nsec

    resolved = packaged_defaults()
    resolved.update(profile_values)
    return resolved


def ensure_profile(profile: str, config: dict | None = None) -> dict:
    config = deepcopy(config or load_user_config())
    config.setdefault(PROFILES_KEY, {})
    config[PROFILES_KEY].setdefault(profile, {})
    if profile not in config[PROFILES_KEY]:
        config[PROFILES_KEY][profile] = {}
    return config


def upsert_profile_config(profile: str, values: dict, config: dict | None = None) -> dict:
    config = ensure_profile(profile, config)
    config[PROFILES_KEY][profile].update(values)
    write_user_config(config)
    sync_profile_record(profile, config)
    sync_profiles_index(config)
    return config


def delete_profile(profile: str, config: dict | None = None) -> dict:
    config = deepcopy(config or load_user_config())
    profiles = config.get(PROFILES_KEY, {})
    profiles.pop(profile, None)
    if not profiles:
        profiles[DEFAULT_PROFILE_NAME] = {}
        config[ACTIVE_PROFILE_KEY] = DEFAULT_PROFILE_NAME
    elif config.get(ACTIVE_PROFILE_KEY) == profile:
        config[ACTIVE_PROFILE_KEY] = sorted(profiles.keys())[0]
    config[PROFILES_KEY] = profiles
    write_user_config(config)
    delete_profile_record(profile, config)
    sync_profiles_index(config)
    return config


def set_active_profile(profile: str, config: dict | None = None) -> dict:
    config = ensure_profile(profile, config)
    config[ACTIVE_PROFILE_KEY] = profile
    write_user_config(config)
    sync_profiles_index(config)
    return config


def render_user_config_template() -> str:
    bootstrap, _ = ensure_root_bootstrap(
        {
            ACTIVE_PROFILE_KEY: DEFAULT_PROFILE_NAME,
            ALIASES_KEY: {},
            PROFILES_KEY: {
                DEFAULT_PROFILE_NAME: packaged_defaults(),
            },
        },
        write=False,
    )
    template = {
        ROOT_NSEC_KEY: bootstrap[ROOT_NSEC_KEY],
        HOME_RELAY_KEY: bootstrap[HOME_RELAY_KEY],
        ACTIVE_PROFILE_KEY: DEFAULT_PROFILE_NAME,
        ALIASES_KEY: {},
        PROFILES_KEY: {
            DEFAULT_PROFILE_NAME: packaged_defaults(),
        },
    }
    return yaml.safe_dump(template, sort_keys=False)


def get_aliases(config: dict | None = None) -> dict[str, str]:
    config = config or load_user_config()
    index = load_aliases_index(config)
    if index is not None:
        return deepcopy(index.aliases)
    return deepcopy(config.get(ALIASES_KEY, {}))


def upsert_alias(alias: str, npub: str, config: dict | None = None) -> dict:
    config = deepcopy(config or load_user_config())
    config.setdefault(ALIASES_KEY, {})
    config[ALIASES_KEY][alias] = npub
    write_user_config(config)
    sync_aliases_index(config)
    return config


def delete_alias(alias: str, config: dict | None = None) -> dict:
    config = deepcopy(config or load_user_config())
    aliases = config.setdefault(ALIASES_KEY, {})
    aliases.pop(alias, None)
    write_user_config(config)
    sync_aliases_index(config)
    return config


DEFAULTS = packaged_defaults()
DEFAULT_RELAYS = DEFAULTS["relays"]
DEFAULT_KIND = DEFAULTS["kind"]
DEFAULT_QUERY_TIMEOUT = DEFAULTS["query_timeout"]
DEFAULT_PUBLISH_WAIT = DEFAULTS["publish_wait"]
DEFAULT_LIMIT = DEFAULTS["limit"]
DEFAULT_QUERY_OUTPUT = DEFAULTS["query_output"]


class ProfileSecretRecord(BaseModel):
    schema_version: int = 1
    profile: str
    as_user: str
    npub: str


class ProfilesIndexRecord(BaseModel):
    schema_version: int = 1
    active_profile: str = DEFAULT_PROFILE_NAME
    profiles: list[str] = [DEFAULT_PROFILE_NAME]


class AliasIndexRecord(BaseModel):
    schema_version: int = 1
    aliases: dict[str, str] = {}


class ProfileConfigRecord(BaseModel):
    schema_version: int = 1
    profile: str
    relays: str | None = None
    kind: int | None = None
    query_timeout: int | None = None
    publish_wait: float | None = None
    limit: int | None = None
    query_output: str | None = None
    authors: list[str] | None = None
    lei: str | None = None


def _get_root_keys(config: dict | None = None) -> Keys:
    root_nsec = resolve_root_nsec(config)
    if not root_nsec:
        raise click.ClickException(
            f"root nsec was not found in {USER_CONFIG_PATH}; use --as-root for stateless operation"
        )
    return resolve_key_string(root_nsec)


def resolve_key_string(value: str) -> Keys:
    key = Keys.get_key(value)
    if key is None or key.private_key_hex() is None:
        raise click.ClickException("invalid nsec private key")
    return key


def _profile_secret_label(profile: str) -> str:
    return f"config:profile:{profile}:as_user"


def _profiles_index_label() -> str:
    return "profiles"


def _aliases_index_label() -> str:
    return "aliases"


def _profile_config_label(profile: str) -> str:
    return f"config:profile:{profile}"


def _salted_record_digest(label: str, root_keys: Keys) -> str:
    digest = hashlib.sha256()
    digest.update(root_keys.private_key_hex().encode("utf-8"))
    digest.update(label.encode("utf-8"))
    return digest.hexdigest()


async def _async_store_profiles_index(index: ProfilesIndexRecord, config: dict) -> None:
    root_keys = _get_root_keys(config)
    d_value = _salted_record_digest(_profiles_index_label(), root_keys)
    encrypted = NIP44Encrypt(root_keys).encrypt(
        index.model_dump_json(),
        to_pub_k=root_keys.public_key_hex(),
    )
    event = Event(
        kind=PROFILE_SECRET_KIND,
        content=encrypted,
        pub_key=root_keys.public_key_hex(),
        tags=[["d", d_value]],
    )
    event.sign(root_keys.private_key_hex())
    async with ClientPool(resolve_home_relays(config)) as client:
        client.publish(event)
        await asyncio.sleep(0.2)


async def _async_store_aliases_index(index: AliasIndexRecord, config: dict) -> None:
    root_keys = _get_root_keys(config)
    d_value = _salted_record_digest(_aliases_index_label(), root_keys)
    encrypted = NIP44Encrypt(root_keys).encrypt(
        index.model_dump_json(),
        to_pub_k=root_keys.public_key_hex(),
    )
    event = Event(
        kind=PROFILE_SECRET_KIND,
        content=encrypted,
        pub_key=root_keys.public_key_hex(),
        tags=[["d", d_value]],
    )
    event.sign(root_keys.private_key_hex())
    async with ClientPool(resolve_home_relays(config)) as client:
        client.publish(event)
        await asyncio.sleep(0.2)


async def _async_load_profiles_index(config: dict) -> ProfilesIndexRecord | None:
    root_keys = _get_root_keys(config)
    d_value = _salted_record_digest(_profiles_index_label(), root_keys)
    query_filter = {
        "authors": [root_keys.public_key_hex()],
        "kinds": [PROFILE_SECRET_KIND],
        "#d": [d_value],
        "limit": 1,
    }
    async with ClientPool(resolve_home_relays(config)) as client:
        events = await client.query(query_filter)
    Event.sort(events, inplace=True, reverse=True)
    if not events:
        return None
    try:
        decrypted = NIP44Encrypt(root_keys).decrypt(events[0].content, root_keys.public_key_hex())
        return ProfilesIndexRecord.model_validate_json(decrypted)
    except Exception:
        return None


async def _async_load_aliases_index(config: dict) -> AliasIndexRecord | None:
    root_keys = _get_root_keys(config)
    d_value = _salted_record_digest(_aliases_index_label(), root_keys)
    query_filter = {
        "authors": [root_keys.public_key_hex()],
        "kinds": [PROFILE_SECRET_KIND],
        "#d": [d_value],
        "limit": 1,
    }
    async with ClientPool(resolve_home_relays(config)) as client:
        events = await client.query(query_filter)
    Event.sort(events, inplace=True, reverse=True)
    if not events:
        return None
    try:
        decrypted = NIP44Encrypt(root_keys).decrypt(events[0].content, root_keys.public_key_hex())
        return AliasIndexRecord.model_validate_json(decrypted)
    except Exception:
        return None


def load_profiles_index(config: dict | None = None) -> ProfilesIndexRecord | None:
    resolved, _ = ensure_root_bootstrap(config)
    try:
        return asyncio.run(_async_load_profiles_index(resolved))
    except Exception:
        return None


def hydrate_local_profiles_from_index(config: dict | None = None) -> dict:
    resolved = deepcopy(config or load_user_config())
    index = load_profiles_index(resolved)
    if index is None:
        return resolved

    profiles = resolved.setdefault(PROFILES_KEY, {})
    for profile_name in index.profiles:
        profiles.setdefault(profile_name, {})
    resolved[ACTIVE_PROFILE_KEY] = index.active_profile
    return resolved


def load_aliases_index(config: dict | None = None) -> AliasIndexRecord | None:
    resolved, _ = ensure_root_bootstrap(config)
    try:
        return asyncio.run(_async_load_aliases_index(resolved))
    except Exception:
        return None


def sync_profiles_index(config: dict | None = None) -> tuple[dict, ProfilesIndexRecord]:
    resolved, _ = ensure_root_bootstrap(config)
    active_profile = resolved.get(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME)
    local_profiles = sorted(resolved.get(PROFILES_KEY, {}).keys()) or [DEFAULT_PROFILE_NAME]
    if active_profile not in local_profiles:
        active_profile = local_profiles[0]
        resolved[ACTIVE_PROFILE_KEY] = active_profile
        write_user_config(resolved)
    index = ProfilesIndexRecord(active_profile=active_profile, profiles=local_profiles)
    try:
        asyncio.run(_async_store_profiles_index(index, resolved))
    except Exception as exc:
        raise click.ClickException(f"failed to store relay-backed profiles index: {exc}") from exc
    return resolved, index


def sync_aliases_index(config: dict | None = None) -> tuple[dict, AliasIndexRecord]:
    resolved, _ = ensure_root_bootstrap(config)
    aliases = deepcopy(resolved.get(ALIASES_KEY, {}))
    index = AliasIndexRecord(aliases=aliases)
    try:
        asyncio.run(_async_store_aliases_index(index, resolved))
    except Exception as exc:
        raise click.ClickException(f"failed to store relay-backed aliases index: {exc}") from exc
    return resolved, index


def _profile_record_values(values: dict) -> dict:
    allowed = {
        "relays",
        "kind",
        "query_timeout",
        "publish_wait",
        "limit",
        "query_output",
        "authors",
        "lei",
    }
    return {key: deepcopy(value) for key, value in values.items() if key in allowed and value is not None}


async def _async_store_profile_record(profile: str, values: dict, config: dict) -> None:
    root_keys = _get_root_keys(config)
    d_value = _salted_record_digest(_profile_config_label(profile), root_keys)
    payload = ProfileConfigRecord(profile=profile, **_profile_record_values(values))
    encrypted = NIP44Encrypt(root_keys).encrypt(
        payload.model_dump_json(),
        to_pub_k=root_keys.public_key_hex(),
    )
    event = Event(
        kind=PROFILE_SECRET_KIND,
        content=encrypted,
        pub_key=root_keys.public_key_hex(),
        tags=[["d", d_value]],
    )
    event.sign(root_keys.private_key_hex())
    async with ClientPool(resolve_home_relays(config)) as client:
        client.publish(event)
        await asyncio.sleep(0.2)


async def _async_load_profile_record(profile: str, config: dict) -> ProfileConfigRecord | None:
    root_keys = _get_root_keys(config)
    d_value = _salted_record_digest(_profile_config_label(profile), root_keys)
    query_filter = {
        "authors": [root_keys.public_key_hex()],
        "kinds": [PROFILE_SECRET_KIND],
        "#d": [d_value],
        "limit": 1,
    }
    async with ClientPool(resolve_home_relays(config)) as client:
        events = await client.query(query_filter)
    Event.sort(events, inplace=True, reverse=True)
    if not events:
        return None
    try:
        decrypted = NIP44Encrypt(root_keys).decrypt(events[0].content, root_keys.public_key_hex())
        return ProfileConfigRecord.model_validate_json(decrypted)
    except Exception:
        return None


def store_profile_record(profile: str, values: dict, config: dict | None = None) -> None:
    resolved, _ = ensure_root_bootstrap(config)
    try:
        asyncio.run(_async_store_profile_record(profile, values, resolved))
    except Exception as exc:
        raise click.ClickException(f"failed to store relay-backed profile record for '{profile}': {exc}") from exc


def load_profile_record(profile: str, config: dict | None = None) -> dict | None:
    resolved, _ = ensure_root_bootstrap(config)
    try:
        record = asyncio.run(_async_load_profile_record(profile, resolved))
    except Exception:
        record = None
    if record is None:
        return None
    return record.model_dump(exclude_none=True)


async def _async_delete_profile_record(profile: str, config: dict) -> bool:
    root_keys = _get_root_keys(config)
    d_value = _salted_record_digest(_profile_config_label(profile), root_keys)
    query_filter = {
        "authors": [root_keys.public_key_hex()],
        "kinds": [PROFILE_SECRET_KIND],
        "#d": [d_value],
        "limit": 1,
    }
    async with ClientPool(resolve_home_relays(config)) as client:
        events = await client.query(query_filter)
        Event.sort(events, inplace=True, reverse=True)
        if not events:
            return False
        delete_event = Event(
            kind=Event.KIND_DELETE,
            content="",
            pub_key=root_keys.public_key_hex(),
            tags=[["e", events[0].id]],
        )
        delete_event.sign(root_keys.private_key_hex())
        client.publish(delete_event)
        await asyncio.sleep(0.2)
    return True


def delete_profile_record(profile: str, config: dict | None = None) -> bool:
    resolved, _ = ensure_root_bootstrap(config)
    try:
        return asyncio.run(_async_delete_profile_record(profile, resolved))
    except Exception:
        return False


def sync_profile_record(profile: str, config: dict | None = None) -> None:
    resolved = deepcopy(config or load_user_config())
    local_values = resolved.get(PROFILES_KEY, {}).get(profile, {})
    store_profile_record(profile, local_values, resolved)


async def _async_store_profile_secret(profile: str, nsec: str, config: dict) -> str:
    root_keys = _get_root_keys(config)
    signer_keys = resolve_key_string(nsec)
    label = _profile_secret_label(profile)
    d_value = _salted_record_digest(label, root_keys)
    payload = ProfileSecretRecord(
        profile=profile,
        as_user=signer_keys.private_key_bech32(),
        npub=signer_keys.public_key_bech32(),
    )
    encrypted = NIP44Encrypt(root_keys).encrypt(
        payload.model_dump_json(),
        to_pub_k=root_keys.public_key_hex(),
    )
    event = Event(
        kind=PROFILE_SECRET_KIND,
        content=encrypted,
        pub_key=root_keys.public_key_hex(),
        tags=[["d", d_value]],
    )
    event.sign(root_keys.private_key_hex())
    async with ClientPool(resolve_home_relays(config)) as client:
        client.publish(event)
        await asyncio.sleep(0.2)
    return payload.npub


def store_profile_secret(profile: str, nsec: str, config: dict | None = None) -> str:
    resolved, _ = ensure_root_bootstrap(config)
    try:
        return asyncio.run(_async_store_profile_secret(profile, nsec, resolved))
    except Exception as exc:
        raise click.ClickException(f"failed to store relay-backed profile signer for '{profile}': {exc}") from exc


async def _async_load_profile_secret(profile: str, config: dict) -> str | None:
    root_keys = _get_root_keys(config)
    label = _profile_secret_label(profile)
    d_value = _salted_record_digest(label, root_keys)
    query_filter = {
        "authors": [root_keys.public_key_hex()],
        "kinds": [PROFILE_SECRET_KIND],
        "#d": [d_value],
        "limit": 1,
    }
    async with ClientPool(resolve_home_relays(config)) as client:
        events = await client.query(query_filter)

    Event.sort(events, inplace=True, reverse=True)
    if not events:
        return None

    try:
        decrypted = NIP44Encrypt(root_keys).decrypt(events[0].content, root_keys.public_key_hex())
        payload = ProfileSecretRecord.model_validate_json(decrypted)
    except Exception:
        return None
    return payload.as_user


def load_profile_secret(profile: str, config: dict | None = None) -> str | None:
    resolved, _ = ensure_root_bootstrap(config)
    try:
        return asyncio.run(_async_load_profile_secret(profile, resolved))
    except Exception:
        return None


async def _async_delete_profile_secret(profile: str, config: dict) -> bool:
    root_keys = _get_root_keys(config)
    label = _profile_secret_label(profile)
    d_value = _salted_record_digest(label, root_keys)
    query_filter = {
        "authors": [root_keys.public_key_hex()],
        "kinds": [PROFILE_SECRET_KIND],
        "#d": [d_value],
        "limit": 1,
    }
    async with ClientPool(resolve_home_relays(config)) as client:
        events = await client.query(query_filter)
        Event.sort(events, inplace=True, reverse=True)
        if not events:
            return False
        delete_event = Event(
            kind=Event.KIND_DELETE,
            content="",
            pub_key=root_keys.public_key_hex(),
            tags=[["e", events[0].id]],
        )
        delete_event.sign(root_keys.private_key_hex())
        client.publish(delete_event)
        await asyncio.sleep(0.2)
    return True


def delete_profile_secret(profile: str, config: dict | None = None) -> bool:
    resolved, _ = ensure_root_bootstrap(config)
    try:
        return asyncio.run(_async_delete_profile_secret(profile, resolved))
    except Exception:
        return False


def get_profile_signer_nsec(profile: str | None = None, config: dict | None = None) -> str | None:
    config = config or load_user_config()
    profile_name = profile or get_active_profile_name(config)
    local_value = config.get(PROFILES_KEY, {}).get(profile_name, {}).get(CONFIG_AS_USER_KEY)
    remote_value = load_profile_secret(profile_name, config)
    return remote_value or local_value


def remove_local_profile_secret(profile: str, config: dict | None = None) -> dict:
    resolved = deepcopy(config or load_user_config())
    profile_values = resolved.setdefault(PROFILES_KEY, {}).setdefault(profile, {})
    profile_values.pop(CONFIG_AS_USER_KEY, None)
    write_user_config(resolved)
    return resolved
