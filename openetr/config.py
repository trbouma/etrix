from copy import deepcopy
from importlib.resources import files
from pathlib import Path

import yaml

PACKAGED_DEFAULTS_PATH = files("openetr").joinpath("defaults.yaml")
USER_CONFIG_DIR = Path.home() / ".openetr"
USER_CONFIG_PATH = USER_CONFIG_DIR / "config.yaml"
CONFIG_AS_USER_KEY = "as_user"
ACTIVE_PROFILE_KEY = "active_profile"
PROFILES_KEY = "profiles"
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

    if PROFILES_KEY in raw_config:
        normalized = deepcopy(raw_config)
        normalized.setdefault(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME)
        normalized.setdefault(PROFILES_KEY, {})
        return normalized

    legacy_values = _legacy_profile_values(raw_config)
    if not legacy_values:
        return {
            ACTIVE_PROFILE_KEY: DEFAULT_PROFILE_NAME,
            PROFILES_KEY: {
                DEFAULT_PROFILE_NAME: {},
            },
        }

    return {
        ACTIVE_PROFILE_KEY: raw_config.get(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME),
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


def write_user_config(config: dict) -> None:
    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    normalized = normalize_user_config(config)
    with USER_CONFIG_PATH.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(normalized, handle, sort_keys=False)


def get_active_profile_name(config: dict | None = None) -> str:
    config = config or load_user_config()
    return config.get(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME)


def list_profiles(config: dict | None = None) -> list[str]:
    config = config or load_user_config()
    return sorted(config.get(PROFILES_KEY, {}).keys())


def get_profile_config(profile: str | None = None, config: dict | None = None) -> dict:
    config = config or load_user_config()
    profile_name = profile or get_active_profile_name(config)
    profile_values = config.get(PROFILES_KEY, {}).get(profile_name, {})

    resolved = packaged_defaults()
    resolved.update(profile_values)
    return resolved


def ensure_profile(profile: str, config: dict | None = None) -> dict:
    config = deepcopy(config or load_user_config())
    config.setdefault(PROFILES_KEY, {})
    config[PROFILES_KEY].setdefault(profile, {})
    return config


def upsert_profile_config(profile: str, values: dict, config: dict | None = None) -> dict:
    config = ensure_profile(profile, config)
    config[PROFILES_KEY][profile].update(values)
    write_user_config(config)
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
    return config


def set_active_profile(profile: str, config: dict | None = None) -> dict:
    config = ensure_profile(profile, config)
    config[ACTIVE_PROFILE_KEY] = profile
    write_user_config(config)
    return config


def render_user_config_template() -> str:
    template = {
        ACTIVE_PROFILE_KEY: DEFAULT_PROFILE_NAME,
        PROFILES_KEY: {
            DEFAULT_PROFILE_NAME: packaged_defaults(),
        },
    }
    return yaml.safe_dump(template, sort_keys=False)


DEFAULTS = packaged_defaults()
DEFAULT_RELAYS = DEFAULTS["relays"]
DEFAULT_KIND = DEFAULTS["kind"]
DEFAULT_QUERY_TIMEOUT = DEFAULTS["query_timeout"]
DEFAULT_PUBLISH_WAIT = DEFAULTS["publish_wait"]
DEFAULT_LIMIT = DEFAULTS["limit"]
DEFAULT_QUERY_OUTPUT = DEFAULTS["query_output"]
