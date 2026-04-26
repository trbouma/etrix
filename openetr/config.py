from importlib.resources import files
from pathlib import Path

import yaml

PACKAGED_DEFAULTS_PATH = files("openetr").joinpath("defaults.yaml")
USER_CONFIG_DIR = Path.home() / ".openetr"
USER_CONFIG_PATH = USER_CONFIG_DIR / "config.yaml"
CONFIG_AS_USER_KEY = "as_user"


def load_defaults() -> dict:
    with PACKAGED_DEFAULTS_PATH.open("r", encoding="utf-8") as handle:
        defaults = yaml.safe_load(handle) or {}

    if USER_CONFIG_PATH.exists():
        with USER_CONFIG_PATH.open("r", encoding="utf-8") as handle:
            user_defaults = yaml.safe_load(handle) or {}
        defaults.update(user_defaults)

    return {
        "relays": defaults.get("relays", defaults.get("relay")),
        "kind": defaults["kind"],
        "query_timeout": defaults["query_timeout"],
        "publish_wait": defaults["publish_wait"],
        "limit": defaults["limit"],
        "query_output": defaults["query_output"],
    }


def load_user_config() -> dict:
    if not USER_CONFIG_PATH.exists():
        return {}

    with USER_CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def write_user_config(config: dict) -> None:
    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with USER_CONFIG_PATH.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)


def upsert_user_config(values: dict) -> dict:
    config = load_defaults()
    config.update(load_user_config())
    config.update(values)
    write_user_config(config)
    return config


def packaged_defaults_text() -> str:
    with PACKAGED_DEFAULTS_PATH.open("r", encoding="utf-8") as handle:
        return handle.read()


DEFAULTS = load_defaults()
DEFAULT_RELAYS = DEFAULTS["relays"]
DEFAULT_KIND = DEFAULTS["kind"]
DEFAULT_QUERY_TIMEOUT = DEFAULTS["query_timeout"]
DEFAULT_PUBLISH_WAIT = DEFAULTS["publish_wait"]
DEFAULT_LIMIT = DEFAULTS["limit"]
DEFAULT_QUERY_OUTPUT = DEFAULTS["query_output"]
