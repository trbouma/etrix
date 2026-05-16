from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
from typing import Any

import bech32
import click
from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.templating import Jinja2Templates
from monstr.encrypt import Keys
from starlette.staticfiles import StaticFiles

from app.encrypted_session import EncryptedSessionMiddleware
from openetr.config import DEFAULT_LIMIT, DEFAULT_PROFILE_NAME, DEFAULT_QUERY_TIMEOUT, DEFAULT_RELAYS, _async_load_profile_record, _async_load_profile_secret, _async_load_profiles_index, load_user_config, packaged_defaults, reset_runtime_bootstrap_overrides, set_runtime_bootstrap_overrides
from openetr.guards import evaluate_issue_etr_guard
from openetr.helpers import format_object_identifier, format_pubkey, normalize_relays, resolve_keys, validate_relays
from openetr.services.issue_etr import publish_issue_etr
from openetr.services.profile_admin import create_relay_backed_profile, initialize_relay_backed_root
from openetr.services.profile_publish import PROFILE_FIELDS, publish_profile_updates
from openetr.services.query_etr import build_query_etr_result, compact_profile, fetch_profile


APP_TITLE = "OpenETR Demo App"
CONTROL_TRANSFER_KIND = 31416
NOBJ_PREFIX = "nobj"
SESSION_ROOT_NSEC_KEY = "openetr_root_nsec"
SESSION_SIGNER_NSEC_KEY = "openetr_signer_nsec"
SESSION_PROFILE_KEY = "openetr_profile"
SESSION_BOOTSTRAP_RELAYS_KEY = "openetr_bootstrap_relays"
SESSION_DEFAULT_RELAYS_KEY = "openetr_default_relays"


def read_runtime_value(name: str, default: str | None = None) -> str | None:
    file_path = (os.environ.get(f"{name}_FILE") or "").strip()
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()

    value = os.environ.get(name)
    if value not in (None, ""):
        return value
    return default


SESSION_SECRET = read_runtime_value("OPENETR_APP_SESSION_SECRET", "openetr-demo-session-secret") or "openetr-demo-session-secret"
SITE_URL = read_runtime_value("OPENETR_SITE_URL", "https://trbouma.github.io/openetr/") or "https://trbouma.github.io/openetr/"
GIT_COMMIT = read_runtime_value("OPENETR_GIT_COMMIT", "unknown") or "unknown"
TEMPLATE_DIR = Path(__file__).parent / "templates"
ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"
APP_ASSETS_DIR = Path(__file__).parent / "assets"

app = FastAPI(
    title=APP_TITLE,
    description="Demonstration FastAPI app kept separate from the installable openetr component.",
    version="0.1.0",
)
app.add_middleware(EncryptedSessionMiddleware, secret_key=SESSION_SECRET)
app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")
if APP_ASSETS_DIR.exists():
    app.mount("/app-assets", StaticFiles(directory=str(APP_ASSETS_DIR)), name="app-assets")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def configured_home_relays() -> str:
    return normalize_relays(read_runtime_value("OPENETR_HOME_RELAYS", DEFAULT_RELAYS) or DEFAULT_RELAYS)


def bytes_to_nobj(data: bytes, prefix: str = NOBJ_PREFIX) -> str:
    digest = hashlib.sha256(data).hexdigest()
    as_int = [int(digest[i:i + 2], 16) for i in range(0, len(digest), 2)]
    converted = bech32.convertbits(as_int, 8, 5)
    return bech32.bech32_encode(prefix, converted)


def short_id(value: str | None, head: int = 12, tail: int = 8) -> str:
    if not value:
        return ""
    if len(value) <= head + tail + 1:
        return value
    return f"{value[:head]}...{value[-tail:]}"


templates.env.filters["short_id"] = short_id

def session_identity(request: Request) -> dict[str, Any]:
    root_nsec = request.session.get(SESSION_ROOT_NSEC_KEY)
    signer_nsec = request.session.get(SESSION_SIGNER_NSEC_KEY)
    bootstrap_relays = request.session.get(SESSION_BOOTSTRAP_RELAYS_KEY) or configured_home_relays()
    default_relays = request.session.get(SESSION_DEFAULT_RELAYS_KEY) or DEFAULT_RELAYS
    if not root_nsec and not signer_nsec:
        return {
            "logged_in": False,
            "nsec": None,
            "npub": None,
            "pubkey_hex": None,
            "root_nsec": None,
            "bootstrap_relays": bootstrap_relays,
            "default_relays": default_relays,
        }

    effective_nsec = signer_nsec or root_nsec
    if effective_nsec is None:
        return {
            "logged_in": False,
            "nsec": None,
            "npub": None,
            "pubkey_hex": None,
            "root_nsec": None,
            "bootstrap_relays": bootstrap_relays,
            "default_relays": default_relays,
        }

    try:
        keys = resolve_keys(effective_nsec)
    except click.ClickException:
        request.session.pop(SESSION_ROOT_NSEC_KEY, None)
        request.session.pop(SESSION_SIGNER_NSEC_KEY, None)
        return {
            "logged_in": False,
            "nsec": None,
            "npub": None,
            "pubkey_hex": None,
            "root_nsec": None,
            "bootstrap_relays": bootstrap_relays,
            "default_relays": default_relays,
        }

    return {
        "logged_in": True,
        "nsec": effective_nsec,
        "root_nsec": root_nsec,
        "signer_nsec": signer_nsec,
        "bootstrap_relays": bootstrap_relays,
        "default_relays": default_relays,
        "npub": keys.public_key_bech32(),
        "pubkey_hex": keys.public_key_hex(),
        "profile": request.session.get(SESSION_PROFILE_KEY),
    }


def get_session_identity(request: Request) -> dict[str, Any]:
    return session_identity(request)


@contextmanager
def session_bootstrap(identity: dict[str, Any]):
    root_nsec = identity.get("root_nsec") or identity.get("nsec")
    if not root_nsec:
        yield
        return
    home_relays = identity.get("bootstrap_relays") or configured_home_relays()
    token = set_runtime_bootstrap_overrides(root_nsec=root_nsec, home_relays=home_relays)
    try:
        yield
    finally:
        reset_runtime_bootstrap_overrides(token)


async def get_default_template_context(
    identity: dict[str, Any] = Depends(get_session_identity),
) -> dict[str, Any]:
    with session_bootstrap(identity):
        available_profiles = await get_available_profiles(identity)
        selected_profile_social = []
        if identity.get("logged_in") and identity.get("profile"):
            relays = str((await relay_profile_config(identity["profile"])).get("relays") or DEFAULT_RELAYS)
            selected_profile_social = compact_profile(
                await fetch_profile(
                    relays=relays,
                    pubkey_hex=identity["pubkey_hex"],
                    timeout=DEFAULT_QUERY_TIMEOUT,
                    ssl_disable_verify=False,
                )
            )
    return {
        "app_title": APP_TITLE,
        "site_url": SITE_URL,
        "git_commit": GIT_COMMIT,
        "default_relays": identity.get("default_relays") or DEFAULT_RELAYS,
        "bootstrap_relays": identity.get("bootstrap_relays") or configured_home_relays(),
        "identity": identity,
        "available_profiles": available_profiles,
        "selected_profile_social": selected_profile_social,
        "error_message": None,
        "success_message": None,
        "generated_nsec": None,
        "created_profile": None,
    }


def normalize_relays_form(relays: str = Form(DEFAULT_RELAYS)) -> str:
    raw = relays or DEFAULT_RELAYS
    return normalize_relays(raw)


@app.post("/settings")
async def update_settings(
    request: Request,
    bootstrap_relays: str = Form(""),
    default_relays: str = Form(""),
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    try:
        normalized_bootstrap_relays = await validate_relays(bootstrap_relays or configured_home_relays(), timeout=DEFAULT_QUERY_TIMEOUT)
        normalized_default_relays = await validate_relays(default_relays or DEFAULT_RELAYS, timeout=DEFAULT_QUERY_TIMEOUT)
    except click.ClickException as exc:
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "settings.html",
            template_context,
            status_code=400,
        )

    request.session[SESSION_BOOTSTRAP_RELAYS_KEY] = normalized_bootstrap_relays
    request.session[SESSION_DEFAULT_RELAYS_KEY] = normalized_default_relays

    template_context = await get_default_template_context(session_identity(request))
    template_context["success_message"] = "Updated relay settings for this session."
    return templates.TemplateResponse(
        request,
        "settings.html",
        template_context,
    )


@app.get("/settings")
async def settings_page(
    request: Request,
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    return templates.TemplateResponse(
        request,
        "settings.html",
        template_context,
    )


async def relay_profile_names() -> tuple[str, list[str]]:
    config = load_user_config()
    try:
        index = await _async_load_profiles_index(config)
    except click.ClickException:
        return DEFAULT_PROFILE_NAME, []
    if index is None:
        return DEFAULT_PROFILE_NAME, []
    return index.active_profile, sorted(index.profiles)


async def relay_profile_config(profile_name: str | None) -> dict[str, Any]:
    resolved = packaged_defaults()
    if not profile_name:
        return resolved
    config = load_user_config()
    try:
        record = await _async_load_profile_record(profile_name, config)
    except click.ClickException:
        return resolved
    if record is None:
        return resolved
    values = record.model_dump(exclude_none=True)
    values.pop("schema_version", None)
    values.pop("profile", None)
    resolved.update(values)
    return resolved


async def resolve_profile_signer_nsec(profile_name: str, config: dict | None = None) -> tuple[str | None, str]:
    resolved_config = config or load_user_config()
    try:
        remote_value = await _async_load_profile_secret(profile_name, resolved_config)
    except click.ClickException:
        return None, "relay unavailable"
    if remote_value:
        return remote_value, "relay"

    return None, "none"


async def get_available_profiles(identity: dict[str, Any]) -> list[dict[str, Any]]:
    if not identity.get("logged_in"):
        return []

    root_pubkey_hex = None
    root_nsec = identity.get("root_nsec")
    if root_nsec:
        try:
            root_pubkey_hex = resolve_keys(root_nsec).public_key_hex()
        except click.ClickException:
            root_pubkey_hex = None

    with session_bootstrap(identity):
        config = load_user_config()
        active_profile, profile_names = await relay_profile_names()
        profiles: list[dict[str, Any]] = []
        for profile_name in profile_names:
            signer_nsec, signer_source = await resolve_profile_signer_nsec(profile_name, config)
            signer_npub = None
            signer_matches_session = False
            if signer_nsec:
                try:
                    signer_keys = resolve_keys(signer_nsec)
                    signer_npub = signer_keys.public_key_bech32()
                    signer_matches_session = signer_keys.public_key_hex() == identity["pubkey_hex"]
                    if (
                        profile_name == DEFAULT_PROFILE_NAME
                        and root_pubkey_hex is not None
                        and signer_keys.public_key_hex() == root_pubkey_hex
                    ):
                        continue
                except click.ClickException:
                    signer_npub = None

            profiles.append(
                {
                    "name": profile_name,
                    "is_active": profile_name == active_profile,
                    "is_selected": profile_name == identity.get("profile"),
                    "signer_npub": signer_npub,
                    "signer_source": signer_source,
                    "signer_matches_session": signer_matches_session,
                    "can_select": signer_nsec is not None,
                    "usable_label": (
                        "matches current session signer"
                        if signer_matches_session
                        else ("signer unavailable in this environment" if signer_source == "relay unavailable" else "session override available")
                    ),
                }
            )

    return profiles


def profile_form_values(profile: dict[str, Any] | None) -> dict[str, str]:
    source = profile or {}
    return {field: str(source.get(field, "")) for field in PROFILE_FIELDS}

@app.get("/")
async def index(
    request: Request,
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    return templates.TemplateResponse(
        request,
        "index.html",
        template_context,
    )


@app.get("/login")
async def login_page(
    request: Request,
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    return templates.TemplateResponse(
        request,
        "login.html",
        template_context,
    )


@app.get("/overview")
async def overview_page(
    request: Request,
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    template_context["overview_image_url"] = "/app-assets/images/info-graphic.png"
    template_context["architecture_image_url"] = "/app-assets/images/relay-backed-architecture.png"
    return templates.TemplateResponse(
        request,
        "overview.html",
        template_context,
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/login")
async def login(
    request: Request,
    nsec: str = Form(...),
    bootstrap_relays: str = Form(""),
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    try:
        keys = resolve_keys(nsec.strip())
    except click.ClickException as exc:
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "login.html",
            template_context,
            status_code=400,
        )

    try:
        normalized_bootstrap_relays = await validate_relays(bootstrap_relays or configured_home_relays(), timeout=DEFAULT_QUERY_TIMEOUT)
    except click.ClickException as exc:
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "login.html",
            template_context,
            status_code=400,
        )

    normalized_nsec = keys.private_key_bech32()
    bootstrap_token = set_runtime_bootstrap_overrides(
        root_nsec=normalized_nsec,
        home_relays=normalized_bootstrap_relays,
    )
    try:
        profiles_index = await _async_load_profiles_index(load_user_config())
    except click.ClickException as exc:
        reset_runtime_bootstrap_overrides(bootstrap_token)
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "login.html",
            template_context,
            status_code=400,
        )
    finally:
        reset_runtime_bootstrap_overrides(bootstrap_token)

    if profiles_index is None:
        template_context["error_message"] = (
            "No relay-backed profile configuration was found for this nsec on the selected bootstrap relays. "
            "If this is meant to be a brand-new identity, use 'Generate New nsec'. "
            "If the identity already exists, specify the correct bootstrap relay(s)."
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            template_context,
            status_code=400,
        )

    request.session[SESSION_ROOT_NSEC_KEY] = normalized_nsec
    request.session[SESSION_SIGNER_NSEC_KEY] = normalized_nsec
    request.session[SESSION_BOOTSTRAP_RELAYS_KEY] = normalized_bootstrap_relays
    request.session.pop(SESSION_PROFILE_KEY, None)
    template_context = await get_default_template_context(session_identity(request))
    template_context["success_message"] = "Logged in with nsec session cookie."
    return templates.TemplateResponse(
        request,
        "index.html",
        template_context,
    )


@app.get("/logout")
async def logout_page(
    request: Request,
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    if not template_context["identity"].get("logged_in"):
        return templates.TemplateResponse(
            request,
            "login.html",
            template_context,
        )
    return templates.TemplateResponse(
        request,
        "logout_confirm.html",
        template_context,
    )


@app.post("/logout")
async def logout(
    request: Request,
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    request.session.pop(SESSION_ROOT_NSEC_KEY, None)
    request.session.pop(SESSION_SIGNER_NSEC_KEY, None)
    request.session.pop(SESSION_PROFILE_KEY, None)
    request.session.pop(SESSION_BOOTSTRAP_RELAYS_KEY, None)
    request.session.pop(SESSION_DEFAULT_RELAYS_KEY, None)
    template_context = await get_default_template_context(session_identity(request))
    template_context["success_message"] = "Logged out."
    return templates.TemplateResponse(
        request,
        "index.html",
        template_context,
    )


@app.post("/generate-login")
async def generate_login(
    request: Request,
    bootstrap_relays: str = Form(""),
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    try:
        normalized_bootstrap_relays = await validate_relays(bootstrap_relays or configured_home_relays(), timeout=DEFAULT_QUERY_TIMEOUT)
    except click.ClickException as exc:
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "login.html",
            template_context,
            status_code=400,
        )

    keys = Keys()
    generated_nsec = keys.private_key_bech32()
    bootstrap_token = set_runtime_bootstrap_overrides(
        root_nsec=generated_nsec,
        home_relays=normalized_bootstrap_relays,
    )
    try:
        await initialize_relay_backed_root(load_user_config())
    except click.ClickException as exc:
        reset_runtime_bootstrap_overrides(bootstrap_token)
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "login.html",
            template_context,
            status_code=400,
        )
    finally:
        reset_runtime_bootstrap_overrides(bootstrap_token)

    request.session[SESSION_ROOT_NSEC_KEY] = generated_nsec
    request.session[SESSION_SIGNER_NSEC_KEY] = generated_nsec
    request.session[SESSION_BOOTSTRAP_RELAYS_KEY] = normalized_bootstrap_relays
    request.session[SESSION_DEFAULT_RELAYS_KEY] = normalized_bootstrap_relays
    request.session.pop(SESSION_PROFILE_KEY, None)
    template_context = await get_default_template_context(session_identity(request))
    template_context["success_message"] = (
        "Generated a new nsec, initialized the new identity on the selected bootstrap relay(s), "
        "and started a session. You can use this same nsec and bootstrap relay set to log back in later."
    )
    template_context["generated_nsec"] = generated_nsec
    return templates.TemplateResponse(
        request,
        "login.html",
        template_context,
    )


@app.post("/profiles/create")
async def create_profile(
    request: Request,
    profile_name: str = Form(...),
    relays: str = Form(DEFAULT_RELAYS),
    signer_nsec: str = Form(""),
    allow_root_signer: str | None = Form(None),
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    identity = template_context["identity"]
    if not identity.get("logged_in"):
        template_context["error_message"] = "You must log in with an nsec before creating a profile."
        return templates.TemplateResponse(
            request,
            "index.html",
            template_context,
            status_code=400,
        )

    provided_signer = signer_nsec.strip()
    if provided_signer and identity.get("root_nsec"):
        try:
            provided_keys = resolve_keys(provided_signer)
            root_keys = resolve_keys(identity["root_nsec"])
        except click.ClickException as exc:
            template_context["error_message"] = str(exc)
            return templates.TemplateResponse(
                request,
                "index.html",
                template_context,
                status_code=400,
            )

        if provided_keys.public_key_hex() == root_keys.public_key_hex() and allow_root_signer != "true":
            template_context["error_message"] = (
                "Warning: the provided signer matches your root admin nsec. "
                "The root key should normally remain separate from profile signer keys. "
                "If you intentionally want to reuse it, confirm that choice in the profile form and submit again."
            )
            return templates.TemplateResponse(
                request,
                "index.html",
                template_context,
                status_code=400,
            )

    try:
        normalized_relays = await validate_relays(relays or DEFAULT_RELAYS, timeout=DEFAULT_QUERY_TIMEOUT)
        with session_bootstrap(identity):
            created_profile = await create_relay_backed_profile(
                profile_name=profile_name,
                relays=normalized_relays,
                config=load_user_config(),
                signer_nsec=signer_nsec,
                root_nsec=identity.get("root_nsec"),
            )
    except ValueError as exc:
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            template_context,
            status_code=400,
        )
    except click.ClickException as exc:
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            template_context,
            status_code=400,
        )

    request.session[SESSION_SIGNER_NSEC_KEY] = created_profile["signer_nsec"]
    request.session[SESSION_PROFILE_KEY] = created_profile["profile_name"]
    template_context = await get_default_template_context(session_identity(request))
    template_context["success_message"] = (
        f"Created relay-backed profile '{created_profile['profile_name']}' and selected it for this session."
    )
    template_context["created_profile"] = created_profile
    return templates.TemplateResponse(
        request,
        "index.html",
        template_context,
    )


@app.post("/profiles/use")
async def use_profile(
    request: Request,
    profile: str = Form(...),
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    with session_bootstrap(template_context["identity"]):
        config = load_user_config()
        signer_nsec, signer_source = await resolve_profile_signer_nsec(profile, config)
    if signer_nsec is None:
        template_context["error_message"] = f"No signer nsec is available for profile '{profile}'."
        return templates.TemplateResponse(
            request,
            "index.html",
            template_context,
            status_code=400,
        )

    try:
        keys = resolve_keys(signer_nsec)
    except click.ClickException as exc:
        template_context["error_message"] = f"Profile '{profile}' signer is invalid: {exc}"
        return templates.TemplateResponse(
            request,
            "index.html",
            template_context,
            status_code=400,
        )

    request.session[SESSION_SIGNER_NSEC_KEY] = keys.private_key_bech32()
    request.session[SESSION_PROFILE_KEY] = profile
    template_context = await get_default_template_context(session_identity(request))
    template_context["success_message"] = (
        f"Switched to profile '{profile}' using the {signer_source} signer secret."
    )
    return templates.TemplateResponse(
        request,
        "index.html",
        template_context,
    )


@app.get("/profiles/edit")
async def edit_profile_page(
    request: Request,
    identity: dict[str, Any] = Depends(get_session_identity),
):
    if not identity.get("logged_in"):
        template_context = await get_default_template_context(identity)
        template_context["error_message"] = "You must log in with an nsec before editing a profile."
        return templates.TemplateResponse(request, "index.html", template_context, status_code=400)

    if not identity.get("profile"):
        template_context = await get_default_template_context(identity)
        template_context["error_message"] = "Select a profile before editing its social profile."
        return templates.TemplateResponse(request, "index.html", template_context, status_code=400)

    with session_bootstrap(identity):
        relays = str((await relay_profile_config(identity["profile"])).get("relays") or DEFAULT_RELAYS)
        current_profile = await fetch_profile(
            relays=relays,
            pubkey_hex=identity["pubkey_hex"],
            timeout=DEFAULT_QUERY_TIMEOUT,
            ssl_disable_verify=False,
        ) or {}
    return templates.TemplateResponse(
        request,
        "profile_edit.html",
        {
            "app_title": APP_TITLE,
            "site_url": SITE_URL,
            "git_commit": GIT_COMMIT,
            "identity": identity,
            "available_profiles": await get_available_profiles(identity),
            "relays": relays,
            "profile_name": identity["profile"],
            "profile_fields": profile_form_values(current_profile),
            "current_profile": compact_profile(current_profile),
            "error_message": None,
            "success_message": None,
            "publish_result": None,
        },
    )


@app.post("/profiles/edit")
async def edit_profile_submit(
    request: Request,
    relays: str = Depends(normalize_relays_form),
    replace: str | None = Form(None),
    name: str = Form(""),
    display_name: str = Form(""),
    about: str = Form(""),
    address: str = Form(""),
    picture: str = Form(""),
    banner: str = Form(""),
    website: str = Form(""),
    nip05: str = Form(""),
    lud16: str = Form(""),
    lud06: str = Form(""),
    lei: str = Form(""),
    identity: dict[str, Any] = Depends(get_session_identity),
):
    if not identity.get("logged_in"):
        template_context = await get_default_template_context(identity)
        template_context["error_message"] = "You must log in with an nsec before editing a profile."
        return templates.TemplateResponse(request, "index.html", template_context, status_code=400)

    if not identity.get("profile"):
        template_context = await get_default_template_context(identity)
        template_context["error_message"] = "Select a profile before editing its social profile."
        return templates.TemplateResponse(request, "index.html", template_context, status_code=400)

    field_values = {
        "name": name,
        "display_name": display_name,
        "about": about,
        "address": address,
        "picture": picture,
        "banner": banner,
        "website": website,
        "nip05": nip05,
        "lud16": lud16,
        "lud06": lud06,
        "lei": lei,
    }

    try:
        validated_relays = await validate_relays(relays, timeout=DEFAULT_QUERY_TIMEOUT)
    except click.ClickException as exc:
        return templates.TemplateResponse(
            request,
            "profile_edit.html",
            {
                "app_title": APP_TITLE,
                "site_url": SITE_URL,
                "git_commit": GIT_COMMIT,
                "identity": identity,
                "available_profiles": await get_available_profiles(identity),
                "relays": relays,
                "profile_name": identity["profile"],
                "profile_fields": field_values,
                "current_profile": [],
                "error_message": str(exc),
                "success_message": None,
                "publish_result": None,
            },
            status_code=400,
        )

    try:
        with session_bootstrap(identity):
            publish_result = await publish_profile_updates(
                relays=validated_relays,
                signer_nsec=identity["nsec"],
                field_values=field_values,
                replace=replace == "true",
                publish_wait=2.0,
                query_timeout=DEFAULT_QUERY_TIMEOUT,
            )
    except click.ClickException as exc:
        current_profile = await fetch_profile(
            relays=validated_relays,
            pubkey_hex=identity["pubkey_hex"],
            timeout=DEFAULT_QUERY_TIMEOUT,
            ssl_disable_verify=False,
        ) or {}
        return templates.TemplateResponse(
            request,
            "profile_edit.html",
            {
                "app_title": APP_TITLE,
                "site_url": SITE_URL,
                "git_commit": GIT_COMMIT,
                "identity": identity,
                "available_profiles": await get_available_profiles(identity),
                "relays": validated_relays,
                "profile_name": identity["profile"],
                "profile_fields": field_values,
                "current_profile": compact_profile(current_profile),
                "error_message": str(exc),
                "success_message": None,
                "publish_result": None,
            },
            status_code=400,
        )

    latest_profile = publish_result["latest_content"] or publish_result["published_content"]
    return templates.TemplateResponse(
        request,
        "profile_edit.html",
        {
            "app_title": APP_TITLE,
            "site_url": SITE_URL,
            "identity": identity,
            "available_profiles": await get_available_profiles(identity),
            "relays": validated_relays,
            "profile_name": identity["profile"],
            "profile_fields": profile_form_values(latest_profile),
            "current_profile": compact_profile(latest_profile),
            "error_message": None,
            "success_message": "Published updated social profile.",
            "publish_result": publish_result,
        },
    )


@app.post("/api/nobj-from-upload")
async def nobj_from_upload(file: UploadFile = File(...)) -> dict[str, Any]:
    content = await file.read()
    digest = hashlib.sha256(content).hexdigest()
    return {
        "filename": file.filename,
        "size_bytes": len(content),
        "sha256": digest,
        "nobj": bytes_to_nobj(content),
    }


@app.post("/api/query-etr-from-upload")
async def query_etr_from_upload(
    request: Request,
    file: UploadFile = File(...),
    relays: str = Depends(normalize_relays_form),
    identity: dict[str, Any] = Depends(get_session_identity),
):
    try:
        validated_relays = await validate_relays(relays, timeout=DEFAULT_QUERY_TIMEOUT)
    except click.ClickException as exc:
        template_context = await get_default_template_context(identity)
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(request, "index.html", template_context, status_code=400)

    content = await file.read()
    digest = hashlib.sha256(content).hexdigest()
    query_context = await build_query_etr_result(
        digest=digest,
        relays=validated_relays,
        author_pubkey_hex=identity["pubkey_hex"],
    )
    return templates.TemplateResponse(
        request,
        "query_etr_result.html",
        {
            "app_title": APP_TITLE,
            "site_url": SITE_URL,
            "git_commit": GIT_COMMIT,
            "identity": identity,
            "available_profiles": await get_available_profiles(identity),
            "filename": file.filename,
            "size_bytes": len(content),
            "sha256": digest,
            "object_id": format_object_identifier(digest),
            "relays": validated_relays,
            "query": query_context,
        },
    )


@app.post("/api/issue-etr-from-upload")
async def issue_etr_from_upload(
    request: Request,
    file: UploadFile | None = File(None),
    relays: str = Depends(normalize_relays_form),
    comment: str = Form(""),
    file_digest: str = Form(""),
    file_name: str = Form(""),
    file_size: int = Form(0),
    identity: dict[str, Any] = Depends(get_session_identity),
):
    try:
        validated_relays = await validate_relays(relays, timeout=DEFAULT_QUERY_TIMEOUT)
    except click.ClickException as exc:
        template_context = await get_default_template_context(identity)
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(request, "index.html", template_context, status_code=400)

    if not identity.get("logged_in"):
        template_context = await get_default_template_context(identity)
        template_context["error_message"] = "You must log in with an nsec before issuing an ETR."
        return templates.TemplateResponse(request, "index.html", template_context, status_code=400)

    if not identity.get("profile"):
        template_context = await get_default_template_context(identity)
        template_context["error_message"] = "Select a profile before issuing an ETR."
        return templates.TemplateResponse(request, "index.html", template_context, status_code=400)

    confirmation = request.query_params.get("confirm") == "true"
    if file is not None:
        content = await file.read()
        digest = hashlib.sha256(content).hexdigest()
        filename = file.filename or "upload"
        size_bytes = len(content)
    else:
        if not confirmation or not file_digest or not file_name or file_size <= 0:
            template_context = await get_default_template_context(identity)
            template_context["error_message"] = "A file upload is required unless you are confirming a guarded issue flow."
            return templates.TemplateResponse(request, "index.html", template_context, status_code=400)
        digest = file_digest
        filename = file_name
        size_bytes = file_size

    guard = await evaluate_issue_etr_guard(
        relays=validated_relays,
        digest=digest,
        author_pubkey_hex=identity["pubkey_hex"],
        query_timeout=DEFAULT_QUERY_TIMEOUT,
        limit=DEFAULT_LIMIT,
    )
    if guard["should_warn"] and not confirmation:
        existing_issuer_profile = []
        if guard.get("latest_issuer_hex"):
            existing_issuer_profile = compact_profile(
                await fetch_profile(
                    relays=relays,
                    pubkey_hex=guard["latest_issuer_hex"],
                    timeout=DEFAULT_QUERY_TIMEOUT,
                    ssl_disable_verify=False,
                )
            )
        return templates.TemplateResponse(
            request,
            "issue_etr_confirm.html",
            {
                "app_title": APP_TITLE,
                "site_url": SITE_URL,
                "git_commit": GIT_COMMIT,
                "identity": identity,
                "available_profiles": await get_available_profiles(identity),
                "filename": filename,
                "size_bytes": size_bytes,
                "sha256": digest,
                "object_id": format_object_identifier(digest),
                "relays": validated_relays,
                "comment": comment.strip(),
                "guard": guard,
                "existing_issuer_profile": existing_issuer_profile,
            },
        )

    issue_result = await publish_issue_etr(
        filename=filename,
        size_bytes=size_bytes,
        digest=digest,
        relays=validated_relays,
        signer_nsec=identity["nsec"],
        comment=comment.strip() or None,
    )
    query_context = await build_query_etr_result(
        digest=issue_result["sha256"],
        relays=validated_relays,
        author_pubkey_hex=identity["pubkey_hex"],
    )
    return templates.TemplateResponse(
        request,
        "query_etr_result.html",
        {
            "app_title": APP_TITLE,
            "site_url": SITE_URL,
            "git_commit": GIT_COMMIT,
            "identity": identity,
            "available_profiles": await get_available_profiles(identity),
            "filename": issue_result["filename"],
            "size_bytes": issue_result["size_bytes"],
            "sha256": issue_result["sha256"],
            "object_id": issue_result["object_id"],
            "relays": validated_relays,
            "query": query_context,
            "issue_result": issue_result,
        },
    )
