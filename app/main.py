import hashlib
import os
from pathlib import Path
from typing import Any

import bech32
import click
from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from openetr.config import ACTIVE_PROFILE_KEY, CONFIG_AS_USER_KEY, DEFAULT_LIMIT, DEFAULT_PROFILE_NAME, DEFAULT_QUERY_TIMEOUT, DEFAULT_RELAYS, PROFILES_KEY, _async_load_profile_secret, load_user_config
from openetr.guards import evaluate_issue_etr_guard
from openetr.helpers import format_object_identifier, format_pubkey, resolve_keys
from openetr.services.issue_etr import publish_issue_etr
from openetr.services.profile_publish import PROFILE_FIELDS, publish_profile_updates
from openetr.services.query_etr import build_query_etr_result, compact_profile, fetch_profile


APP_TITLE = "OpenETR Demo App"
CONTROL_TRANSFER_KIND = 31416
NOBJ_PREFIX = "nobj"
SESSION_NSEC_KEY = "openetr_nsec"
SESSION_PROFILE_KEY = "openetr_profile"
SESSION_SECRET = os.environ.get("OPENETR_APP_SESSION_SECRET", "openetr-demo-session-secret")
TEMPLATE_DIR = Path(__file__).parent / "templates"

app = FastAPI(
    title=APP_TITLE,
    description="Demonstration FastAPI app kept separate from the installable openetr component.",
    version="0.1.0",
)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def bytes_to_nobj(data: bytes, prefix: str = NOBJ_PREFIX) -> str:
    digest = hashlib.sha256(data).hexdigest()
    as_int = [int(digest[i:i + 2], 16) for i in range(0, len(digest), 2)]
    converted = bech32.convertbits(as_int, 8, 5)
    return bech32.bech32_encode(prefix, converted)

def session_identity(request: Request) -> dict[str, Any]:
    nsec = request.session.get(SESSION_NSEC_KEY)
    if not nsec:
        return {"logged_in": False, "nsec": None, "npub": None, "pubkey_hex": None}

    try:
        keys = resolve_keys(nsec)
    except click.ClickException:
        request.session.pop(SESSION_NSEC_KEY, None)
        return {"logged_in": False, "nsec": None, "npub": None, "pubkey_hex": None}

    return {
        "logged_in": True,
        "nsec": nsec,
        "npub": keys.public_key_bech32(),
        "pubkey_hex": keys.public_key_hex(),
        "profile": request.session.get(SESSION_PROFILE_KEY),
    }


def get_session_identity(request: Request) -> dict[str, Any]:
    return session_identity(request)


async def get_default_template_context(
    identity: dict[str, Any] = Depends(get_session_identity),
) -> dict[str, Any]:
    return {
        "app_title": APP_TITLE,
        "default_relays": DEFAULT_RELAYS,
        "identity": identity,
        "available_profiles": await get_available_profiles(identity),
        "error_message": None,
        "success_message": None,
    }


def normalize_relays_form(relays: str = Form(DEFAULT_RELAYS)) -> str:
    normalized = ",".join(relay.strip() for relay in relays.split(",") if relay.strip())
    return normalized or DEFAULT_RELAYS


def local_profile_relays(profile_name: str | None) -> str:
    if not profile_name:
        return DEFAULT_RELAYS
    config = load_user_config()
    return str(config.get(PROFILES_KEY, {}).get(profile_name, {}).get("relays") or DEFAULT_RELAYS)


async def resolve_profile_signer_nsec(profile_name: str, config: dict | None = None) -> tuple[str | None, str]:
    resolved_config = config or load_user_config()
    local_value = resolved_config.get(PROFILES_KEY, {}).get(profile_name, {}).get(CONFIG_AS_USER_KEY)
    if local_value:
        return local_value, "local"

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

    config = load_user_config()
    active_profile = config.get(ACTIVE_PROFILE_KEY, DEFAULT_PROFILE_NAME)
    profile_names = sorted(config.get(PROFILES_KEY, {}).keys())
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


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/login")
async def login(
    request: Request,
    nsec: str = Form(...),
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    try:
        keys = resolve_keys(nsec.strip())
    except click.ClickException as exc:
        template_context["error_message"] = str(exc)
        return templates.TemplateResponse(
            request,
            "index.html",
            template_context,
            status_code=400,
        )

    normalized_nsec = keys.private_key_bech32()
    request.session[SESSION_NSEC_KEY] = normalized_nsec
    request.session.pop(SESSION_PROFILE_KEY, None)
    template_context = await get_default_template_context(session_identity(request))
    template_context["success_message"] = "Logged in with nsec session cookie."
    return templates.TemplateResponse(
        request,
        "index.html",
        template_context,
    )


@app.post("/logout")
async def logout(
    request: Request,
    template_context: dict[str, Any] = Depends(get_default_template_context),
):
    request.session.pop(SESSION_NSEC_KEY, None)
    request.session.pop(SESSION_PROFILE_KEY, None)
    template_context = await get_default_template_context(session_identity(request))
    template_context["success_message"] = "Logged out."
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

    request.session[SESSION_NSEC_KEY] = keys.private_key_bech32()
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

    relays = local_profile_relays(identity["profile"])
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
        publish_result = await publish_profile_updates(
            relays=relays,
            signer_nsec=identity["nsec"],
            field_values=field_values,
            replace=replace == "true",
            publish_wait=2.0,
            query_timeout=DEFAULT_QUERY_TIMEOUT,
        )
    except click.ClickException as exc:
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
                "identity": identity,
                "available_profiles": await get_available_profiles(identity),
                "relays": relays,
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
            "identity": identity,
            "available_profiles": await get_available_profiles(identity),
            "relays": relays,
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
    content = await file.read()
    digest = hashlib.sha256(content).hexdigest()
    query_context = await build_query_etr_result(
        digest=digest,
        relays=relays,
        author_pubkey_hex=identity["pubkey_hex"],
    )
    return templates.TemplateResponse(
        request,
        "query_etr_result.html",
        {
            "app_title": APP_TITLE,
            "identity": identity,
            "available_profiles": await get_available_profiles(identity),
            "filename": file.filename,
            "size_bytes": len(content),
            "sha256": digest,
            "object_id": format_object_identifier(digest),
            "relays": relays,
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
        relays=relays,
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
                "identity": identity,
                "available_profiles": await get_available_profiles(identity),
                "filename": filename,
                "size_bytes": size_bytes,
                "sha256": digest,
                "object_id": format_object_identifier(digest),
                "relays": relays,
                "comment": comment.strip(),
                "guard": guard,
                "existing_issuer_profile": existing_issuer_profile,
            },
        )

    issue_result = await publish_issue_etr(
        filename=filename,
        size_bytes=size_bytes,
        digest=digest,
        relays=relays,
        signer_nsec=identity["nsec"],
        comment=comment.strip() or None,
    )
    query_context = await build_query_etr_result(
        digest=issue_result["sha256"],
        relays=relays,
        author_pubkey_hex=identity["pubkey_hex"],
    )
    return templates.TemplateResponse(
        request,
        "query_etr_result.html",
        {
            "app_title": APP_TITLE,
            "identity": identity,
            "available_profiles": await get_available_profiles(identity),
            "filename": issue_result["filename"],
            "size_bytes": issue_result["size_bytes"],
            "sha256": issue_result["sha256"],
            "object_id": issue_result["object_id"],
            "relays": relays,
            "query": query_context,
            "issue_result": issue_result,
        },
    )
