"""cmdcheck FastAPI application."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .classifier import classify
from . import mitre as mitre_catalog
from . import stripe_billing
from .db import (
    accept_workspace_invite, add_threat_group_member, close_pool,
    consume_verification_token, count_users, create_api_key, create_bug_report,
    create_threat_group, create_user, create_workspace, create_workspace_invite,
    delete_analysis, delete_threat_group, delete_workspace, fetch_admin_stats,
    fetch_analysis, fetch_api_keys_for_user, fetch_bug_reports, fetch_invite,
    fetch_recent, fetch_subscription_status, fetch_threat_groups,
    fetch_user_by_api_key, fetch_user_by_email, fetch_workspace,
    fetch_workspaces_for_user, get_banner, remove_threat_group_member,
    remove_workspace_member, revoke_api_key, run_migrations, search_analyses,
    set_setting, set_stripe_customer_id, update_bug_report,
    update_subscription_by_customer, upsert_analysis,
)
from .decoder import decode_layers
from .gtfobins import load_catalog as load_gtfobins, match as gtfobins_match
from .lolbas import load_catalog as load_lolbas, match as lolbas_match
from .loldrivers import load_catalog as load_loldrivers, match as loldrivers_match
from .parent_score import score_parent
from .parser import extract_binaries, parse_command
from .redactor import redact
from .slug import make_slug
from .ip_extractor import extract_ips
from . import threat_intel as threat_intel_mod
from .url_extractor import extract_urls_from_analysis
from .users import hash_password, is_admin_email, verify_password
from .virustotal import lookup_urls

_ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")

# Static descriptions for well-known Windows system binaries not covered by the LOLBAS catalog.
# Keys are lowercase with .exe suffix.  LOLBAS/GTFOBins always take precedence; these fire only
# when no catalog entry is found.
# Known offensive security tools — not in LOLBAS (not legitimate Windows binaries)
# but commonly seen in incident response and deserve explicit recognition.
_THREAT_TOOL_INFO: dict[str, dict[str, Any]] = {
    "mimikatz.exe": {
        "description": "Open-source credential theft toolkit by Benjamin Delpy",
        "abuse_note": "Extracts plaintext passwords, hashes, PINs, and Kerberos tickets from LSASS memory. Used in almost every major ransomware and APT campaign.",
        "techniques": ["T1003.001", "T1550.002", "T1558"],
    },
    "procdump.exe": {
        "description": "Sysinternals process dump utility (Microsoft-signed)",
        "abuse_note": "Abused to dump LSASS memory to disk for offline hash extraction. Microsoft-signed, so often bypasses application whitelisting.",
        "techniques": ["T1003.001"],
    },
    "rubeus.exe": {
        "description": "Kerberos attack toolkit (.NET) by SpecterOps",
        "abuse_note": "Performs Kerberoasting, AS-REP roasting, pass-the-ticket, and Golden/Silver ticket attacks against Active Directory.",
        "techniques": ["T1558.003", "T1558.004", "T1550.003"],
    },
    "sharphound.exe": {
        "description": "BloodHound AD enumeration collector (.NET) by SpecterOps",
        "abuse_note": "Enumerates Active Directory relationships (ACLs, group memberships, sessions) and exports graph data used to identify attack paths to Domain Admin.",
        "techniques": ["T1069", "T1087", "T1482"],
    },
    "bloodhound.exe": {
        "description": "Active Directory attack path analysis tool",
        "abuse_note": "Visualises Active Directory attack paths. The collector (SharpHound) gathers data that feeds this tool to identify privilege escalation routes.",
        "techniques": ["T1069", "T1087"],
    },
    "psexec.exe": {
        "description": "Sysinternals remote execution utility (Microsoft-signed)",
        "abuse_note": "Executes processes on remote systems over SMB. Heavily abused for lateral movement and deploying ransomware. Microsoft-signed.",
        "techniques": ["T1570", "T1021.002"],
    },
    "wce.exe": {
        "description": "Windows Credentials Editor — credential extraction tool",
        "abuse_note": "Dumps NTLM hashes and plaintext credentials from LSASS. Predates Mimikatz; still seen in older incident investigations.",
        "techniques": ["T1003.001"],
    },
    "pwdump.exe": {
        "description": "Password hash dumper",
        "abuse_note": "Extracts NTLM password hashes from the SAM database for offline cracking or pass-the-hash attacks.",
        "techniques": ["T1003.002"],
    },
    "nc.exe": {
        "description": "Netcat — network utility used as a reverse shell",
        "abuse_note": "Establishes outbound connections that give attackers an interactive shell. Commonly dropped as part of post-exploitation toolkits.",
        "techniques": ["T1095", "T1059.003"],
    },
    "ncat.exe": {
        "description": "Nmap's Netcat implementation",
        "abuse_note": "Same capabilities as nc.exe. Often used instead to evade basic filename detections on nc.exe.",
        "techniques": ["T1095"],
    },
    "cobaltstrike.exe": {
        "description": "Cobalt Strike commercial C2 framework",
        "abuse_note": "The Beacon implant from Cobalt Strike is the most common C2 payload seen in ransomware and espionage operations. Legitimate red-team tool widely abused by threat actors.",
        "techniques": ["T1071", "T1055", "T1027"],
    },
}

_SYSTEM_BINARY_INFO: dict[str, dict[str, Any]] = {
    "vssadmin.exe": {
        "description": "Volume Shadow Copy Service admin tool (Windows built-in)",
        "abuse_note": "Ransomware runs 'vssadmin delete shadows /all' before encryption to destroy backup copies and prevent file recovery.",
        "techniques": ["T1490"],
    },
    "bcdedit.exe": {
        "description": "Boot Configuration Data store editor (Windows built-in)",
        "abuse_note": "Ransomware sets 'recoveryenabled No' and 'bootstatuspolicy ignoreallfailures' to prevent Windows Recovery Environment from launching after encryption.",
        "techniques": ["T1490"],
    },
    "net.exe": {
        "description": "Windows network, user, and service management command (Windows built-in)",
        "abuse_note": "Used by attackers for local user/group enumeration, account creation, service manipulation, and network share discovery.",
        "techniques": ["T1069.001", "T1087.001", "T1543.003"],
    },
    "net1.exe": {
        "description": "Functional alias for net.exe (Windows built-in)",
        "abuse_note": "Attackers invoke net1 to bypass detections that only monitor 'net.exe'. Identical capabilities.",
        "techniques": ["T1069.001", "T1087.001"],
    },
    "sc.exe": {
        "description": "Service Control Manager interface (Windows built-in)",
        "abuse_note": "Used to create or modify Windows services for persistence, disable security products, or run payloads with SYSTEM privileges.",
        "techniques": ["T1543.003", "T1562.001"],
    },
    "schtasks.exe": {
        "description": "Task Scheduler management tool (Windows built-in)",
        "abuse_note": "Used to create scheduled tasks that execute malware at startup, logon, or on a schedule — a primary persistence mechanism.",
        "techniques": ["T1053.005"],
    },
    "wmic.exe": {
        "description": "WMI command-line interface (Windows built-in, deprecated in Win11)",
        "abuse_note": "Abused for remote process creation, lateral movement, fileless persistence via WMI event subscriptions, and system reconnaissance.",
        "techniques": ["T1047", "T1021.006"],
    },
    "taskkill.exe": {
        "description": "Windows process termination tool (Windows built-in)",
        "abuse_note": "Ransomware uses taskkill to stop security products, databases, and backup agents before encryption to ensure target files are unlocked.",
        "techniques": ["T1562.001"],
    },
    "whoami.exe": {
        "description": "Prints current user and privilege context (Windows built-in)",
        "abuse_note": "Standard post-exploitation recon step to identify current account, domain membership, and privilege level.",
        "techniques": ["T1033"],
    },
    "systeminfo.exe": {
        "description": "Displays detailed OS and hardware configuration (Windows built-in)",
        "abuse_note": "Used in the recon phase to identify OS version, patch level, domain, and hardware — informs privilege escalation and lateral movement.",
        "techniques": ["T1082"],
    },
    "ipconfig.exe": {
        "description": "Displays and manages IP network configuration (Windows built-in)",
        "abuse_note": "Used for network discovery — identifies subnets, DNS servers, and gateways to map the internal network.",
        "techniques": ["T1016"],
    },
    "nltest.exe": {
        "description": "Netlogon diagnostic tool for domain trust enumeration (Windows built-in)",
        "abuse_note": "Used by attackers to enumerate domain trusts, domain controllers, and forest structure — common in ransomware pre-encryption AD recon.",
        "techniques": ["T1482", "T1016"],
    },
    "icacls.exe": {
        "description": "ACL (Access Control List) management tool (Windows built-in)",
        "abuse_note": "Used to weaken file/folder permissions for persistence or to grant access to planted backdoors.",
        "techniques": ["T1222.001"],
    },
    "attrib.exe": {
        "description": "File attribute management tool (Windows built-in)",
        "abuse_note": "Attackers use '+h' (hidden) and '+s' (system) flags to hide malware files and directories from casual inspection.",
        "techniques": ["T1564.001"],
    },
    "reg.exe": {
        "description": "Windows Registry command-line editor (Windows built-in)",
        "abuse_note": "Used for persistence (Run keys), credential theft (SAM/SYSTEM hive export), and disabling security features via registry modification.",
        "techniques": ["T1112", "T1547.001"],
    },
}


def _build_binaries_in_command(
    binaries: list[str],
    lolbas_by_name: dict[str, dict[str, Any]],
    gtfobins_by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for name in binaries:
        name_key = name.lower()
        name_noext = name_key.removesuffix(".exe")

        lb = lolbas_by_name.get(name_key) or lolbas_by_name.get(name_noext)
        if lb:
            result.append({
                "name": name,
                "source": "lolbas",
                "description": lb.get("description"),
                "abuse_note": None,
                "functions": lb.get("functions") or [],
                "techniques": lb.get("technique_details") or [],
                "url": lb.get("url"),
            })
            continue

        gt = gtfobins_by_name.get(name_key) or gtfobins_by_name.get(name_noext)
        if gt:
            result.append({
                "name": name,
                "source": "gtfobins",
                "description": gt.get("description"),
                "abuse_note": None,
                "functions": gt.get("functions") or [],
                "techniques": [],
                "url": gt.get("url"),
            })
            continue

        sys_info = _SYSTEM_BINARY_INFO.get(name_key) or _SYSTEM_BINARY_INFO.get(name_noext + ".exe")
        if sys_info:
            result.append({
                "name": name,
                "source": "system",
                "description": sys_info.get("description"),
                "abuse_note": sys_info.get("abuse_note"),
                "functions": [],
                "techniques": mitre_catalog.enrich(sys_info.get("techniques", [])),
                "url": None,
            })
            continue

        threat_tool = _THREAT_TOOL_INFO.get(name_key) or _THREAT_TOOL_INFO.get(name_noext + ".exe")
        if threat_tool:
            result.append({
                "name": name,
                "source": "threat_tool",
                "description": threat_tool.get("description"),
                "abuse_note": threat_tool.get("abuse_note"),
                "functions": [],
                "techniques": mitre_catalog.enrich(threat_tool.get("techniques", [])),
                "url": None,
            })
            continue

        result.append({
            "name": name,
            "source": "unknown",
            "description": None,
            "abuse_note": None,
            "functions": [],
            "techniques": [],
            "url": None,
        })

    return result

# Rate limits — override via env vars for testing (e.g. RATE_ANALYZE=500/minute)
_RATE_ANALYZE = os.getenv("RATE_ANALYZE", "60/minute")
_RATE_REGISTER = os.getenv("RATE_REGISTER", "20/hour")
_RATE_FEEDBACK = os.getenv("RATE_FEEDBACK", "20/hour")
_RATE_RESEND = os.getenv("RATE_RESEND", "10/hour")

limiter = Limiter(key_func=get_remote_address)

# ── Per-tier rate limiting ────────────────────────────────────────────────────
_TIER_RPM: dict[str, int] = {
    "individual": 120,
    "teams": 300,
    "organization": 600,
    "free": 60,
}
_rate_windows: dict[str, deque] = defaultdict(deque)


def _check_tier_limit(key: str, tier: str) -> bool:
    """Sliding-window rate check. Returns True if request is allowed."""
    rpm = _TIER_RPM.get(tier, 60)
    now = time.monotonic()
    window = _rate_windows[key]
    cutoff = now - 60.0
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= rpm:
        return False
    window.append(now)
    return True


# ── API key authentication ────────────────────────────────────────────────────

async def _resolve_api_key_user(request: Request) -> dict[str, Any] | None:
    """Return the user dict if a valid API key is present in the request headers."""
    raw = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not raw or not raw.startswith("cckey_"):
        return None
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    return await fetch_user_by_api_key(key_hash)


def _require_admin(x_admin_secret: str | None = Header(default=None)) -> None:
    if not _ADMIN_SECRET or x_admin_secret != _ADMIN_SECRET:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "detail": "Admin access required"})


@asynccontextmanager
async def lifespan(app: FastAPI):
    mitre_catalog.load_catalog()
    load_lolbas()
    load_gtfobins()
    load_loldrivers()
    _stripe_key = os.getenv("STRIPE_SECRET_KEY", "")
    if _stripe_key:
        stripe_billing.init(_stripe_key)
    await run_migrations()
    yield
    await close_pool()


app = FastAPI(title="cmdcheck", version="0.1.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
_CORS_WILDCARD = "*" in _ALLOWED_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _CORS_WILDCARD else _ALLOWED_ORIGINS,
    # Always allow LAN addresses so dev testing from phones/tablets works
    allow_origin_regex=r"https?://(localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?",
    allow_methods=["GET", "POST", "DELETE", "PATCH", "PUT"],
    allow_headers=["Content-Type", "Authorization"],
)


class AnalyzeRequest(BaseModel):
    command: str = Field(min_length=1, max_length=65536)
    parent_process: str | None = None
    is_private: bool = False
    user_email: str | None = None
    skip_redaction: bool = False
    workspace_id: str | None = None


class ErrorResponse(BaseModel):
    code: str
    detail: str


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
@limiter.limit(_RATE_ANALYZE)
async def analyze(request: Request, body: AnalyzeRequest) -> dict[str, Any]:
    command = body.command
    parent_process = body.parent_process
    is_private = body.is_private
    user_id: str | None = None

    # API key auth — overrides user_email if a valid key is provided
    api_key_user = await _resolve_api_key_user(request)
    if api_key_user:
        body_email = api_key_user["email"]
        is_private = True
        user_id = str(api_key_user["id"])
        tier = api_key_user.get("subscription_tier", "free")
        if not _check_tier_limit(f"apikey:{body_email}", tier):
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "detail": f"Rate limit of {_TIER_RPM.get(tier, 60)} req/min exceeded."},
            )
    elif body.user_email:
        # Per-tier rate limit for authenticated web users
        web_user = await fetch_user_by_email(body.user_email)
        if web_user:
            tier = (web_user or {}).get("subscription_tier", "free")
            if not _check_tier_limit(f"email:{body.user_email}", tier):
                raise HTTPException(
                    status_code=429,
                    detail={"code": "rate_limited", "detail": f"Rate limit of {_TIER_RPM.get(tier, 60)} req/min exceeded."},
                )

    if is_private and not api_key_user:
        if not body.user_email:
            raise HTTPException(
                status_code=401,
                detail={"code": "unauthenticated", "detail": "Sign in to submit privately."},
            )
        priv_user = await fetch_user_by_email(body.user_email)
        if not priv_user:
            raise HTTPException(
                status_code=401,
                detail={"code": "unauthenticated", "detail": "Account not found."},
            )
        if priv_user.get("subscription_status", "free") not in ("active", "trialing"):
            raise HTTPException(
                status_code=402,
                detail={"code": "subscription_required", "detail": "Private submissions require an active subscription."},
            )
        user_id = str(priv_user["id"])

    # Workspace tagging — validate membership before accepting workspace_id
    workspace_id: str | None = body.workspace_id
    if workspace_id and user_id:
        ws = await fetch_workspace(workspace_id, user_id)
        if not ws:
            raise HTTPException(
                status_code=403,
                detail={"code": "forbidden", "detail": "You are not a member of that workspace."},
            )
        is_private = True  # workspace analyses are always private
    elif workspace_id:
        workspace_id = None  # ignore workspace_id if user is not identified

    slug = make_slug(command)

    existing = await fetch_analysis(slug)
    if existing is not None and not existing.get("deleted"):
        if parent_process and not existing.get("parent_verdict"):
            verdict = score_parent(parent_process, command)
            if verdict:
                existing["parent_verdict"] = asdict(verdict)
        return existing
    # If deleted (or None), fall through to re-analyze and restore the row

    ast, parse_error = parse_command(command)
    layers = decode_layers(command)

    # Collect all unique binaries from command + decoded layers (single pass)
    all_binaries: list[str] = []
    seen_all_binaries: set[str] = set()
    for source in [command, *(layer["value"] for layer in layers)]:
        for binary in extract_binaries(source):
            if binary.lower() not in seen_all_binaries:
                seen_all_binaries.add(binary.lower())
                all_binaries.append(binary)

    # LOLBAS matching
    lolbas_matches: list[dict[str, Any]] = []
    lolbas_by_name: dict[str, dict[str, Any]] = {}
    seen_lolbas: set[str] = set()
    for binary in all_binaries:
        hit = lolbas_match(binary)
        if hit is not None and hit["name"] not in seen_lolbas:
            seen_lolbas.add(hit["name"])
            lolbas_matches.append(hit)
            lolbas_by_name[hit["name"].lower()] = hit

    # GTFOBins matching
    gtfobins_matches: list[dict[str, Any]] = []
    gtfobins_by_name: dict[str, dict[str, Any]] = {}
    seen_gtfobins: set[str] = set()
    for binary in all_binaries:
        hit = gtfobins_match(binary)
        if hit is not None and hit["name"] not in seen_gtfobins:
            seen_gtfobins.add(hit["name"])
            gtfobins_matches.append(hit)
            gtfobins_by_name[hit["name"].lower()] = hit

    # LOLDrivers matching — vulnerable kernel drivers (BYOVD)
    loldrivers: dict[str, Any] | None = None
    for source in [command, *(layer["value"] for layer in layers)]:
        hit = loldrivers_match(source)
        if hit is not None:
            loldrivers = hit
            break

    binaries_in_command = _build_binaries_in_command(all_binaries, lolbas_by_name, gtfobins_by_name)

    threat_classes = classify(command, layers)
    parent_verdict = score_parent(parent_process, command) if parent_process else None
    # Redaction opt-out — subscribers only; silently redact if not subscribed
    skip_redact = body.skip_redaction and user_id is not None
    if skip_redact:
        sub = await fetch_subscription_status(body.user_email or "")
        skip_redact = sub.get("status") in ("active", "trialing")

    stored_command, was_redacted = ("", False) if skip_redact else redact(command)
    if skip_redact:
        stored_command = command
        was_redacted = False

    # URL + IP extraction then multi-source threat intel enrichment
    extracted_urls = extract_urls_from_analysis(command, layers)
    extracted_ips = extract_ips(command, layers)
    vt_results = await lookup_urls(extracted_urls)
    threat_intel_results = await threat_intel_mod.enrich(extracted_urls, extracted_ips, vt_results)

    result: dict[str, Any] = {
        "slug": slug,
        "parsed": ast,
        "parsed_error": parse_error,
        "decoded_layers": layers,
        "lolbas_match": lolbas_matches[0] if lolbas_matches else None,
        "lolbas_matches": lolbas_matches,
        "gtfobins_match": gtfobins_matches[0] if gtfobins_matches else None,
        "gtfobins_matches": gtfobins_matches,
        "loldrivers_match": loldrivers,
        "threat_classes": [asdict(tc) for tc in threat_classes],
        "parent_verdict": asdict(parent_verdict) if parent_verdict else None,
        "redacted": was_redacted,
        "extracted_urls": extracted_urls,
        "extracted_ips": extracted_ips,
        "vt_results": vt_results,
        "vt_configured": bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "threat_intel": threat_intel_results,
        "threat_intel_configured": {
            "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
            "otx": bool(os.getenv("OTX_API_KEY")),
        },
        "binaries_in_command": binaries_in_command,
        "is_private": is_private,
    }

    await upsert_analysis(slug, stored_command, result, is_private=is_private, user_id=user_id, workspace_id=workspace_id)
    return result


@app.get("/recent")
async def recent_analyses(limit: int = 50) -> list[dict[str, Any]]:
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail={"code": "invalid_limit", "detail": "limit must be 1-100"})
    return await fetch_recent(limit)


@app.get("/search")
async def search(q: str, limit: int = 20) -> list[dict[str, Any]]:
    q = q.strip()
    if len(q) < 2:
        raise HTTPException(status_code=400, detail={"code": "query_too_short", "detail": "Query must be at least 2 characters"})
    if limit < 1 or limit > 50:
        raise HTTPException(status_code=400, detail={"code": "invalid_limit", "detail": "limit must be 1–50"})
    return await search_analyses(q, limit)


@app.get("/c/{slug}")
async def get_analysis(slug: str) -> dict[str, Any]:
    if len(slug) != 12 or not slug.isalnum():
        raise HTTPException(status_code=400, detail={"code": "invalid_slug", "detail": "Bad slug format"})
    row = await fetch_analysis(slug)
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "detail": "Analysis not found"})
    return row


@app.delete("/c/{slug}")
async def delete_analysis_endpoint(slug: str) -> dict[str, Any]:
    if len(slug) != 12 or not slug.isalnum():
        raise HTTPException(status_code=400, detail={"code": "invalid_slug", "detail": "Bad slug format"})
    row = await fetch_analysis(slug)
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "detail": "Analysis not found"})
    if row.get("deleted"):
        raise HTTPException(status_code=410, detail={"code": "already_deleted", "detail": "Already deleted"})
    success = await delete_analysis(slug)
    if not success:
        raise HTTPException(status_code=404, detail={"code": "not_found", "detail": "Analysis not found"})
    return {"slug": slug, "deleted": True}


# ── Auth ────────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class VerifyRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/register")
@limiter.limit(_RATE_REGISTER)
async def register(request: Request, body: RegisterRequest) -> dict[str, Any]:
    existing = await fetch_user_by_email(body.email)
    if existing:
        raise HTTPException(status_code=409, detail={"code": "email_taken", "detail": "Email already registered"})
    role = "admin" if is_admin_email(body.email) else "user"
    # First ever user also becomes admin
    if role == "user" and await count_users() == 0:
        role = "admin"
    user = await create_user(body.email, hash_password(body.password), role)
    return {"id": str(user["id"]), "email": user["email"], "role": user["role"], "verified": True}


@app.post("/auth/verify")
@limiter.limit(_RATE_ANALYZE)
async def verify_credentials(request: Request, body: VerifyRequest) -> dict[str, Any]:
    user = await fetch_user_by_email(body.email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail={"code": "invalid_credentials", "detail": "Invalid email or password"})
    if not user.get("verified", True):
        raise HTTPException(status_code=403, detail={"code": "email_not_verified", "detail": "Please verify your email before signing in."})
    return {"id": str(user["id"]), "email": user["email"], "role": user["role"]}


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/verify-email")
async def verify_email(body: VerifyEmailRequest) -> dict[str, Any]:
    user_id = await consume_verification_token(body.token)
    if user_id is None:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_token", "detail": "Token is invalid, expired, or already used."},
        )
    return {"ok": True, "user_id": user_id}


@app.post("/auth/resend-verification")
@limiter.limit(_RATE_RESEND)
async def resend_verification(request: Request, body: ResendVerificationRequest) -> dict[str, Any]:
    user = await fetch_user_by_email(body.email)
    # Validate credentials before resending to prevent enumeration
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail={"code": "invalid_credentials", "detail": "Invalid email or password"})
    if user.get("verified", True):
        return {"ok": True, "already_verified": True}
    token = await create_verification_token(str(user["id"]))
    await send_verification_email(body.email, token)
    return {"ok": True, "already_verified": False}


# ── Public settings ─────────────────────────────────────────────────────────────

@app.get("/settings/banner")
async def get_banner_endpoint() -> dict[str, Any]:
    return await get_banner()


# ── Bug reports ─────────────────────────────────────────────────────────────────

class BugReportRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=5000)
    severity: str = Field(default="medium", pattern="^(low|medium|high)$")
    contact_email: str | None = None


@app.post("/feedback")
@limiter.limit(_RATE_FEEDBACK)
async def submit_bug_report(request: Request, body: BugReportRequest) -> dict[str, Any]:
    report = await create_bug_report(body.title, body.description, body.severity, body.contact_email)
    return {"id": str(report["id"]), "status": report["status"]}


# ── Admin ───────────────────────────────────────────────────────────────────────

class BannerSettings(BaseModel):
    enabled: bool
    message: str = Field(max_length=500)
    type: str = Field(default="info", pattern="^(info|warning|danger)$")


class BugReportUpdate(BaseModel):
    status: str = Field(pattern="^(open|triaging|resolved|closed)$")
    admin_notes: str | None = None


@app.get("/admin/stats", dependencies=[Depends(_require_admin)])
async def admin_stats() -> dict[str, Any]:
    return await fetch_admin_stats()


@app.put("/admin/settings/banner", dependencies=[Depends(_require_admin)])
async def admin_update_banner(body: BannerSettings) -> dict[str, Any]:
    await set_setting("banner_enabled", "true" if body.enabled else "false")
    await set_setting("banner_message", body.message)
    await set_setting("banner_type", body.type)
    return {"ok": True}


@app.get("/admin/bug-reports", dependencies=[Depends(_require_admin)])
async def admin_bug_reports(status: str | None = None) -> list[dict[str, Any]]:
    rows = await fetch_bug_reports(status)
    # Serialize UUIDs and datetimes
    return [
        {**{k: str(v) if hasattr(v, "hex") else v for k, v in r.items()}}
        for r in rows
    ]


@app.patch("/admin/bug-reports/{report_id}", dependencies=[Depends(_require_admin)])
async def admin_update_bug_report(report_id: str, body: BugReportUpdate) -> dict[str, Any]:
    try:
        uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"code": "invalid_id", "detail": "Bad report ID"})
    ok = await update_bug_report(report_id, body.status, body.admin_notes)
    if not ok:
        raise HTTPException(status_code=404, detail={"code": "not_found", "detail": "Report not found"})
    return {"ok": True}


# ── Threat groups ────────────────────────────────────────────────────────────────

class ThreatGroupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class ThreatGroupMemberRequest(BaseModel):
    slug: str = Field(min_length=12, max_length=12, pattern=r"^[A-Z2-7]{12}$")
    notes: str | None = Field(default=None, max_length=300)


@app.get("/admin/threat-groups", dependencies=[Depends(_require_admin)])
async def list_threat_groups() -> list[dict[str, Any]]:
    return await fetch_threat_groups()


@app.post("/admin/threat-groups", dependencies=[Depends(_require_admin)])
async def create_threat_group_endpoint(body: ThreatGroupRequest) -> dict[str, Any]:
    return await create_threat_group(body.name, body.description)


@app.delete("/admin/threat-groups/{group_id}", dependencies=[Depends(_require_admin)])
async def delete_threat_group_endpoint(group_id: str) -> dict[str, Any]:
    try:
        uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"code": "invalid_id", "detail": "Bad group ID"})
    ok = await delete_threat_group(group_id)
    if not ok:
        raise HTTPException(status_code=404, detail={"code": "not_found", "detail": "Group not found"})
    return {"ok": True}


@app.post("/admin/threat-groups/{group_id}/members", dependencies=[Depends(_require_admin)])
async def add_member_endpoint(group_id: str, body: ThreatGroupMemberRequest) -> dict[str, Any]:
    try:
        uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"code": "invalid_id", "detail": "Bad group ID"})
    member = await add_threat_group_member(group_id, body.slug, body.notes)
    if member is None:
        raise HTTPException(status_code=400, detail={"code": "add_failed", "detail": "Could not add member — slug may not exist or is already in this group"})
    return member


@app.delete("/admin/threat-groups/{group_id}/members/{slug}", dependencies=[Depends(_require_admin)])
async def remove_member_endpoint(group_id: str, slug: str) -> dict[str, Any]:
    try:
        uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"code": "invalid_id", "detail": "Bad group ID"})
    ok = await remove_threat_group_member(group_id, slug)
    if not ok:
        raise HTTPException(status_code=404, detail={"code": "not_found", "detail": "Member not found"})
    return {"ok": True}


# ── Billing ──────────────────────────────────────────────────────────────────────

def _require_stripe() -> None:
    if not stripe_billing.is_configured():
        raise HTTPException(
            status_code=503,
            detail={"code": "stripe_not_configured", "detail": "Billing is not enabled on this server."},
        )


class CheckoutRequest(BaseModel):
    email: str
    tier: str = Field(pattern="^(individual|teams)$")
    success_url: str
    cancel_url: str


class PortalRequest(BaseModel):
    email: str
    return_url: str


@app.post("/billing/checkout", dependencies=[Depends(_require_stripe)])
async def billing_checkout(body: CheckoutRequest) -> dict[str, str]:
    user = await fetch_user_by_email(body.email)
    if not user:
        raise HTTPException(status_code=404, detail={"code": "not_found", "detail": "User not found"})

    price_id = stripe_billing.PRICE_IDS.get(body.tier, "")
    if not price_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_tier", "detail": f"No price configured for tier '{body.tier}'"},
        )

    customer_id: str = user.get("stripe_customer_id") or ""
    if not customer_id:
        customer_id = stripe_billing.get_or_create_customer(body.email)
        await set_stripe_customer_id(body.email, customer_id)

    url = stripe_billing.create_checkout_session(
        customer_id, price_id, body.success_url, body.cancel_url
    )
    return {"url": url}


@app.post("/billing/portal", dependencies=[Depends(_require_stripe)])
async def billing_portal(body: PortalRequest) -> dict[str, str]:
    sub = await fetch_subscription_status(body.email)
    customer_id = sub.get("stripe_customer_id")
    if not customer_id:
        raise HTTPException(
            status_code=404,
            detail={"code": "no_subscription", "detail": "No active subscription found for this account."},
        )
    url = stripe_billing.create_portal_session(customer_id, body.return_url)
    return {"url": url}


@app.get("/billing/status")
async def billing_status(email: str) -> dict[str, str]:
    return await fetch_subscription_status(email)


@app.post("/billing/webhook")
async def billing_webhook(request: Request) -> dict[str, str]:
    if not stripe_billing.is_configured():
        raise HTTPException(status_code=503, detail={"code": "stripe_not_configured", "detail": "Billing not enabled"})

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe_billing.construct_webhook_event(payload, sig_header)
    except Exception as exc:
        raise HTTPException(status_code=400, detail={"code": "invalid_signature", "detail": str(exc)})

    event_type: str = event["type"]
    data_obj = event["data"]["object"]

    if event_type == "checkout.session.completed":
        customer_id = data_obj.get("customer")
        # Subscription is now active — status will be confirmed by subscription.updated event
        if customer_id:
            await update_subscription_by_customer(customer_id, "active", "unknown")

    elif event_type in ("customer.subscription.updated", "customer.subscription.created"):
        customer_id = data_obj.get("customer")
        if customer_id:
            status, tier = stripe_billing.extract_subscription_info(data_obj)
            await update_subscription_by_customer(customer_id, status, tier)

    elif event_type == "customer.subscription.deleted":
        customer_id = data_obj.get("customer")
        if customer_id:
            await update_subscription_by_customer(customer_id, "canceled", "free")

    return {"received": True}


# ── Workspaces ───────────────────────────────────────────────────────────────────

class WorkspaceCreateRequest(BaseModel):
    email: str
    name: str = Field(min_length=1, max_length=80)


class WorkspaceInviteRequest(BaseModel):
    owner_email: str
    invite_email: str = Field(pattern=r"^[^@]+@[^@]+\.[^@]+$")


class AcceptInviteRequest(BaseModel):
    token: str
    user_email: str


class RemoveMemberRequest(BaseModel):
    requester_email: str


@app.post("/workspaces")
async def workspace_create(body: WorkspaceCreateRequest) -> dict[str, Any]:
    user = await fetch_user_by_email(body.email)
    if not user:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    if user.get("subscription_status", "free") not in ("active", "trialing"):
        raise HTTPException(402, {"code": "subscription_required", "detail": "Workspaces require an active subscription."})
    return await create_workspace(body.name, str(user["id"]))


@app.get("/workspaces/mine")
async def workspaces_for_user(email: str) -> list[dict[str, Any]]:
    user = await fetch_user_by_email(email)
    if not user:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    return await fetch_workspaces_for_user(str(user["id"]))


@app.get("/workspaces/{workspace_id}")
async def workspace_get(workspace_id: str, email: str) -> dict[str, Any]:
    user = await fetch_user_by_email(email)
    if not user:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    ws = await fetch_workspace(workspace_id, str(user["id"]))
    if not ws:
        raise HTTPException(404, {"code": "not_found", "detail": "Workspace not found or access denied."})
    return ws


@app.post("/workspaces/{workspace_id}/invite")
async def workspace_invite(workspace_id: str, body: WorkspaceInviteRequest) -> dict[str, Any]:
    owner = await fetch_user_by_email(body.owner_email)
    if not owner:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    ws = await fetch_workspace(workspace_id, str(owner["id"]))
    if not ws or ws.get("your_role") != "owner":
        raise HTTPException(403, {"code": "forbidden", "detail": "Only workspace owners can invite members."})
    token = secrets.token_urlsafe(32)
    invite = await create_workspace_invite(workspace_id, body.invite_email, str(owner["id"]), token)
    invite["workspace_name"] = ws["name"]
    return invite


@app.post("/workspaces/accept/{token}")
async def workspace_accept_invite(token: str, body: AcceptInviteRequest) -> dict[str, Any]:
    user = await fetch_user_by_email(body.user_email)
    if not user:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    result = await accept_workspace_invite(token, str(user["id"]), body.user_email)
    if not result:
        raise HTTPException(400, {"code": "invalid_invite", "detail": "Invite is invalid, expired, or already accepted."})
    return result


@app.get("/workspaces/invite/{token}")
async def workspace_invite_info(token: str) -> dict[str, Any]:
    invite = await fetch_invite(token)
    if not invite:
        raise HTTPException(404, {"code": "not_found", "detail": "Invite not found."})
    return invite


@app.delete("/workspaces/{workspace_id}/members/{member_id}")
async def workspace_remove_member(workspace_id: str, member_id: str, body: RemoveMemberRequest) -> dict[str, Any]:
    owner = await fetch_user_by_email(body.requester_email)
    if not owner:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    ok = await remove_workspace_member(workspace_id, member_id, str(owner["id"]))
    if not ok:
        raise HTTPException(404, {"code": "not_found", "detail": "Member not found or you are not the owner."})
    return {"ok": True}


@app.delete("/workspaces/{workspace_id}")
async def workspace_delete(workspace_id: str, body: RemoveMemberRequest) -> dict[str, Any]:
    user = await fetch_user_by_email(body.requester_email)
    if not user:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    ok = await delete_workspace(workspace_id, str(user["id"]))
    if not ok:
        raise HTTPException(404, {"code": "not_found", "detail": "Workspace not found or you are not the owner."})
    return {"ok": True}


# ── API Keys ─────────────────────────────────────────────────────────────────────

class ApiKeyCreateRequest(BaseModel):
    email: str
    name: str = Field(min_length=1, max_length=80)


class ApiKeyDeleteRequest(BaseModel):
    email: str


@app.post("/api-keys")
async def api_key_create(body: ApiKeyCreateRequest) -> dict[str, Any]:
    user = await fetch_user_by_email(body.email)
    if not user:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    if user.get("subscription_tier", "free") not in ("organization", "teams", "individual"):
        raise HTTPException(402, {"code": "subscription_required", "detail": "API keys require an active subscription."})
    plaintext = "cckey_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    key_prefix = plaintext[:14] + "…"
    row = await create_api_key(str(user["id"]), body.name, key_hash, key_prefix)
    row["key"] = plaintext  # returned once — never stored in plaintext
    return row


@app.get("/api-keys")
async def api_key_list(email: str) -> list[dict[str, Any]]:
    user = await fetch_user_by_email(email)
    if not user:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    return await fetch_api_keys_for_user(str(user["id"]))


@app.delete("/api-keys/{key_id}")
async def api_key_revoke(key_id: str, body: ApiKeyDeleteRequest) -> dict[str, Any]:
    user = await fetch_user_by_email(body.email)
    if not user:
        raise HTTPException(401, {"code": "unauthenticated", "detail": "Account not found."})
    ok = await revoke_api_key(key_id, str(user["id"]))
    if not ok:
        raise HTTPException(404, {"code": "not_found", "detail": "Key not found."})
    return {"ok": True}
