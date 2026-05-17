# cmdcheck — Security & Code Audit Action Plan

Audited against `CLAUDE.md` core invariants. Execute top-down; **P0 first**.
Each item has: location, problem, fix, and CLAUDE.md tie-in.

---

## P0 — Critical (privacy/security; fix before anything else)

### P0-1. Private analyses are publicly retrievable via the deterministic slug
**Where:** `backend/app/db.py:923-935` (`fetch_analysis`), `backend/app/main.py` `GET /c/{slug}` and the `/analyze` "return existing" path; `backend/app/slug.py`.
**Problem:** The slug is `base32(sha256(normalized_command))[:12]` — fully derivable from the command. `fetch_analysis()` performs **no authorization check** and even **decrypts** the stored command for anyone. So:
- Anyone who knows or guesses a command computes the slug and fetches the "private" analysis (incl. decrypted command) at `GET /c/{slug}`.
- `upsert_analysis` `ON CONFLICT … WHERE deleted_at IS NOT NULL` means a public re-submitter of the same command gets the **existing private row** returned verbatim by `/analyze`.

This breaks **CLAUDE.md invariant #4 (privacy is load-bearing)** and the Data Handling rule "Private commands … accessible only to the workspace, never in the public corpus." It also contradicts the stated Storage layout: *"Public commands have stable hash-based slugs. Private commands live behind auth."*

**Fix (requires user sign-off — touches permalink semantics, see CLAUDE.md "What to ask the user before doing"):**
1. **Public** submissions: keep the deterministic hash slug (do **not** change format — existing links must not break).
2. **Private** submissions (incl. workspace): generate a **random unguessable slug** (e.g. `secrets.token_urlsafe`, base32-normalized to the 12-char `[A-Z2-7]` shape the frontend regex expects, or widen the regex). They must not collide with the public hash namespace.
3. Add authorization to `fetch_analysis` (or a new `fetch_analysis_authorized(slug, requesting_user_id)`): if `is_private`, only return full data when the requester is the owner or a member of the analysis's workspace; otherwise return a 404-style "not found" (not "deleted").
4. In `/analyze`, when an existing row is private and the requester is not authorized, **do not return it** — treat the submission as a fresh (public, or the requester's own private) analysis.
5. Confirm `GET /c/{slug}` plumbs the session/api-key identity into the authorization check.

### P0-2. Unauthenticated admin server actions
**Where:** `frontend/app/admin/threat-map/actions.ts:1-47` (`createGroup`, `deleteGroup`, `addMember`, `removeMember`).
**Problem:** These `"use server"` actions attach the server-held `X-Admin-Secret` and hit `/admin/*` with **no `requireAdmin()`/session check** (contrast `frontend/app/admin/actions.ts:10-13` which does). Server actions are directly invocable POST endpoints; `proxy.ts` only gates page navigations, not action invocations. Any unauthenticated caller can perform admin mutations using the server's secret.
**Fix:** Add `await requireAdmin()` as the first statement of every function in `threat-map/actions.ts` (mirror `admin/actions.ts`).

### P0-3. `skip_redaction` privacy bypass for anonymous users
**Where:** `frontend/app/api/analyze/route.ts` (~lines 22, 36) → `backend/app/main.py` analyze.
**Problem:** `is_private` requires a session, but `skip_redaction:true` is forwarded unconditionally with no auth. An anonymous user can disable the credential/internal-IP redaction pass on a **public** command. Breaks **CLAUDE.md Data Handling: redaction before storing public commands** and "What to ask the user before … Changing the redaction rules for public commands."
**Fix:** Require an authenticated session for `skip_redaction`; backend already gates it on `user_id` + active subscription (`main.py:489-497`) — make the frontend route enforce session presence and never forward `skip_redaction` for anonymous requests. Confirm backend silently redacts when not entitled (it does — keep that).

### P0-4. Latent `NameError` crashes resend-verification
**Where:** `backend/app/main.py:658` uses `create_verification_token`, but the `from .db import (…)` block at `main.py:27` imports only `consume_verification_token`, not `create_verification_token`.
**Problem:** `POST /auth/resend-verification` raises `NameError` if it ever reaches that branch.
**Fix:** Either add `create_verification_token` to the import (if keeping the flow) or delete the orphaned verification flow entirely — see **P2-2** (decide once, holistically).

---

## P1 — High

### P1-1. Admin secret compared non-constant-time
**Where:** `backend/app/main.py:317` — `x_admin_secret != _ADMIN_SECRET`.
**Fix:** `secrets.compare_digest(x_admin_secret or "", _ADMIN_SECRET)`; keep the empty-secret guard.

### P1-2. Encrypted commands rendered as ciphertext in listings
**Where:** `backend/app/db.py:717` (`fetch_workspace` recent_analyses), `db.py:576` (`fetch_threat_groups`), `db.py:630` (`add_threat_group_member`).
**Problem:** Workspace analyses are forced `is_private=True` → `command` stored encrypted. These listings read `row["command"]` without `decrypt()`, so members/admins see ciphertext blobs. Broken feature.
**Fix:** Decrypt per-row (respecting the `encrypted` column) before truncating to the preview length. Add `encrypted` to the SELECTs.

### P1-3. No Zod validation on API route handlers
**Where:** `frontend/app/api/analyze/route.ts`, `api/workspaces/route.ts`, `api/api-keys/route.ts`, `api/workspaces/accept/route.ts`, `api/workspaces/[id]/invite/route.ts` — all `request.json().catch(()=>({}))` then pass through.
**Problem:** Violates **CLAUDE.md: "Every API route has a Zod schema (TS) or Pydantic model (Python) for input validation."**
**Fix:** Add a `z.object({...}).safeParse(body)` gate to each handler; 400 on failure with the structured `{code, detail}` shape.

### P1-4. `workspace_id` forwarded from client unvalidated (defense-in-depth)
**Where:** `frontend/app/api/analyze/route.ts` (~line 37).
**Note:** Backend *does* validate membership when `user_id` is known (`main.py:419-426`). Still, the frontend forwards a raw client value; ensure the backend path can never accept `workspace_id` without the membership check (it currently nulls it if user not identified — verify and keep). Add an explicit test.

### P1-5. Exception text leaked to clients
**Where:** `backend/app/main.py:867` (`detail={"code":"invalid_signature","detail": str(exc)}`); also `db.py` error strings are user-facing on startup (acceptable for logs, not for HTTP). 
**Problem:** Violates **CLAUDE.md: "Error responses are structured JSON with a stable code field, not raw stack traces."**
**Fix:** Log `exc` server-side; return a static `detail` message. Audit all `str(exc)` in HTTP responses.

---

## P2 — Medium (correctness / robustness)

### P2-1. Migrations re-run on every startup with no tracking
**Where:** `backend/app/db.py:208-214` — every `*.sql` executed each boot, no `schema_migrations` table.
**Problem:** Relies on every migration being perfectly idempotent forever; one non-idempotent statement bricks startup. Fragile.
**Fix:** Add a `schema_migrations(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ)` table; skip already-applied files; wrap each file in a transaction.

### P2-2. Orphaned email-verification subsystem (dead code — decide)
**Where:** `register()` `main.py:614` + `create_user` hard-codes `verified=true` (`db.py:339-342`); `send_verification_email` never called in register; `resend_verification`/`verify_email`/`consume_verification_token`/`create_verification_token` + `VerifyEmailRequest`/`ResendVerificationRequest` only reachable for already-verified users.
**Decision needed:** Either (a) wire verification into `register` (don't auto-verify; send email; gate sign-in on `verified`), or (b) **delete** the whole flow: `send_verification_email`, `create_verification_token`, `consume_verification_token`, the two endpoints, the two Pydantic models, and migration `005`'s tokens table usage. Pick one; do not leave it half-wired (resolves P0-4 too).

### P2-3. Double / non-distributed rate limiting
**Where:** `backend/app/main.py:274-299` — slowapi decorator **and** custom in-memory sliding window (`_rate_windows`, `_TIER_RPM`) both apply to `/analyze`. Both are per-process in-memory.
**Problem:** Double-limiting; and on multi-instance/multi-worker Railway deploys the limits are per-process, not global → ineffective.
**Fix:** Consolidate to one mechanism; back it with the DB or a shared store if multi-instance is expected. At minimum document the single-instance assumption and remove the redundant limiter.

### P2-4. Open-redirect-ish login `next` param
**Where:** `frontend/app/login/page.tsx:12,51` — `router.push(next)` with no same-origin check.
**Fix:** Only accept `next` matching `^/(?!/)` (single leading slash, not `//` or `/\`); else default to `/`.

### P2-5. `apiBase()` host-derivation fallback
**Where:** `frontend/app/lib/api.ts:254-257` — falls back to `http://${window.location.hostname}:8000`.
**Problem:** Analyst-pasted (sensitive) commands could be sent to an attacker-controlled host if served from an unexpected domain.
**Fix:** Hard-fail (throw) when `NEXT_PUBLIC_API_URL` is unset and not on localhost, instead of deriving from the host header.

### P2-6. Naive `.env` parser
**Where:** `backend/app/db.py:16-22`.
**Fix:** Use `python-dotenv` (or strip surrounding quotes and handle `export ` prefixes); keep `setdefault` semantics.

---

## P3 — Redundancy / code quality (low risk, high cleanliness payoff)

Group these into one refactor pass; no behavior change.

- **P3-1. Triplicated row→summary serializer.** `db.py:278-294`, `db.py:313-329`, `db.py:712-720` build the same `{slug, command[:200], threat_labels, …}`. Extract `_summarize_analysis_row(row) -> dict` (decrypt-aware, ties into P1-2).
- **P3-2. 12× user-lookup + 401.** `main.py:915,925,933,944,959,978,989,1011,1027,1034` (and analyze path). Make a FastAPI dependency `require_user(email) -> dict`.
- **P3-3. Subscription gate repeated.** `main.py:415-419, 918-919, 1014-1015`. Dependency `require_active_subscription` / `require_paid_tier`.
- **P3-4. UUID-validate + 400 repeated 5×.** `main.py:725,758,770,782`. Extract `_validate_uuid(id)`.
- **P3-5. Slug-format validation duplicated & inconsistent.** `main.py:569-570` ≡ `579-580` use `isalnum()`; `ThreatGroupMemberRequest.slug` (`main.py:742`) uses `[A-Z2-7]{12}`. Single `is_valid_slug()` helper; pick one canonical charset (must match the slug generator + frontend regex).
- **P3-6. Duplicated Resend send block.** `email.py:31-52` ≡ `69-91`. Extract `_send(to, subject, text, html)`.
- **P3-7. Catalog-load boilerplate 5×.** `lolbas.py:23-42`, `gtfobins.py:40-62`, `loldrivers.py:31-47`, `threat_actors.py:22-32`, `mitre.py:21-34`. Shared `load_json_catalog(path, parse)` / decorator.
- **P3-8. Scattered magic strings.** Subscription statuses `("active","trialing")` and tiers `("organization","teams","individual")`/`"free"` across `main.py:386,396,415,489-497,918,1014` + `db.py:404`; confidence filter `("high","medium")` in the 3 summary sites + `story.py`. Create `constants.py` (`ACTIVE_STATUSES`, `PAID_TIERS`, `ALERT_CONFIDENCES`).
- **P3-9. Duplicated limits.** `_MAX_URLS/_TIMEOUT` in `virustotal.py:22-23` and `threat_intel.py:28-29`. Consolidate.
- **P3-10. `print()`→`logging` in db.py** (`db.py:148-196`); inline `__import__("datetime").datetime.utcnow()` (`db.py:776`) → top-level `from datetime import datetime, timezone`, timezone-aware compare (also fixes a 3.12 deprecation).
- **P3-11. Bare `except Exception: return None`** swallowing errors: `db.py:624`, `threat_intel.py:55,80,103,129,150,171` (add `logger.debug`), `gtfobins.py:36-37`. Narrow exception types or log.
- **P3-12. Dead/unused.** `ErrorResponse` model (`main.py:362-364`) unused; `stripe_billing.py:91` redundant `or "unknown"`; missing return type hints (`encryption.py:_get_fernet`, `main.py:lifespan`) — CLAUDE.md requires hints on every signature.
- **P3-13. Inconsistent `HTTPException` construction** (keyword `status_code=`/`detail=` vs positional). Standardize on one style repo-wide.

---

## Execution notes for the implementer

- **Do P0-1 and P0-3 with explicit user confirmation** — they change permalink/redaction semantics, which `CLAUDE.md` lists under "What to ask the user before doing."
- Add/extend tests for: private-slug isolation (P0-1), admin-action auth (P0-2), redaction-when-anonymous (P0-3). `CLAUDE.md` requires adversarial fixtures in `backend/tests/fixtures/`.
- Keep the **public** slug format byte-stable. Do not switch public slugs to UUIDs.
- After P0/P1, run `ruff` (rules E,F,I,UP,B,SIM) and `pytest`; fix new findings before the P3 refactor.
- One PR per priority band (P0, P1, P2, P3) for reviewable diffs.
