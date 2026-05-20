# shellhawk.net — domain switchover checklist

The rebrand commit ships the code changes. The five items below are configuration
in dashboards I can't touch — you have to do them. Do them in this order; each
step depends on the one above.

---

## 1. Vercel — attach the domain

1. Vercel project → **Settings → Domains** → Add `shellhawk.net` and `www.shellhawk.net`.
2. Vercel will print DNS records to add at your registrar.
   - **Apex (`shellhawk.net`)**: A record → `76.76.21.21`
   - **`www`**: CNAME → `cname.vercel-dns.com`
3. Wait for "Valid Configuration" in Vercel (usually <10 min, can take up to a few hours).
4. In the same page, set **`shellhawk.net`** as the **primary domain** so Vercel
   issues 308 redirects from the old `*.vercel.app` URL — keeps existing
   permalinks working.

## 2. Vercel — environment variables

Add / update under **Settings → Environment Variables** for **Production**:

| Variable | New value |
|---|---|
| `NEXT_PUBLIC_SITE_URL` | `https://shellhawk.net` *(new — drives metadataBase / OG canonicals)* |
| `AUTH_URL`             | `https://shellhawk.net` *(NextAuth canonical — was the vercel.app URL)* |

Redeploy after saving — Vercel does not pick up env-var changes until the next deploy.

## 3. Railway (backend) — environment variables

Update under your Railway backend service → **Variables**:

| Variable | New value |
|---|---|
| `ALLOWED_ORIGINS` | `https://shellhawk.net,https://<your-current>.vercel.app` — keep the vercel.app entry so preview deploys still work |
| `APP_URL`         | `https://shellhawk.net` — used to build email verification / reset / invite links |
| `FROM_EMAIL`      | `ShellHawk <noreply@shellhawk.net>` |

Railway auto-redeploys on env-var change.

## 4. Email — DKIM / SPF for noreply@shellhawk.net

Until DKIM is set up, emails from `noreply@shellhawk.net` will go to spam or be
rejected outright. You're using Resend (`RESEND_API_KEY`), so:

1. Resend dashboard → **Domains → Add Domain** → `shellhawk.net`.
2. Resend prints three DNS records (SPF TXT, DKIM CNAME, DMARC TXT). Add them
   at your registrar.
3. Wait for Resend to show "Verified" (a few minutes to a few hours).
4. Test by triggering a registration on the live site — verification email
   should land in inbox, not spam.

## 5. Stripe (if you're keeping paid tiers visible)

If you re-enable the pricing/billing flow:
- Stripe dashboard → **Settings → Business → Public details**: rename to
  ShellHawk; the receipt email and Stripe-hosted checkout page will pick this up.
- Webhook endpoint URL stays the same (it points at your Railway backend, not
  the brand domain).

---

## What does NOT need changing

- **Permalink slugs** — same SHA-256 hashing, same `/c/<slug>` shape. Existing
  shared links continue to resolve once `shellhawk.net` is live.
- **Database / Postgres credentials** — internal-only, untouched.
- **Stripe webhook URL / API keys** — backend URL, brand-agnostic.
- **`backend/.env` for local dev** — no changes needed.

---

## Smoke test after switchover

1. `https://shellhawk.net` loads, header shows the hawk mark + "ShellHawk".
2. Paste a command → permalink redirects to `https://shellhawk.net/c/<slug>` (not vercel.app).
3. Register a new account → verification email arrives, sender is `ShellHawk <noreply@shellhawk.net>`, link points at `shellhawk.net/verify-email?token=…`.
4. Sign in still works (cookies are domain-scoped — if sign-in breaks, log out from old domain first).
5. `https://api.shellhawk.net` is **NOT** set up by these steps — the docs example URL is aspirational. The backend stays on its Railway URL unless you want to attach a subdomain there too.
