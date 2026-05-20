# Deployment Guide

Stack: **Vercel** (frontend) + **Railway** (backend) + **Supabase** (database).
All have free tiers. Full deployment takes ~30 minutes.

---

## Step 1 — Database (Supabase) ~5 min

1. Go to [supabase.com](https://supabase.com) → New project
2. Once created: **Settings → Database → Connection string**
3. Copy the **Session mode URI** (port **5432**, not 6543)
4. That string is your `DATABASE_URL` — keep it for Step 2

> Migrations run automatically on backend startup via `run_migrations()`.
> No manual SQL needed.

---

## Step 2 — Backend (Railway) ~10 min

1. Go to [railway.app](https://railway.app) → New Project → **Deploy from GitHub repo**
2. Select your repo → set **Root Directory** to `backend`
3. Railway detects Python automatically. The `Procfile` in `backend/` handles startup:
   ```
   web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```
4. **Variables** tab → add all of these:

| Variable | Value |
|---|---|
| `DATABASE_URL` | Your Supabase Session mode URI |
| `ADMIN_SECRET` | Same value as frontend `ADMIN_SECRET` |
| `ADMIN_EMAIL` | Your email — grants admin role on first register |
| `ALLOWED_ORIGINS` | Your frontend URL — comma-separated (e.g. `https://shellhawk.net,https://shellhawk.vercel.app`) |
| `APP_URL` | Same Vercel URL — used in verification emails |
| `VIRUSTOTAL_API_KEY` | Optional — VirusTotal lookups skip gracefully if unset |
| `ABUSEIPDB_API_KEY` | Optional — AbuseIPDB IP reputation lookups |
| `OTX_API_KEY` | Optional — AlienVault OTX threat intelligence |
| `RESEND_API_KEY` | Optional — email verification falls back to server log if unset |
| `FROM_EMAIL` | e.g. `ShellHawk <noreply@shellhawk.net>` |

5. Deploy. Copy the Railway public URL (e.g. `https://shellhawk-backend.up.railway.app`)

---

## Step 3 — Frontend (Vercel) ~10 min

1. Go to [vercel.com](https://vercel.com) → New Project → import your repo
2. Set **Root Directory** to `frontend`
3. Framework preset: **Next.js** (auto-detected)
4. **Environment Variables** → add all of these:

| Variable | Value |
|---|---|
| `NEXT_PUBLIC_API_URL` | Your Railway backend URL |
| `BACKEND_URL` | Same Railway backend URL |
| `AUTH_SECRET` | Run `openssl rand -hex 16` to generate |
| `ADMIN_SECRET` | Same value as backend `ADMIN_SECRET` |
| `AUTH_URL` | Your canonical frontend URL (e.g. `https://shellhawk.net`) |

5. Deploy. Vercel gives you a URL like `your-app.vercel.app`

---

## Step 4 — Wire them together

Once both are live, go back to Railway and update:
- `ALLOWED_ORIGINS` → set to your actual Vercel URL
- `APP_URL` → set to your actual Vercel URL

Vercel and Railway both **auto-redeploy on every push to `main`**.

---

## Step 5 — First login

1. Go to `/register` on your deployed frontend
2. Sign up with the email you set in `ADMIN_EMAIL`
3. If `RESEND_API_KEY` is not set, the verification link prints to the Railway log —
   grab it from there and open it in your browser
4. Sign in — you'll have the admin role automatically

---

## Environment variable reference

### Backend (`backend/.env` locally, Railway vars in prod)

```env
DATABASE_URL=postgresql://user:pass@host/dbname?sslmode=require
ALLOWED_ORIGINS=https://your-app.vercel.app
ADMIN_SECRET=<generate: openssl rand -hex 16>
ADMIN_EMAIL=you@example.com
APP_URL=https://your-app.vercel.app
VIRUSTOTAL_API_KEY=<optional>
ABUSEIPDB_API_KEY=<optional: abuseipdb.com>
OTX_API_KEY=<optional: otx.alienvault.com>
RESEND_API_KEY=<optional: resend.com>
FROM_EMAIL=ShellHawk <noreply@shellhawk.net>
```

### Frontend (`frontend/.env.local` locally, Vercel vars in prod)

```env
NEXT_PUBLIC_API_URL=https://your-backend.up.railway.app
BACKEND_URL=https://your-backend.up.railway.app
AUTH_SECRET=<generate: openssl rand -hex 16>
ADMIN_SECRET=<same as backend ADMIN_SECRET>
AUTH_URL=https://your-app.vercel.app
```

---

## Common gotchas

| Problem | Fix |
|---|---|
| Backend 500 on first request | Supabase free tier pauses after inactivity — retry after a few seconds |
| CORS error in browser | `ALLOWED_ORIGINS` must exactly match your Vercel URL, no trailing slash |
| Auth redirects to wrong URL | `AUTH_URL` in Vercel env must match your actual deployed domain |
| Railway build fails | Confirm root directory is `backend` and `pyproject.toml` is present |
| Vercel: admin page unprotected | Ensure `proxy.ts` exists at frontend root (Next.js 16 renamed `middleware.ts`) |
| Verification email not arriving | Check Railway logs — if `RESEND_API_KEY` is unset the link prints there |
| Sign-in hangs after deploy | Ensure `BACKEND_URL` is set in Vercel (server-side auth calls use this) |
| Admin page returns 403 | `ADMIN_SECRET` must be identical in both Railway and Vercel env vars |

---

## Local dev (quick reference)

```bash
# Backend
cd backend
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:3000  
Backend: http://localhost:8000  
API docs: http://localhost:8000/docs
