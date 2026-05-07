# cmdcheck

Command-line analyzer for incident responders. Paste a suspicious command, get structured deobfuscation, LOLBAS matching, and a shareable permalink.

## Local dev setup

**Prerequisites:** Docker, Docker Compose, Git, Node 20+, Python 3.12+

### 1. Clone with submodules

```bash
git clone --recurse-submodules <repo-url>
cd cmdcheck
# If you already cloned without submodules:
git submodule update --init --recursive
```

### 2. Start everything

```bash
docker compose up --build
```

| Service  | URL                    |
|----------|------------------------|
| Frontend | http://localhost:3000  |
| Backend  | http://localhost:8000  |
| Postgres | localhost:5432         |

### 3. Run without Docker (faster iteration)

**Backend:**

```bash
cd backend
pip install uv
uv pip install --system -e ".[dev]"
DATABASE_URL=postgresql://cmdcheck:cmdcheck@localhost:5432/cmdcheck uvicorn app.main:app --reload
```

**Frontend:**

```bash
cd frontend
cp .env.local.example .env.local
npm install
npm run dev
```

### 4. Run tests

**Backend:**

```bash
cd backend
pytest
```

**Frontend (Playwright):**

```bash
cd frontend
npx playwright install chromium
npm run test:e2e
```

## Architecture

See [CLAUDE.md](./CLAUDE.md) for full design notes, invariants, and conventions.

- `frontend/` — Next.js (App Router), TypeScript, Tailwind v4
- `backend/` — FastAPI, Python 3.12, bashlex, LOLBAS
- `shared/` — JSON schemas for request/response contracts
- `backend/data/LOLBAS/` — git submodule from LOLBAS-Project/LOLBAS

## Hosting

TBD
