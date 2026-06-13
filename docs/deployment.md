# Deployment Guide

CyberSentinel AI is a **split deployment**: the React dashboard runs on **Vercel**, and the FastAPI backend runs on **Railway** (or Render). Vercel is ideal for the static Vite frontend; the backend needs a long-running process for SSE streaming, background analysis, and in-memory session state.

## Live deployment (example)

| Service | URL |
|---------|-----|
| Frontend (Vercel) | https://frontend-pearl-five-55.vercel.app |
| Backend (Railway) | https://cybersentinel-api-production.up.railway.app |
| API docs | https://cybersentinel-api-production.up.railway.app/docs |

---

## Architecture

```
Browser  →  Vercel (frontend)  →  Railway (FastAPI backend)
              │                         │
              │  VITE_API_URL           │  OPENROUTER_API_KEY
              │                         │  GITHUB_TOKEN, etc.
              └──── fetch + SSE ────────┘
```

| Component | Platform | Why |
|-----------|----------|-----|
| Frontend (`frontend/`) | Vercel | Static Vite build, CDN, preview URLs |
| Backend (`backend/`) | Railway | Persistent server, SSE, 5-agent pipeline, no serverless timeout |

### Railway build notes

This repo includes `backend/mise.toml` to work around Railway/Railpack Python attestation issues. `fastapi` is listed explicitly in `requirements.txt` (not only as a transitive dependency).

---

### Option A — GitHub (recommended)

1. Open [railway.app](https://railway.app) and sign in with GitHub.
2. **New Project** → **Deploy from GitHub repo** → select `dheerajrvanteru/c7-hackathon`.
3. In project settings, set **Root Directory** to `backend`.
4. Railway detects Python via `requirements.txt` and starts with the `Procfile`:
   ```
   web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
   ```
5. Add **Variables** (Settings → Variables):

   | Variable | Required | Notes |
   |----------|----------|-------|
   | `OPENROUTER_API_KEY` | Recommended | LLM action plans; fallback works without it |
   | `GITHUB_TOKEN` | Recommended | Higher GitHub API rate limits for repo scans |
   | `NVD_API_KEY` | Optional | CVE lookups |
   | `ABUSEIPDB_API_KEY` | Optional | IP reputation |

6. **Settings → Networking → Generate Domain** (e.g. `cybersentinel-api-production.up.railway.app`).
7. Copy the public HTTPS URL — you need it for the frontend.

### Option B — Railway CLI

```bash
npm i -g @railway/cli
railway login
cd backend
railway init
railway up
railway domain
```

### Verify backend

```bash
curl https://YOUR-RAILWAY-URL.up.railway.app/docs
```

You should see the FastAPI Swagger UI.

---

## 2. Deploy the frontend (Vercel)

### Option A — GitHub (recommended)

1. Open [vercel.com](https://vercel.com) and sign in with GitHub.
2. **Add New Project** → import `dheerajrvanteru/c7-hackathon`.
3. Configure the project:

   | Setting | Value |
   |---------|-------|
   | **Root Directory** | `frontend` |
   | **Framework Preset** | Vite |
   | **Build Command** | `npm run build` |
   | **Output Directory** | `dist` |

4. Add **Environment Variable**:

   | Name | Value |
   |------|-------|
   | `VITE_API_URL` | `https://YOUR-RAILWAY-URL.up.railway.app` |

   No trailing slash. Must be HTTPS in production.

5. Click **Deploy**.

6. After deploy, open the Vercel URL (e.g. `https://c7-hackathon.vercel.app`) and run **Synthetic** analysis to confirm the pipeline connects.

### Option B — Vercel CLI

```bash
npm i -g vercel
cd frontend
vercel login
vercel --prod
```

When prompted, set `VITE_API_URL` in the Vercel dashboard (Settings → Environment Variables) to your Railway backend URL, then redeploy.

### SPA routing

`frontend/vercel.json` rewrites all routes to `index.html` so client-side navigation works.

---

## 3. Local development with production-like config

```bash
# Terminal 1 — backend
cd backend
source .venv/bin/activate
cp .env.example .env   # add keys
uvicorn main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
cp .env.example .env
# VITE_API_URL=http://localhost:8000  (default)
npm install
npm run dev
```

---

## 4. Environment variables reference

### Frontend (Vercel)

| Variable | Description |
|----------|-------------|
| `VITE_API_URL` | Backend base URL (Railway domain) |

### Backend (Railway)

| Variable | Description |
|----------|-------------|
| `OPENROUTER_API_KEY` | OpenRouter API key for Incident Response LLM |
| `GITHUB_TOKEN` | GitHub PAT for repo scanning |
| `NVD_API_KEY` | NIST NVD API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB key |
| `PORT` | Set automatically by Railway |

See `backend/.env.example` for local development.

---

## 5. CORS

The backend allows all origins (`allow_origins=["*"]` in `main.py`), so the Vercel frontend can call the Railway API without extra CORS configuration.

---

## 6. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard loads but analysis fails immediately | Check `VITE_API_URL` on Vercel matches Railway URL; redeploy frontend after changing env vars |
| GitHub scan returns rate limit error | Add `GITHUB_TOKEN` on Railway and redeploy |
| Agent pipeline stuck / no SSE events | Backend may be down or URL wrong; check Railway logs |
| Empty action plan | Add `OPENROUTER_API_KEY` or rely on deterministic fallback (should still show steps) |
| `Mixed Content` browser error | Ensure `VITE_API_URL` uses `https://`, not `http://` |

### Redeploy after env changes

Vite bakes `VITE_*` variables at **build time**. After changing `VITE_API_URL` on Vercel, trigger a **new deployment** (Redeploy from Deployments tab).

### Railway logs

```bash
railway logs
```

Or use the Railway dashboard → your service → **Deployments** → **View Logs**.

---

## 7. Why not full-stack on Vercel?

Vercel’s Python runtime runs FastAPI as **serverless functions**. CyberSentinel relies on:

- **Background tasks** — analysis runs after `POST /analyze` returns
- **SSE** — long-lived `/stream/{session_id}` connections
- **In-memory sessions** — `_sessions` dict for report retrieval

These patterns need a persistent process. Railway (or Render/Fly.io) is the right fit for the backend; Vercel remains the right fit for the React UI.

---

## 8. Optional: Render instead of Railway

1. [render.com](https://render.com) → **New Web Service** → connect repo.
2. **Root Directory:** `backend`
3. **Build Command:** `pip install -r requirements.txt`
4. **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add the same environment variables as Railway.
6. Use the Render URL as `VITE_API_URL` on Vercel.

---

## Quick checklist

- [ ] Backend deployed on Railway with public HTTPS URL
- [ ] Backend env vars set (`OPENROUTER_API_KEY`, `GITHUB_TOKEN`)
- [ ] `curl https://YOUR-BACKEND/docs` works
- [ ] Frontend deployed on Vercel with **Root Directory** = `frontend`
- [ ] `VITE_API_URL` set to Railway URL on Vercel
- [ ] Frontend redeployed after setting env var
- [ ] Synthetic analysis run succeeds on Vercel URL
