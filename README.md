# Instagram Downloader - Backend (Render)

Flask + yt-dlp API that extracts Instagram video download links.

## Endpoints

| Method | Path               | Description                                                        |
| ------ | ------------------ | ------------------------------------------------------------------ |
| GET    | `/health`          | Health check (public).                                             |
| GET    | `/api/instagram`   | `?url=<instagram_url>` → JSON with `video_url`, `title`, thumbnail. |
| GET    | `/api/proxy`       | `?url=<video_url>` → streams the video through Render (fallback).   |

All `/api/*` endpoints require the `X-API-Key` header. The service refuses to
serve the API until `API_AUTH_KEY` is configured (secure by default).

Example:
```
GET https://<your-api>.onrender.com/api/instagram?url=https://www.instagram.com/reel/ABC123/
```

Response:
```json
{
  "success": true,
  "title": "Some reel",
  "video_url": "https://scontent-xxx.cdninstagram.com/.../video.mp4",
  "thumbnail": "https://.../thumbnail.jpg",
  "duration": 29.4,
  "uploader": "someuser",
  "height": 1080,
  "ext": "mp4"
}
```

## Prerequisites

- Instagram session cookies (`cookies.txt`) — Instagram requires a logged-in session to serve videos.
- A GitHub repo to push this folder to (Render deploys from Git).

## Deploying on Render (free tier)

1. Push `backend/` contents to a GitHub repository.
2. On [render.com](https://render.com) → **New → Web Service** → connect the repo.
3. Settings:
   - **Runtime**: Python 3
   - **Build command**: `pip install -r requirements.txt`
   - **Start command**: `gunicorn app:app --bind 0.0.0.0:$PORT --timeout 120 --workers 1`
   - **Health check path**: `/health`
4. Add an environment variable:
   - `ALLOWED_ORIGIN` = your Hostinger domain, e.g. `https://yourdomain.com`
     (or `*` while testing).
   - `API_AUTH_KEY` = a long random secret. Set the **same value** in the
     admin panel at **Downloader Settings → Backend API key**. The PHP frontend
     sends it as the `X-API-Key` header on every backend call.
5. Deploy. The service URL will be `https://<name>.onrender.com`.

Optional environment variables:
   - `MAX_FILE_MB` = max video size allowed through `/api/proxy` (default 400).
   - `RATE_LIMIT_API` = per-IP requests/minute on `/api/instagram` (default 30).
   - `RATE_LIMIT_PROXY` = per-IP requests/minute on `/api/proxy` (default 60).

## Updating cookies.txt (important)

1. Log in to instagram.com in Firefox/Chrome.
2. Export with the **"Get cookies.txt LOCALLY"** extension.
3. Make sure it contains a `sessionid` line — **without it nothing works for stories/private content.**
4. Replace `cookies.txt`, commit, and push — Render auto-redeploys.

### Multi-account cookie pool (recommended — beats rate limits)

Rate limiting se permanent bachne ke liye backend **cookie rotation** support karta hai:

```
backend/
├── cookies/
│   ├── account1.txt   # ek account ka exported cookies (sessionid zaroori)
│   ├── account2.txt
│   └── account3.txt
└── cookies.txt        # legacy single-file slot (optional)
```

- Har request agli available session use karti hai (round-robin) — load bat jata hai
- Jo account baar-baar fail ho usko automatic cooldown milta hai
- Saare accounts expire ho jayein to bina cookie ke public posts phir bhi try hote hain

**Dummy/secondary accounts use karo, main account nahi.**

## Built-in rate-limit protections

| Protection | Kya karta hai |
|---|---|
| Response cache | Same link dobara aaye to instant result (6h posts / 5min stories) — IG jaata hi nahi |
| Request pacing | Har IG call ke beech minimum 1.5s gap (`IG_MIN_GAP` env) |
| Global cooldown | Throttle response aate hi 90s (`IG_COOLDOWN` env) tak fast-fail — hole aur gehra nahi hota |
| Cookie rotation | Load multiple accounts me bant jata hai |

Tuning env vars: `IG_MIN_GAP`, `IG_COOLDOWN`, `CACHE_TTL_POST`, `CACHE_TTL_STORY`.

Instagram sessions expire quickly. When downloads fail with "login/session expired",
refresh the cookies and redeploy.

## Free tier notes

- The service **sleeps after 15 minutes** of inactivity; the first request after sleep
  takes ~30–60 s (cold start). The frontend shows a spinner for this.
- Bandwidth is limited to ~100 GB/month — prefer the direct `video_url` download and
  use `/api/proxy` only when hotlink protection blocks the direct link.
- No persistent disk: nothing is stored; we only extract the CDN URL.