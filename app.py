import http.cookiejar
import json
import os
import re
import threading
import time

import requests
from flask import Flask, jsonify, request, Response
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    import yt_dlp
    HAS_YTDLP = True
except ImportError:
    HAS_YTDLP = False

# Browser-perfect TLS fingerprinting — makes logged-out requests look real.
try:
    from curl_cffi import requests as creq
    HAS_CURL_CFFI = True
except ImportError:
    creq = None
    HAS_CURL_CFFI = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COOKIE_FILE = os.path.join(BASE_DIR, "cookies.txt")
COOKIE_DIR = os.path.join(BASE_DIR, "cookies")  # multi-account pool: one .txt per account
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
INSTAGRAM_RE = re.compile(
    r"^https?://(?:www\.|m\.|mobile\.)?instagram\.com/(?:p|reel|reels|tv)/[A-Za-z0-9_\-]+"
)
# Stories have a different shape: /stories/<username>/<media_id>/
STORIES_RE = re.compile(
    r"^https?://(?:www\.)?instagram\.com/stories/[A-Za-z0-9_.]+/[0-9]+"
)
IMAGE_EXTS = ("jpg", "jpeg", "webp", "png")

# SSRF guard: only Instagram media CDN hosts may be streamed via /api/proxy.
ALLOWED_PROXY_HOST_SUFFIXES = (
    "cdninstagram.com",
    "fbcdn.net",
    "instagram.com",
    "akamaihd.net",
)


def is_allowed_media_host(url):
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    return any(host == s or host.endswith("." + s) for s in ALLOWED_PROXY_HOST_SUFFIXES)

# ---- API authentication (shared secret with the PHP frontend) ----
# Set API_AUTH_KEY on the server. When empty, API endpoints refuse to run
# (secure by default) until it is configured. /health stays public for uptime.
API_KEY = os.environ.get("API_AUTH_KEY", "")

# ---- file-size & rate limits ----
MAX_FILE_MB = int(os.environ.get("MAX_FILE_MB", "400"))
MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024
RATE_LIMIT_API = int(os.environ.get("RATE_LIMIT_API", "30"))
RATE_LIMIT_PROXY = int(os.environ.get("RATE_LIMIT_PROXY", "60"))

# ---- anti-rate-limit toolkit ----
# 1) Cookie pool: rotate several logged-in sessions (cookies/*.txt, one per
#    account) so no single account absorbs all the load.
# 2) Response cache: repeated links are served instantly without touching IG.
# 3) Pacing: minimum gap between outgoing IG requests.
# 4) Global cooldown: after a throttle response, back off instead of digging
#    the hole deeper.
MIN_IG_GAP = float(os.environ.get("IG_MIN_GAP", "1.5"))   # seconds between IG calls
IG_COOLDOWN = int(os.environ.get("IG_COOLDOWN", "90"))    # pause after a throttle
CACHE_TTL_POST = int(os.environ.get("CACHE_TTL_POST", str(6 * 3600)))   # posts/reels
CACHE_TTL_STORY = int(os.environ.get("CACHE_TTL_STORY", "300"))          # stories expire fast
_CACHE = {}                    # key -> (expires_ts, payload_dict)
_LOCK = threading.Lock()
_PACE = {"last": 0.0}
_COOLDOWN = {"until": 0.0}
_COOKIE_IDX = {"i": 0}
_COOKIE_FAILS = {}             # path -> consecutive failures


def cache_get(key):
    with _LOCK:
        hit = _CACHE.get(key)
        if not hit:
            return None
        exp, payload = hit
        if time.time() > exp:
            _CACHE.pop(key, None)
            return None
        return payload


def cache_set(key, payload, ttl=None):
    if ttl is None:
        ttl = CACHE_TTL_POST if "/stories/" not in key else CACHE_TTL_STORY
    with _LOCK:
        if len(_CACHE) > 500:  # keep memory bounded
            now = time.time()
            for k in [k for k, (e, _) in _CACHE.items() if e < now][:250]:
                _CACHE.pop(k, None)
            if len(_CACHE) > 500:
                _CACHE.clear()
        _CACHE[key] = (time.time() + ttl, payload)


def ig_cooldown_active():
    return time.time() < _COOLDOWN["until"]


def ig_trigger_cooldown():
    _COOLDOWN["until"] = time.time() + IG_COOLDOWN


def pace():
    """Guarantee a minimum gap between outgoing Instagram requests."""
    with _LOCK:
        now = time.time()
        wait = MIN_IG_GAP - (now - _PACE["last"])
        _PACE["last"] = max(now, _PACE["last"]) + MIN_IG_GAP
    if wait > 0:
        time.sleep(min(wait, 10))


def normalize_media_key(url):
    u = (url or "").strip()
    u = re.sub(r"[?#/]+$", "", u.split("?")[0].split("#")[0])
    m = re.search(r"instagram\.com/(?:p|reel|reels|tv)/([A-Za-z0-9_-]+)", u)
    if m:
        return "post:" + m.group(1)
    m = re.search(r"instagram\.com/stories/([A-Za-z0-9_.]+)/([0-9]+)", u)
    if m:
        return f"story:{m.group(1)}:{m.group(2)}"
    return "url:" + u


def cookie_pool():
    """All usable cookie files: cookies/*.txt first, legacy cookies.txt last."""
    files = []
    try:
        if os.path.isdir(COOKIE_DIR):
            files = [
                os.path.join(COOKIE_DIR, f)
                for f in sorted(os.listdir(COOKIE_DIR))
                if f.endswith(".txt")
            ]
    except OSError:
        files = []
    files.append(COOKIE_FILE)  # legacy single-file slot
    out = []
    for p in files:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                if "sessionid" in fh.read():
                    fails = _COOKIE_FAILS.get(p, 0)
                    if fails < 5:  # cool down accounts that keep failing
                        out.append(p)
        except OSError:
            continue
    return out


def next_cookie(exclude=None):
    pool = [p for p in cookie_pool() if p != exclude]
    if not pool:
        return None
    with _LOCK:
        i = _COOKIE_IDX["i"]
        _COOKIE_IDX["i"] = i + 1
    return pool[i % len(pool)]


def cookie_fail(path):
    if path:
        _COOKIE_FAILS[path] = _COOKIE_FAILS.get(path, 0) + 1


def cookie_ok(path):
    if path:
        _COOKIE_FAILS[path] = 0


def gql_session_for(cookie_path=None):
    """requests.Session carrying the account's cookies + csrf token."""
    sess = requests.Session()
    sess.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    })
    if cookie_path and os.path.exists(cookie_path):
        try:
            jar = http.cookiejar.MozillaCookieJar(cookie_path)
            jar.load(ignore_discard=True, ignore_expires=True)
            sess.cookies.update(jar)
        except Exception:
            pass
    return sess


# ---- session sync: pull admin-pasted cookies from the PHP panel ----
SYNC_URL = os.environ.get("COOKIE_SYNC_URL", "http://localhost:8000/sessions-sync.php")
_SYNC_TTL = int(os.environ.get("COOKIE_SYNC_TTL", "300"))  # re-sync every 5 min
_last_sync = {"t": 0.0}


def sync_sessions(force=False):
    """Download sessions saved via the admin panel into the local cookie pool.
    Runs at most once per _SYNC_TTL seconds (or when forced / pool is empty)."""
    global _last_sync
    if not API_KEY:
        return
    now = time.time()
    with _LOCK:
        due = force or (now - _last_sync["t"]) >= _SYNC_TTL
        if not due:
            return
        _last_sync["t"] = now
    try:
        r = requests.get(SYNC_URL, headers={"X-API-Key": API_KEY}, timeout=10)
        j = r.json()
        sessions = j.get("sessions") or []
        os.makedirs(COOKIE_DIR, exist_ok=True)
        # refresh only db-managed files; manual files in cookies/ are untouched
        for f in os.listdir(COOKIE_DIR):
            if f.startswith("db-") and f.endswith(".txt"):
                try:
                    os.remove(os.path.join(COOKIE_DIR, f))
                except OSError:
                    pass
        for i, s in enumerate(sessions, 1):
            text = str(s.get("cookie") or "")
            if "sessionid" not in text:
                continue
            with open(os.path.join(COOKIE_DIR, f"db-{i}.txt"), "w", encoding="utf-8") as fh:
                fh.write(text)
        app.logger.info("cookie pool synced from admin: %s session(s)", len(sessions))
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("cookie sync failed: %s", str(exc)[:120])


_RATE = {}
_RATE_LOCK = threading.Lock()


def _client_ip():
    return request.remote_addr or "0.0.0.0"


def _check_rate(limit, window=60):
    global _RATE
    now = time.time()
    key = _client_ip()
    with _RATE_LOCK:
        dq = _RATE.setdefault(key, [])
        dq[:] = [t for t in dq if now - t < window]
        if len(dq) >= limit:
            app.logger.warning("RATE denied %s len=%d limit=%d", key, len(dq), limit)
            return False
        dq.append(now)
        if len(_RATE) > 5000:  # stop unbounded growth
            cutoff = now - 120
            _RATE = {k: v for k, v in _RATE.items() if v and v[-1] > cutoff}
    return True


def _require_api_key():
    if not API_KEY:
        return jsonify({"success": False, "error": "Service not configured yet (API key missing)."}), 503
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"success": False, "error": "Unauthorized."}), 401
    return None


def cors_headers():
    return {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
    }


def is_valid_instagram_url(url):
    url = url.strip()
    if "?" in url:
        url = url.split("?", 1)[0]
    if "#" in url:
        url = url.split("#", 1)[0]
    return bool(INSTAGRAM_RE.match(url) or STORIES_RE.match(url))


def build_ydl_opts(cookie_path=None):
    opts = {
        "quiet": True,
        "no_warnings": True,
        # Keep playlist extraction enabled so carousel posts return all items.
        # Single posts are unaffected (they are never playlists).
        "noplaylist": False,
        "skip_download": True,
        "extract_flat": False,
        "format": "best",
        "socket_timeout": 30,
        "retries": 2,
        "no_color": True,
    }
    path = cookie_path or (COOKIE_FILE if has_valid_cookies() else None)
    if path and os.path.exists(path):
        opts["cookiefile"] = path
    return opts


def has_valid_cookies():
    """cookies.txt is only useful when it carries a sessionid — an expired
    file can make Instagram reject requests that would otherwise succeed."""
    try:
        with open(COOKIE_FILE, "r", encoding="utf-8", errors="ignore") as fh:
            return "sessionid" in fh.read()
    except OSError:
        return False


# ---- GraphQL fallback (public posts: photos, carousels, videos) ----
GQL_ENDPOINT = "https://www.instagram.com/graphql/query"
GQL_DOC_IDS = ("25531498899829322", "8845758582119845")
GQL_APP_ID = "936619743392459"


def gql_shortcode(url):
    m = re.search(r"instagram\.com/(?:p|reel|reels|tv)/([A-Za-z0-9_-]+)", url or "")
    return m.group(1) if m else None


def gql_fetch(shortcode, cookie_path=None):
    """Fetch post metadata via Instagram's web GraphQL endpoint.
    Uses a logged-in session when a cookie file is supplied (much higher
    limits). Returns (media_dict_or_None, throttled_bool)."""
    variables = {
        "shortcode": shortcode,
        "fetch_tagged_user_count": None,
        "hoisted_comment_id": None,
        "hoisted_reply_id": None,
    }
    sess = gql_session_for(cookie_path)
    csrf = sess.cookies.get("csrftoken", domain=".instagram.com") or ""
    try:
        sess.get(f"https://www.instagram.com/p/{shortcode}/", timeout=15, allow_redirects=True)
        csrf = csrf or sess.cookies.get("csrftoken", domain=".instagram.com") or ""
    except Exception:
        pass

    throttled = False
    for doc_id in GQL_DOC_IDS:
        try:
            r = sess.post(
                GQL_ENDPOINT,
                params={"doc_id": doc_id},
                data={
                    "variables": json.dumps(variables),
                    "lsd": "",
                },
                headers={
                    "X-IG-App-ID": GQL_APP_ID,
                    "X-Requested-With": "XMLHttpRequest",
                    "X-CSRFTOKEN": csrf,
                    "X-FB-Friendly-Name": "PolarisPostActionLoadPostQueryQuery",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "cors",
                    "Referer": f"https://www.instagram.com/p/{shortcode}/",
                },
                timeout=20,
            )
            j = r.json()
            data = j.get("data") or {}
            media = data.get("xdt_shortcode_media") or data.get("shortcode_media")
            if media:
                return media, False
            msg_txt = str(j.get("message") or "")
            if "wait" in msg_txt.lower() or j.get("require_login"):
                throttled = True
                break  # this session/IP is throttled — caller rotates accounts
        except Exception:
            continue
    return None, throttled


def gql_pick_image(node):
    u = node.get("display_url") or ""
    res = node.get("display_resources") or []
    if res:
        u = res[-1].get("src") or u
    ext = "jpg"
    m = re.search(r"\.(jpe?g|webp|png)(?:\?|$)", u)
    if m:
        ext = "jpg" if m.group(1).startswith("jp") else m.group(1)
    return u, ext, (node.get("dimensions") or {}).get("height")


def gql_node_to_item(node):
    if node.get("is_video"):
        u = node.get("video_url")
        return (u, "mp4", node.get("video_duration")) if u else (None, None, None)
    return gql_pick_image(node)


# ---- Cookie-free extraction: parse the public post page's embedded JSON.
#      Works logged-out with a browser-perfect TLS fingerprint (curl_cffi). ----
def html_extract_payload(shortcode, started):
    if not HAS_CURL_CFFI:
        return None
    try:
        s = creq.Session(impersonate="chrome")
        r = s.get(f"https://www.instagram.com/p/{shortcode}/", timeout=25)
        if r.status_code != 200 or len(r.text) < 5000:
            return None
        target = None
        uploader = None
        for blob in re.findall(r'<script type="application/json"[^>]*>(.*?)</script>', r.text, re.S):
            if '"image_versions2"' not in blob and '"video_versions"' not in blob:
                continue
            um = re.search(r'"username"\s*:\s*"([A-Za-z0-9._]{2,30})"', blob)
            if um:
                uploader = um.group(1)
            try:
                target = json.loads(blob)
                break
            except Exception:
                continue
        if target is None:
            return None

        nodes = []
        def walk(o):
            if isinstance(o, dict):
                if "image_versions2" in o or "video_versions" in o:
                    nodes.append(o)
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(target)
        # dedupe identical nodes (same url+id)
        seen = set()
        uniq = []
        for n in nodes:
            k = id(n)
            if k in seen:
                continue
            seen.add(k)
            uniq.append(n)

        base_name = safe_title(shortcode, "instagram-media")
        uploader = ""
        m = re.search(r'<meta property="og:title" content="([^"]+)"', r.text)
        if m:
            import html as _html
            t = _html.unescape(m.group(1))
            t = t.split(" on Instagram")[0]
            t = re.split(r"\s*[|•·]\s*", t)[0]
            uname = t.strip().strip("@ ").strip()
            uname = re.sub(r"[\u200e\u200f\u200b\ufeff]", "", uname).strip()
            if uname and 0 < len(uname) <= 60 and uname.lower() != shortcode.lower():
                uploader = uname
        items = []
        for i, n in enumerate(uniq[:20], 1):
            vv = n.get("video_versions") or []
            iv = (n.get("image_versions2") or {}).get("candidates") or []
            vid = (vv[0] or {}).get("url") if vv else ""
            img = (iv[0] or {}).get("url") if iv else ""
            u = vid or img
            if not u:
                continue
            ext = "mp4" if vid else "jpg"
            items.append({
                "url": u,
                "ext": ext,
                "height": n.get("original_height"),
                "filename": f"{base_name}-{i}.{ext}" if len(uniq) > 1 else f"{base_name}.{ext}",
                "thumbnail": img,
                "duration": None,
            })
        if not items:
            return None

        first_img = next((it["thumbnail"] for it in items if it["thumbnail"]), "")
        payload = {
            "success": True,
            "type": "carousel" if len(items) > 1 else ("video" if items[0]["ext"] == "mp4" else "image"),
            "title": uploader or shortcode,
            "uploader": uploader or None,
            "count": len(items),
            "thumbnail": first_img,
            "items": items,
            "fetch_ms": int((time.time() - started) * 1000),
        }
        if len(items) == 1:
            it0 = items[0]
            payload.update({
                "type": "video" if it0["ext"] == "mp4" else "image",
                "video_url": it0["url"],
                "filename": it0["filename"],
                "height": it0["height"],
                "ext": it0["ext"],
            })
        return payload
    except Exception as exc:  # noqa: BLE001
        app.logger.warning("html extract failed: %s", str(exc)[:120])
        return None


def build_gql_response(media, started):
    title = ""
    try:
        edges = media.get("edge_media_to_caption", {}).get("edges") or []
        if edges:
            title = edges[0].get("node", {}).get("text") or ""
    except Exception:
        title = ""
    title = title.strip()[:80] or (media.get("shortcode") or "Instagram media")
    base_name = safe_title(title, "instagram-media")

    typename = media.get("__typename") or ""

    def item_payload(idx, node):
        u, ext, dur = gql_node_to_item(node)
        if not u:
            return None
        return {
            "url": u,
            "ext": ext,
            "height": (node.get("dimensions") or {}).get("height"),
            "filename": f"{base_name}-{idx}.{ext}" if idx else f"{base_name}.{ext}",
            "thumbnail": node.get("display_url") or "",
            "duration": dur,
        }

    if typename == "GraphSidecar":
        nodes = [e.get("node") for e in (media.get("edge_sidecar_to_children", {}).get("edges") or [])]
        nodes = [n for n in nodes if n]
        items = []
        for i, n in enumerate(nodes[:20], 1):
            it = item_payload(i, n)
            if it:
                items.append(it)
        if not items:
            return None
        return {
            "success": True,
            "type": "carousel",
            "title": title,
            "count": len(items),
            "thumbnail": media.get("display_url") or (items[0]["thumbnail"] if items else ""),
            "uploader": (media.get("owner") or {}).get("username"),
            "items": items,
            "fetch_ms": int((time.time() - started) * 1000),
        }

    it = item_payload(0, media)
    if not it:
        return None
    kind = "image" if it["ext"] in IMAGE_EXTS else "video"
    return {
        "success": True,
        "type": kind,
        "title": title,
        "video_url": it["url"],
        "filename": it["filename"],
        "thumbnail": media.get("display_url") or "",
        "duration": it["duration"],
        "uploader": (media.get("owner") or {}).get("username"),
        "height": it["height"],
        "ext": it["ext"],
        "fetch_ms": int((time.time() - started) * 1000),
    }


def extract_info(url, cookie_path=None):
    if not HAS_YTDLP:
        raise RuntimeError("yt-dlp is not installed on the server.")
    with yt_dlp.YoutubeDL(build_ydl_opts(cookie_path)) as ydl:
        return ydl.extract_info(url, download=False)


def has_audio(f):
    ac = f.get("acodec")
    return ac not in (None, "none")


def has_video(f):
    vc = f.get("vcodec")
    return vc not in (None, "none")


def sort_key(f):
    return (f.get("height") or 0, f.get("tbr") or 0, f.get("abr") or 0)


def safe_title(title, fallback="instagram"):
    title = title or fallback
    cleaned = re.sub(r"[^\w\-.\u0900-\u097F ]", "_", str(title)).strip()
    return cleaned[:60] or fallback


def normalize_ext(ext, default="mp4"):
    ext = (ext or "").lower().strip(".")
    if not ext:
        return default
    if len(ext) > 5:  # junk like "mp4;codecs=avc1"
        ext = ext.split(";")[0]
    return ext or default


def pick_image_url(info):
    """Best image URL from a photo post (formats carry the image itself)."""
    best = None
    for f in info.get("formats") or []:
        url = f.get("url")
        if not url or f.get("vcodec") not in (None, "none"):
            continue
        if f.get("ext") not in IMAGE_EXTS and "image" not in (f.get("format_id") or ""):
            continue
        w = f.get("width") or 0
        if best is None or w > (best[0] or 0):
            best = (w, url, f.get("ext"))
    if best:
        return best[1], normalize_ext(best[2], "jpg")
    u = info.get("url")
    if u:
        return u, normalize_ext(info.get("ext"), "jpg")
    return None, None


def pick_direct_url(info):
    formats = info.get("formats") or []
    formats = [f for f in formats if f.get("protocol") not in ("m3u8", "m3u8_native")]
    if not formats:
        formats = info.get("formats") or []

    # 1) Prefer formats that clearly contain BOTH audio and video.
    with_av = [f for f in formats if has_audio(f) and has_video(f)]
    if with_av:
        with_av.sort(key=sort_key, reverse=True)
        best = with_av[0]
        return best.get("url"), best.get("height"), best.get("ext")

    # 2) Fall back to "progressive" candidates whose codecs are unknown (null)
    #    — these are Instagram's combined mp4s. Never pick a video-only DASH stream.
    progressive = [
        f
        for f in formats
        if f.get("acodec") is None and f.get("vcodec") is None and f.get("url")
    ]
    if progressive:
        progressive.sort(key=sort_key, reverse=True)
        best = progressive[0]
        return best.get("url"), best.get("height"), best.get("ext")

    # 3) Last resort: the format yt-dlp selected itself.
    u = info.get("url")
    if u:
        return u, info.get("height"), info.get("ext")

    # 4) Any other available URL.
    for f in formats:
        u = f.get("url")
        if u:
            return u, f.get("height"), f.get("ext")
    return None, None, None


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.route("/")
def home():
    return jsonify({"service": "instagram-downloader", "status": "ok"})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "ytdlp": HAS_YTDLP})


@app.route("/api/instagram", methods=["GET", "OPTIONS"])
def instagram():
    if request.method == "OPTIONS":
        return ("", 204, cors_headers())

    auth = _require_api_key()
    if auth is not None:
        return auth
    if not _check_rate(RATE_LIMIT_API):
        return jsonify({"success": False, "error": "Too many requests. Please wait a moment."}), 429

    url = (request.args.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "error": "Missing 'url' parameter."}), 400
    if not is_valid_instagram_url(url):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Invalid URL. Must be an instagram.com /p/, /reel/, /reels/, /tv/ or /stories/ link.",
                }
            ),
            400,
        )

    # ---- cache: repeated links never touch Instagram ----
    key = normalize_media_key(url)
    cached = cache_get(key)
    if cached is not None:
        out = dict(cached)
        out["_cache"] = "HIT"
        return jsonify(out)

    # ---- global cooldown: after a throttle, fail fast instead of digging deeper
    if ig_cooldown_active():
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Instagram is rate-limiting this server temporarily. Please wait a few minutes and try again.",
                }
            ),
            503,
        )

    sync_sessions()  # pull admin-pasted sessions into the pool (throttled internally)

    started = time.time()
    payload = None          # success dict (built below)
    err_msg = ""
    saw_throttle = False
    used_cookie = None

    # ---- attempt 1..2: yt-dlp with rotating accounts ----
    for attempt in range(2):
        ck = next_cookie(exclude=used_cookie)
        used_cookie = ck or used_cookie
        pace()
        try:
            info = extract_info(url, ck)
            cookie_ok(ck)

            title = info.get("title") or info.get("id") or "Instagram media"
            base_name = safe_title(title, "instagram-media")

            entries = None
            if info.get("_type") == "playlist" or info.get("entries"):
                entries = [e for e in (info.get("entries") or []) if e]

            if entries and len(entries) > 1:
                items = []
                for idx, entry in enumerate(entries[:20], 1):
                    e_ext = normalize_ext(entry.get("ext"))
                    if e_ext in IMAGE_EXTS:
                        u, ext = pick_image_url(entry)
                        h = entry.get("height")
                    else:
                        u, h, ext = pick_direct_url(entry)
                        ext = normalize_ext(ext)
                    if not u:
                        continue
                    items.append({
                        "url": u,
                        "ext": ext,
                        "height": h,
                        "filename": f"{base_name}-{idx}.{ext}",
                        "thumbnail": entry.get("thumbnail") or "",
                        "duration": entry.get("duration"),
                    })
                if items:
                    payload = {
                        "success": True,
                        "type": "carousel",
                        "title": title,
                        "count": len(items),
                        "thumbnail": items[0]["thumbnail"] or info.get("thumbnail") or "",
                        "uploader": info.get("uploader"),
                        "items": items,
                    }
                    break

            first_ext = normalize_ext(info.get("ext"), "")
            if first_ext in IMAGE_EXTS:
                direct_url, ext = pick_image_url(info)
                height = None
            else:
                direct_url, height, ext = pick_direct_url(info)
                ext = normalize_ext(ext)
            if direct_url:
                payload = {
                    "success": True,
                    "type": "image" if ext in IMAGE_EXTS else "video",
                    "title": title,
                    "video_url": direct_url,
                    "filename": f"{base_name}.{ext}",
                    "thumbnail": (info.get("thumbnail") or ""),
                    "duration": info.get("duration"),
                    "uploader": info.get("uploader"),
                    "height": height,
                    "ext": ext,
                }
                break
            err_msg = "No downloadable media found for this post."
            break  # real empty result — no point retrying with another account
        except Exception as exc:  # noqa: BLE001
            err_msg = str(exc)
            app.logger.warning("instagram extract failed (%s): %s", ck or "nocookie", err_msg[:200])
            lowered = err_msg.lower()
            if "no video formats found" in lowered:
                break  # photo-type post — GraphQL fallback handles it
            if any(x in lowered for x in ("login", "not available", "unreachable")):
                cookie_fail(ck)
                saw_throttle = True
                continue  # rotate to the next account
            break

    # ---- GraphQL fallback: rescues photos, carousels and posts yt-dlp can't read.
    #      Rotates through every account in the pool. ----
    sc = gql_shortcode(url)
    if payload is None and sc:
        for attempt in range(3):
            ck = next_cookie(exclude=used_cookie)
            pace()
            media, thr = gql_fetch(sc, ck)
            if media:
                built = build_gql_response(media, started)
                if built is not None:
                    payload = built
                    used_cookie = ck
                    cookie_ok(ck)
                    break
            if thr:
                saw_throttle = True
                cookie_fail(ck)
                used_cookie = ck
                continue
            break

    # ---- HTML fallback: 100% cookie-free — parses the public page itself ----
    if payload is None and sc:
        pace()
        payload = html_extract_payload(sc, started)
        if payload is not None:
            app.logger.info("html fallback rescued shortcode %s (cookie-free)", sc)

    if payload is None:
        if saw_throttle:
            ig_trigger_cooldown()
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Instagram is rate-limiting this server temporarily. Please wait a few minutes and try again.",
                    }
                ),
                503,
            )
        lowered = err_msg.lower()
        if lowered and any(x in lowered for x in ("login", "log in", "not available", "unreachable")):
            hint = (
                "Instagram requires a logged-in session for this content. Admin: add cookies/*.txt files that contain sessionid."
                if not cookie_pool()
                else "Instagram rejected every available session. Refresh the cookies on the server."
            )
            return jsonify({"success": False, "error": hint}), 401
        return (
            jsonify(
                {
                    "success": False,
                    "error": err_msg[:160] if err_msg.startswith("No downloadable") else "Failed to fetch media. Please try again.",
                }
            ),
            500 if not err_msg.startswith("No downloadable") else 404,
        )

    payload["fetch_ms"] = int((time.time() - started) * 1000)
    cache_set(key, payload)
    out = dict(payload)
    out["_cache"] = "MISS"
    return jsonify(out)


@app.route("/api/thumbnail", methods=["GET", "OPTIONS"])
def thumbnail_only():
    """Return only the thumbnail image URL for an Instagram post/video URL."""
    if request.method == "OPTIONS":
        return ("", 204, cors_headers())

    auth = _require_api_key()
    if auth is not None:
        return auth
    if not _check_rate(RATE_LIMIT_API):
        return jsonify({"success": False, "error": "Too many requests. Please wait a moment."}), 429

    url = (request.args.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "error": "Missing 'url' parameter."}), 400

    cache_key = "thumb:" + url
    cached = cache_get(cache_key)
    if cached is not None:
        out = dict(cached)
        out["_cache"] = "HIT"
        return jsonify(out)

    # Use yt-dlp to extract video info (thumbnail + title)
    try:
        info = extract_info(url)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 502

    thumb_url = (info.get("thumbnail") or info.get("url") or "")
    title = info.get("title", "")
    ext = "jpg"

    # Clean thumbnail URL — remove size params for full-res
    thumb_url = re.sub(r"s\d+x\d+/", "", thumb_url)
    thumb_url = re.sub(r"[&?]stp=[^&]*", "", thumb_url)
    if "?" not in thumb_url and "&" in thumb_url:
        thumb_url = thumb_url.replace("&", "?", 1)

    if not thumb_url:
        return jsonify({"success": False, "error": "Could not extract thumbnail from this URL."}), 404

    payload = {
        "success": True,
        "video_url": thumb_url,
        "thumbnail": thumb_url,
        "filename": "instagram-thumbnail.jpg",
        "ext": "jpg",
        "type": "image",
        "title": title or "Instagram Thumbnail",
        "uploader": info.get("uploader", ""),
        "height": info.get("height", ""),
        "duration": info.get("duration", 0),
    }
    cache_set(cache_key, payload)
    out_resp = dict(payload)
    out_resp["_cache"] = "MISS"
    return jsonify(out_resp)


@app.route("/api/profile", methods=["GET", "OPTIONS"])
def profile_pic():
    """Extract and return the full-size profile picture URL for an Instagram username."""
    if request.method == "OPTIONS":
        return ("", 204, cors_headers())

    auth = _require_api_key()
    if auth is not None:
        return auth
    if not _check_rate(RATE_LIMIT_API):
        return jsonify({"success": False, "error": "Too many requests. Please wait a moment."}), 429

    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"success": False, "error": "Missing 'username' parameter."}), 400

    # Clean the username: remove @, instagram.com prefix, trailing slash
    username = re.sub(r"^@?", "", username)
    username = re.sub(r"^https?://(?:www\.)?instagram\.com/", "", username)
    username = username.strip("/").split("/")[0].split("?")[0]
    if not re.match(r"^[A-Za-z0-9_.]{1,30}$", username):
        return jsonify({"success": False, "error": "Invalid username."}), 400

    # Check cache
    cache_key = "profile:" + username.lower()
    cached = cache_get(cache_key)
    if cached is not None:
        out = dict(cached)
        out["_cache"] = "HIT"
        return jsonify(out)

    # Fetch profile page and extract HD profile pic URL
    profile_url = f"https://www.instagram.com/{username}/"
    pic_url = None
    is_private = False

    # Try with curl_cffi (browser-perfect TLS)
    if HAS_CURL_CFFI:
        try:
            s = creq.Session(impersonate="chrome")
            r = s.get(profile_url, timeout=20)
            if r.status_code == 200:
                # Look for hd_profile_pic_url_info in the page JSON
                for blob in re.findall(r'<script type="application/json"[^>]*>(.*?)</script>', r.text, re.S):
                    if 'hd_profile_pic_url_info' in blob or 'profile_pic_url' in blob:
                        try:
                            data = json.loads(blob)
                            def find_pic(obj):
                                if isinstance(obj, dict):
                                    if 'hd_profile_pic_url_info' in obj:
                                        return obj['hd_profile_pic_url_info'].get('url')
                                    if 'profile_pic_url_hd' in obj:
                                        return obj['profile_pic_url_hd']
                                    if 'profile_pic_url' in obj and isinstance(obj['profile_pic_url'], str):
                                        return obj['profile_pic_url']
                                    for v in obj.values():
                                        result = find_pic(v)
                                        if result:
                                            return result
                                elif isinstance(obj, list):
                                    for v in obj:
                                        result = find_pic(v)
                                        if result:
                                            return result
                                return None
                            pic_url = find_pic(data)
                        except Exception:
                            pass
                        if pic_url:
                            break
                if '"is_private":true' in r.text or '"is_private": true' in r.text:
                    is_private = True
            elif r.status_code == 404:
                return jsonify({"success": False, "error": "User not found."}), 404
        except Exception:
            pass

    # Fallback: try with requests
    if not pic_url:
        try:
            sess = gql_session_for()
            r = sess.get(profile_url, timeout=15, allow_redirects=True)
            if r.status_code == 200:
                for blob in re.findall(r'<script type="application/json"[^>]*>(.*?)</script>', r.text, re.S):
                    if 'profile_pic_url' in blob:
                        try:
                            data = json.loads(blob)
                            def find_pic(obj):
                                if isinstance(obj, dict):
                                    if 'hd_profile_pic_url_info' in obj:
                                        return obj['hd_profile_pic_url_info'].get('url')
                                    if 'profile_pic_url_hd' in obj:
                                        return obj['profile_pic_url_hd']
                                    if 'profile_pic_url' in obj and isinstance(obj['profile_pic_url'], str):
                                        return obj['profile_pic_url']
                                    for v in obj.values():
                                        result = find_pic(v)
                                        if result:
                                            return result
                                elif isinstance(obj, list):
                                    for v in obj:
                                        result = find_pic(v)
                                        if result:
                                            return result
                                return None
                            pic_url = find_pic(data)
                        except Exception:
                            pass
                        if pic_url:
                            break
                if '"is_private":true' in r.text or '"is_private": true' in r.text:
                    is_private = True
        except Exception:
            pass

    # Fallback: try the Instagram GraphQL API
    if not pic_url:
        try:
            sess = gql_session_for()
            csrf = ""
            try:
                sess.get("https://www.instagram.com/", timeout=10)
                csrf = sess.cookies.get("csrftoken", domain=".instagram.com") or ""
            except Exception:
                pass
            variables = json.dumps({"username": username})
            r = sess.post(
                GQL_ENDPOINT,
                params={"doc_id": "17888483320059182"},
                data={"variables": variables, "lsd": ""},
                headers={
                    "X-IG-App-ID": GQL_APP_ID,
                    "X-Requested-With": "XMLHttpRequest",
                    "X-CSRFTOKEN": csrf,
                },
                timeout=15,
            )
            j = r.json()
            user = (j.get("data") or {}).get("user") or {}
            pic_url = user.get("profile_pic_url_hd") or user.get("profile_pic_url")
            is_private = user.get("is_private", False)
        except Exception:
            pass

    if not pic_url:
        if is_private:
            return jsonify({"success": False, "error": "This account is private."}), 403
        return jsonify({"success": False, "error": "Could not fetch profile picture. The user may not exist or is private."}), 404

    # Remove size parameters to get the largest version
    pic_url = re.sub(r"s\d+x\d+/", "", pic_url)
    pic_url = re.sub(r"[&?]stp=[^&]*", "", pic_url)
    if "?" not in pic_url and "&" in pic_url:
        pic_url = pic_url.replace("&", "?", 1)

    payload = {
        "success": True,
        "username": username,
        "thumbnail": pic_url,
        "video_url": pic_url,
        "filename": f"{username}-profile.jpg",
        "ext": "jpg",
        "type": "image",
        "title": f"@{username} profile picture",
    }
    cache_set(cache_key, payload, ttl=3600)
    out = dict(payload)
    out["_cache"] = "MISS"
    return jsonify(out)


@app.route("/api/proxy", methods=["GET", "OPTIONS"])
def proxy():
    """Streams the video through Render, forcing a real file download."""
    if request.method == "OPTIONS":
        return ("", 204, cors_headers())

    auth = _require_api_key()
    if auth is not None:
        return auth
    if not _check_rate(RATE_LIMIT_PROXY):
        return jsonify({"success": False, "error": "Too many requests. Please wait a moment."}), 429

    url = (request.args.get("url") or "").strip()
    if not url.startswith("http"):
        return jsonify({"success": False, "error": "Invalid url parameter."}), 400
    if not is_allowed_media_host(url):
        return (
            jsonify({"success": False, "error": "URL host is not an allowed media CDN."}),
            400,
        )

    filename = (request.args.get("filename") or "instagram-video.mp4")
    filename = re.sub(r"[^\w\-.\u0900-\u097F ]", "_", filename).strip()[:80] or "instagram-media"
    if "." not in filename:
        # No usable extension — the frontend normally sends one; fall back to mp4.
        filename += ".mp4"

    headers = {
        "Referer": "https://www.instagram.com/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    range_hdr = request.headers.get("Range")
    if range_hdr:
        headers["Range"] = range_hdr

    cookies = None
    if os.path.exists(COOKIE_FILE):
        try:
            jar = http.cookiejar.MozillaCookieJar(COOKIE_FILE)
            jar.load(ignore_discard=True, ignore_expires=True)
            cookies = jar
        except Exception:  # noqa: BLE001
            cookies = None

    upstream = requests.get(
        url, headers=headers, cookies=cookies, stream=True, timeout=60
    )
    if upstream.status_code not in (200, 206):
        return (
            jsonify({"success": False, "error": f"Upstream returned {upstream.status_code}"}),
            upstream.status_code,
        )

    # File-size limit: reject early when the size is known.
    length_hdr = upstream.headers.get("Content-Length")
    if length_hdr and length_hdr.isdigit() and int(length_hdr) > MAX_FILE_BYTES:
        upstream.close()
        return (
            jsonify({"success": False, "error": "Video file exceeds the size limit."}),
            413,
        )

    sent = 0

    def generate():
        nonlocal sent
        try:
            for chunk in upstream.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                sent += len(chunk)
                if sent > MAX_FILE_BYTES:
                    break
                yield chunk
        finally:
            upstream.close()

    resp = Response(
        generate(),
        status=upstream.status_code,
        content_type=upstream.headers.get("Content-Type", "video/mp4"),
        headers={
            **cors_headers(),
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
    if length_hdr and int(length_hdr) <= MAX_FILE_BYTES:
        resp.headers["Content-Length"] = length_hdr
    if range_hdr and upstream.headers.get("Content-Range"):
        resp.headers["Content-Range"] = upstream.headers["Content-Range"]
    if range_hdr:
        resp.headers["Accept-Ranges"] = "bytes"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)