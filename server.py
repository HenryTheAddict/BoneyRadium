import hashlib
import json
import os
import copy
import re
import mimetypes
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, unquote


HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8765"))
MAX_BODY_BYTES = 64 * 1024
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
RELEASE_DIR = os.path.join(os.path.dirname(__file__), "release")
LOCK = threading.Lock()
SERVER_SECRET = secrets.token_hex(32)
STATE = {
    "users": {},
    "queue": [],
    "matches": {},
    "replays": {},
    "ip_rate": {},
    "stats": {
        "requests": 0,
        "rejected_syncs": 0,
        "matches_created": 0,
        "expired_matches": 0,
    },
}


def now():
    return int(time.time())


def normalize_text(value, fallback="", max_length=24):
    cleaned = "".join(ch if ch.isalnum() or ch in " -_!?." else " " for ch in str(value or ""))
    cleaned = " ".join(cleaned.split()).strip()
    return (cleaned or fallback)[:max_length]


def normalize_color(value):
    text = str(value or "").strip()
    if len(text) == 7 and text.startswith("#") and all(ch in "0123456789abcdefABCDEF" for ch in text[1:]):
        return text.lower()
    return "#66d6ff"


def json_response(handler, status_code, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def html_response(handler, html):
    body = html.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
    handler.end_headers()
    handler.wfile.write(body)


def get_user(username):
    username = normalize_text(username, "")
    if not username:
        return None
    user = STATE["users"].get(username)
    if not user:
        user = {
            "username": username,
            "title": "",
            "accent": "#66d6ff",
            "wins": 0,
            "games": 0,
            "friends": set(),
            "last_seen": 0,
            "pending_match_id": None,
        }
        STATE["users"][username] = user
    return user


def is_online(user):
    return now() - user["last_seen"] <= 35


def public_profile(user):
    return {
        "username": user["username"],
        "title": user["title"],
        "accent": user["accent"],
        "online": is_online(user),
    }


def make_signature(match_id, seq, state):
    packed = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{SERVER_SECRET}:{match_id}:{seq}:{packed}".encode("utf-8")).hexdigest()


def release_match_players(match):
    p1_user = get_user(match["players"]["p1"])
    p2_user = get_user(match["players"]["p2"])
    p1_user["pending_match_id"] = None
    p2_user["pending_match_id"] = None
    return p1_user, p2_user


def finalize_match(match, reason):
    replay_id = secrets.token_hex(10)
    match["ended_at"] = now()
    match["replay_id"] = replay_id
    replay_payload = {
        "id": replay_id,
        "matchId": match["id"],
        "players": copy.deepcopy(match["players"]),
        "endedAt": match["ended_at"],
        "reason": reason,
        "frames": copy.deepcopy(match.get("state_history", [])),
        "chat": copy.deepcopy(match.get("chat_messages", [])),
        "reactions": copy.deepcopy(match.get("reactions", [])),
        "finalState": copy.deepcopy(match.get("state")),
    }
    STATE["replays"][replay_id] = replay_payload
    if len(STATE["replays"]) > 250:
        oldest_id = min(STATE["replays"], key=lambda rid: STATE["replays"][rid]["endedAt"])
        del STATE["replays"][oldest_id]
    return replay_id


def clamp_chat_message(message):
    cleaned = normalize_text(message, "", 120)
    return cleaned[:120]


def release_downloads():
    manifest_path = os.path.join(RELEASE_DIR, "releases.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as release_file:
                payload = json.load(release_file)
                records = payload.get("releases", [])
                safe_records = []
                for entry in records:
                    filename = os.path.basename(str(entry.get("filename", "")))
                    full_path = os.path.join(RELEASE_DIR, filename)
                    if not filename or not os.path.exists(full_path):
                        continue
                    safe_records.append({
                        "version": str(entry.get("version", "")),
                        "platform": str(entry.get("platform", "")),
                        "arch": str(entry.get("arch", "x64")),
                        "filename": filename,
                        "channel": str(entry.get("channel", "stable")),
                        "notes": str(entry.get("notes", ""))[:160],
                        "sizeBytes": os.path.getsize(full_path),
                        "url": f"/release/{filename}",
                    })
                return safe_records
        except (OSError, json.JSONDecodeError):
            return []

    if not os.path.exists(RELEASE_DIR):
        return []

    regexes = [
        (re.compile(r"^BoneyRadium-(\d+\.\d+\.\d+)\.dmg$"), "mac"),
        (re.compile(r"^BoneyRadium-(\d+\.\d+\.\d+)-mac\.zip$"), "mac"),
        (re.compile(r"^BoneyRadium-(\d+\.\d+\.\d+)-win\.zip$"), "win"),
        (re.compile(r"^BoneyRadium-(\d+\.\d+\.\d+)\.AppImage$"), "linux"),
    ]
    entries = []
    for filename in os.listdir(RELEASE_DIR):
        for regex, platform in regexes:
            matched = regex.match(filename)
            if matched:
                full_path = os.path.join(RELEASE_DIR, filename)
                if not os.path.isfile(full_path):
                    continue
                entries.append({
                    "version": matched.group(1),
                    "platform": platform,
                    "arch": "x64",
                    "filename": filename,
                    "channel": "stable",
                    "notes": "",
                    "sizeBytes": os.path.getsize(full_path),
                    "url": f"/release/{filename}",
                })
                break
    return entries


def send_static_release_file(handler, filename):
    safe_name = os.path.basename(unquote(filename))
    if safe_name != filename or not safe_name:
        json_response(handler, 400, {"ok": False, "error": "invalid filename"})
        return
    file_path = os.path.join(RELEASE_DIR, safe_name)
    if not os.path.isfile(file_path):
        json_response(handler, 404, {"ok": False, "error": "file not found"})
        return

    mime, _ = mimetypes.guess_type(file_path)
    content_type = mime or "application/octet-stream"
    with open(file_path, "rb") as binary_file:
        binary = binary_file.read()

    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(binary)))
    handler.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
    handler.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(binary)


def is_safe_id(value, min_len=8, max_len=64):
    text = str(value or "").strip()
    if not (min_len <= len(text) <= max_len):
        return False
    return all(ch in "0123456789abcdef" for ch in text)


def is_safe_token(value):
    text = str(value or "").strip()
    if not (16 <= len(text) <= 64):
        return False
    return all(ch in "0123456789abcdef" for ch in text)


def check_ip_rate_limit(ip, bucket, limit, window_seconds):
    now_ts = time.time()
    key = f"{ip}:{bucket}"
    entry = STATE["ip_rate"].get(key, {"count": 0, "reset_at": now_ts + window_seconds})
    if now_ts > entry["reset_at"]:
        entry = {"count": 0, "reset_at": now_ts + window_seconds}
    entry["count"] += 1
    STATE["ip_rate"][key] = entry
    return entry["count"] <= limit


def prune_queue():
    fresh_queue = []
    for username in STATE["queue"]:
        user = get_user(username)
        if user and is_online(user) and not user["pending_match_id"]:
            fresh_queue.append(username)
    STATE["queue"] = fresh_queue


def prune_stale_matches():
    stale_ids = []
    now_ts = now()
    for match_id, match in STATE["matches"].items():
        if match.get("quit_by"):
            continue
        age = now_ts - int(match.get("updated_at", now_ts))
        if age > 900:
            stale_ids.append(match_id)

    for match_id in stale_ids:
        match = STATE["matches"][match_id]
        match["quit_by"] = "server_timeout"
        match["updated_at"] = now_ts
        release_match_players(match)
        finalize_match(match, "timeout")
        STATE["stats"]["expired_matches"] += 1


def match_payload_for(username, match):
    if match["players"]["p1"] == username:
        player_key = "p1"
        opponent_name = match["players"]["p2"]
    else:
        player_key = "p2"
        opponent_name = match["players"]["p1"]
    opponent = public_profile(get_user(opponent_name))
    return {
        "ok": True,
        "status": "matched",
        "matchId": match["id"],
        "playerKey": player_key,
        "token": match["tokens"][player_key],
        "opponent": opponent,
        "seq": match["seq"],
        "signature": match["signature"],
        "lastReactionId": match.get("last_reaction_id"),
        "lastChatId": match.get("last_chat_id"),
        "replayId": match.get("replay_id"),
    }


def create_match(p1_name, p2_name):
    match_id = secrets.token_hex(8)
    match = {
        "id": match_id,
        "created_at": now(),
        "updated_at": now(),
        "players": {"p1": p1_name, "p2": p2_name},
        "tokens": {"p1": secrets.token_hex(16), "p2": secrets.token_hex(16)},
        "state": None,
        "seq": 0,
        "signature": "",
        "show_turn_banner": False,
        "reactions": [],
        "last_reaction_id": None,
        "chat_messages": [],
        "last_chat_id": None,
        "state_history": [],
        "rate_limit": {"p1": {"reaction_at": 0, "chat_at": 0}, "p2": {"reaction_at": 0, "chat_at": 0}},
        "quit_by": None,
        "replay_id": None,
    }
    STATE["matches"][match_id] = match
    get_user(p1_name)["pending_match_id"] = match_id
    get_user(p2_name)["pending_match_id"] = match_id
    STATE["stats"]["matches_created"] += 1
    return match


def validate_state(match, actor_key, candidate_state, anti_cheat_mode):
    if not isinstance(candidate_state, dict):
        return False, "invalid state payload"
    players = candidate_state.get("players")
    if not isinstance(players, list) or len(players) != 2:
        return False, "state must have two players"
    if candidate_state.get("currentTurn") not in ("p1", "p2"):
        return False, "invalid current turn"

    seen_ids = set()
    hp_delta_limit = 350 if anti_cheat_mode == "strict" else 550

    for index, player in enumerate(players):
        expected_key = f"p{index + 1}"
        if player.get("key") != expected_key:
            return False, "player keys are corrupted"
        if not isinstance(player.get("label"), str) or len(player.get("label", "")) > 30:
            return False, "invalid player label"
        if player.get("selected") and not isinstance(player.get("selected"), str):
            return False, "invalid selected card id"
        hp = int(player.get("hp", 0))
        max_hp = int(player.get("maxHp", 0))
        if hp < 0 or max_hp < 1 or hp > max_hp:
            return False, "hp out of range"
        extra_turns = int(player.get("extraTurns", 0))
        if extra_turns < 0 or extra_turns > 5:
            return False, "invalid extra turn value"
        poison_rounds = int(player.get("poisonRounds", 0))
        poison_damage = int(player.get("poisonDamage", 0))
        if poison_rounds < 0 or poison_rounds > 8 or poison_damage < 0 or poison_damage > 600:
            return False, "invalid poison values"
        if int(player.get("handSize", 0)) < 1 or int(player.get("handSize", 0)) > 5:
            return False, "illegal hand size"
        hand = player.get("hand", [])
        if not isinstance(hand, list) or len(hand) > 5:
            return False, "illegal hand payload"
        if int(player.get("handSize", 0)) != len(hand):
            return False, "hand size does not match cards"
        hand_ids = set()
        for card in hand:
            card_id = str(card.get("id", ""))
            if not card_id or card_id in seen_ids:
                return False, "duplicate or missing card ids"
            if card_id in hand_ids:
                return False, "duplicate card in hand"
            hand_ids.add(card_id)
            seen_ids.add(card_id)
            card_src = str(card.get("src", ""))
            card_name = str(card.get("name", ""))
            fade_level = int(card.get("fadeLevel", 0))
            if not card_src.startswith("Assets/Cards/") or not card_src.endswith(".png"):
                return False, "illegal card source"
            if len(card_name) > 40:
                return False, "illegal card name"
            if fade_level < 0 or fade_level > 3:
                return False, "illegal card fade level"
        selected_id = player.get("selected")
        if selected_id and selected_id not in hand_ids:
            return False, "selected card not in hand"

    previous_state = match["state"]
    if previous_state is None:
        return actor_key == "p1", "only host can initialize the match"

    if previous_state.get("currentTurn") != actor_key:
        return False, "out of turn update rejected"

    previous_players = previous_state["players"]
    for index, previous_player in enumerate(previous_players):
        current_player = players[index]
        if int(current_player["maxHp"]) != int(previous_player["maxHp"]):
            return False, "max hp changed illegally"
        hp_delta = abs(int(current_player["hp"]) - int(previous_player["hp"]))
        if hp_delta > hp_delta_limit:
            return False, "hp delta exceeded anti-cheat limits"
        hand_delta = abs(len(current_player["hand"]) - len(previous_player["hand"]))
        if hand_delta > 2:
            return False, "hand delta exceeded anti-cheat limits"
        previous_by_id = {str(card.get("id", "")): card for card in previous_player.get("hand", [])}
        for card in current_player.get("hand", []):
            card_id = str(card.get("id", ""))
            if card_id in previous_by_id:
                old_card = previous_by_id[card_id]
                if str(card.get("src", "")) != str(old_card.get("src", "")):
                    return False, "card source tampering detected"
                if str(card.get("name", "")) != str(old_card.get("name", "")):
                    return False, "card name tampering detected"

    previous_actor = next(player for player in previous_players if player["key"] == actor_key)
    if candidate_state["currentTurn"] == actor_key and int(previous_actor.get("extraTurns", 0)) <= 0:
        return False, "turn did not advance legally"
    return True, ""


def server_stats_html():
    with LOCK:
        users = list(STATE["users"].values())
        matches = list(STATE["matches"].values())
        queue_size = len(STATE["queue"])
        online_users = sum(1 for user in users if is_online(user))
        total_users = len(users)
        active_matches = sum(1 for match in matches if match["state"] is not None)
        rejected = STATE["stats"]["rejected_syncs"]
        requests = STATE["stats"]["requests"]
        created = STATE["stats"]["matches_created"]

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BoneyRadium Server Stats</title>
  <style>
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: Inter, system-ui, sans-serif;
      background: radial-gradient(circle at top, #bfe9ff, #edf6ff 40%, #d9e2ff 100%);
      color: #0c2238;
      display: grid;
      place-items: center;
      padding: 22px;
      box-sizing: border-box;
    }}
    .panel {{
      width: min(980px, 96vw);
      background: rgba(255,255,255,0.78);
      backdrop-filter: blur(18px);
      border: 1px solid rgba(255,255,255,0.65);
      border-radius: 28px;
      padding: 32px;
      box-shadow: 0 24px 80px rgba(32, 76, 126, 0.18);
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-top: 24px;
    }}
    .card {{
      padding: 18px;
      border-radius: 20px;
      background: linear-gradient(180deg, rgba(255,255,255,0.95), rgba(223,239,255,0.85));
      border: 1px solid rgba(141,181,226,0.5);
    }}
    .label {{
      font-size: 0.9rem;
      opacity: 0.7;
      margin-bottom: 8px;
    }}
    .value {{
      font-size: 2rem;
      font-weight: 800;
    }}
    .downloader {{
      margin-top: 26px;
      border-radius: 22px;
      border: 1px solid rgba(141,181,226,0.5);
      background: rgba(255,255,255,0.76);
      padding: 16px;
    }}
    .controls {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }}
    .controls label {{
      font-size: 0.8rem;
      opacity: 0.7;
      margin-bottom: 4px;
      display: block;
    }}
    .controls select {{
      width: 100%;
      border-radius: 10px;
      border: 1px solid #a2c4e7;
      background: #fff;
      padding: 0.5rem;
      font: inherit;
    }}
    .release-list {{
      display: grid;
      gap: 8px;
    }}
    .release-item {{
      display: grid;
      grid-template-columns: 1.3fr 1fr 0.7fr auto;
      align-items: center;
      gap: 8px;
      padding: 10px;
      border-radius: 12px;
      border: 1px solid rgba(141,181,226,0.5);
      background: rgba(255,255,255,0.9);
    }}
    .badge {{
      font-size: 0.75rem;
      border-radius: 999px;
      padding: 0.25rem 0.6rem;
      font-weight: 700;
      justify-self: start;
      background: #e9f5ff;
      color: #15538f;
    }}
    .badge.upgrade {{ background: #def7e6; color: #0f6a32; }}
    .badge.downgrade {{ background: #ffe5e5; color: #8b1a1a; }}
    .download-btn {{
      border: none;
      border-radius: 10px;
      background: #0b61ff;
      color: #fff;
      font-weight: 700;
      padding: 0.5rem 0.85rem;
      cursor: pointer;
      text-decoration: none;
      text-align: center;
    }}
    .release-meta {{
      font-size: 0.85rem;
      opacity: 0.75;
    }}
    a {{
      color: #0b61ff;
    }}
    @media (max-width: 780px) {{
      .controls {{
        grid-template-columns: 1fr;
      }}
      .release-item {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="panel">
    <h1>BoneyRadium Server Stats</h1>
    <p>Public API JSON is available at <a href="/api/stats">/api/stats</a>.</p>
    <section class="grid">
      <div class="card"><div class="label">Online Users</div><div class="value">{online_users}</div></div>
      <div class="card"><div class="label">Registered Users</div><div class="value">{total_users}</div></div>
      <div class="card"><div class="label">Queue Size</div><div class="value">{queue_size}</div></div>
      <div class="card"><div class="label">Active Matches</div><div class="value">{active_matches}</div></div>
      <div class="card"><div class="label">Matches Created</div><div class="value">{created}</div></div>
      <div class="card"><div class="label">Rejected Syncs</div><div class="value">{rejected}</div></div>
      <div class="card"><div class="label">Requests Served</div><div class="value">{requests}</div></div>
    </section>
    <section class="downloader">
      <h2 style="margin: 4px 0 10px;">Downloads</h2>
      <div class="controls">
        <div>
          <label for="platform-filter">System</label>
          <select id="platform-filter">
            <option value="all">All</option>
            <option value="mac">macOS</option>
            <option value="win">Windows</option>
            <option value="linux">Linux</option>
          </select>
        </div>
        <div>
          <label for="version-sort">Version Sort</label>
          <select id="version-sort">
            <option value="desc">Newest First</option>
            <option value="asc">Oldest First</option>
          </select>
        </div>
        <div>
          <label for="current-version">Your Version</label>
          <select id="current-version">
            <option value="">Unknown</option>
          </select>
        </div>
      </div>
      <div id="release-list" class="release-list"></div>
    </section>
  </main>
  <script>
    const compareSemver = (a, b) => {{
      const aParts = a.split('.').map(Number);
      const bParts = b.split('.').map(Number);
      for (let i = 0; i < 3; i++) {{
        const diff = (aParts[i] || 0) - (bParts[i] || 0);
        if (diff !== 0) return diff;
      }}
      return 0;
    }};

    const fmtSize = (bytes) => {{
      if (!Number.isFinite(bytes) || bytes <= 0) return 'Unknown size';
      const units = ['B', 'KB', 'MB', 'GB'];
      let value = bytes;
      let idx = 0;
      while (value >= 1024 && idx < units.length - 1) {{
        value /= 1024;
        idx += 1;
      }}
      return `${{value.toFixed(idx === 0 ? 0 : 1)}} ${{units[idx]}}`;
    }};

    const listEl = document.getElementById('release-list');
    const platformFilter = document.getElementById('platform-filter');
    const versionSort = document.getElementById('version-sort');
    const currentVersion = document.getElementById('current-version');
    let releases = [];

    const render = () => {{
      const platform = platformFilter.value;
      const sortDirection = versionSort.value;
      const current = currentVersion.value;
      const filtered = releases
        .filter((entry) => platform === 'all' || entry.platform === platform)
        .sort((left, right) => {{
          const cmp = compareSemver(left.version, right.version);
          return sortDirection === 'asc' ? cmp : -cmp;
        }});

      if (!filtered.length) {{
        listEl.innerHTML = '<div class="release-item"><div>No builds for this filter yet.</div></div>';
        return;
      }}

      listEl.innerHTML = filtered.map((entry) => {{
        let badgeText = 'Install';
        let badgeClass = '';
        if (current) {{
          const cmp = compareSemver(entry.version, current);
          if (cmp > 0) {{
            badgeText = 'Upgrade';
            badgeClass = 'upgrade';
          }} else if (cmp < 0) {{
            badgeText = 'Downgrade';
            badgeClass = 'downgrade';
          }} else {{
            badgeText = 'Current';
          }}
        }}
        const platformName = entry.platform === 'mac' ? 'macOS' : entry.platform === 'win' ? 'Windows' : 'Linux';
        return `
          <div class="release-item">
            <div>
              <div style="font-weight: 800;">${{entry.filename}}</div>
              <div class="release-meta">${{platformName}} • v${{entry.version}} • ${{fmtSize(entry.sizeBytes)}}</div>
            </div>
            <span class="badge ${{badgeClass}}">${{badgeText}}</span>
            <div class="release-meta">${{entry.channel || 'stable'}}</div>
            <a class="download-btn" href="${{entry.url}}">Download</a>
          </div>
        `;
      }}).join('');
    }};

    const setupVersions = () => {{
      const versions = [...new Set(releases.map((entry) => entry.version))]
        .sort((a, b) => -compareSemver(a, b));
      currentVersion.innerHTML = '<option value="">Unknown</option>' + versions.map((ver) => `<option value="${{ver}}">${{ver}}</option>`).join('');
      if (versions.length) {{
        currentVersion.value = versions[0];
      }}
    }};

    Promise.resolve(fetch('/api/releases').then((res) => res.json()))
      .then((payload) => {{
        releases = Array.isArray(payload.releases) ? payload.releases : [];
        setupVersions();
        render();
      }})
      .catch(() => {{
        listEl.innerHTML = '<div class="release-item"><div>Failed to load releases.</div></div>';
      }});

    platformFilter.addEventListener('change', render);
    versionSort.addEventListener('change', render);
    currentVersion.addEventListener('change', render);
  </script>
</body>
</html>"""


class BoneyRadiumHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            self._body_error = "invalid content length"
            return {}
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            self._body_error = "payload too large"
            return {}
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            self._body_error = "content-type must be application/json"
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._body_error = "invalid json payload"
            return {}

    def _query(self):
        parsed = urlparse(self.path)
        return parsed.path, {key: values[0] for key, values in parse_qs(parsed.query).items()}

    def do_OPTIONS(self):
        json_response(self, 200, {"ok": True})

    def do_GET(self):
        ip = self.client_address[0] if self.client_address else "unknown"
        with LOCK:
            if not check_ip_rate_limit(ip, "get", 180, 60):
                json_response(self, 429, {"ok": False, "error": "rate limit"})
                return
            STATE["stats"]["requests"] += 1
            prune_stale_matches()
        path, query = self._query()

        if path == "/stats":
            html_response(self, server_stats_html())
            return

        if path == "/api/stats":
            with LOCK:
                users = list(STATE["users"].values())
                matches = list(STATE["matches"].values())
                payload = {
                    "ok": True,
                    "onlineUsers": sum(1 for user in users if is_online(user)),
                    "registeredUsers": len(users),
                    "queueSize": len(STATE["queue"]),
                    "activeMatches": sum(1 for match in matches if match["state"] is not None),
                    "rejectedSyncs": STATE["stats"]["rejected_syncs"],
                    "matchesCreated": STATE["stats"]["matches_created"],
                    "expiredMatches": STATE["stats"]["expired_matches"],
                    "replaysStored": len(STATE["replays"]),
                    "requestsServed": STATE["stats"]["requests"],
                }
            json_response(self, 200, payload)
            return

        if path == "/api/releases":
            json_response(self, 200, {"ok": True, "releases": release_downloads()})
            return

        if path.startswith("/release/"):
            filename = path.split("/release/")[1]
            send_static_release_file(self, filename)
            return

        if path == "/api/friends":
            username = normalize_text(query.get("username", ""))
            with LOCK:
                user = get_user(username)
                friends = []
                if user:
                    for friend_name in sorted(user["friends"]):
                        friends.append(public_profile(get_user(friend_name)))
            json_response(self, 200, {"ok": True, "friends": friends})
            return

        if path == "/api/matchmaking/status":
            username = normalize_text(query.get("username", ""))
            with LOCK:
                prune_queue()
                user = get_user(username)
                if user and user["pending_match_id"]:
                    match = STATE["matches"].get(user["pending_match_id"])
                    if match:
                        json_response(self, 200, match_payload_for(username, match))
                        return
                queue_size = len(STATE["queue"])
            json_response(self, 200, {"ok": True, "status": "queued", "queueSize": queue_size})
            return

        if path.startswith("/api/matches/") and path.endswith("/state"):
            parts = path.strip("/").split("/")
            match_id = parts[2]
            player_key = query.get("playerKey", "")
            token = query.get("token", "")
            if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
                json_response(self, 400, {"ok": False, "error": "invalid match credentials"})
                return
            with LOCK:
                match = STATE["matches"].get(match_id)
                if not match or match["tokens"].get(player_key) != token:
                    json_response(self, 403, {"ok": False, "error": "unauthorized"})
                    return
                username = match["players"][player_key]
                payload = {
                    "ok": True,
                    "seq": match["seq"],
                    "signature": match["signature"],
                    "state": match["state"],
                    "showTurnBanner": match["show_turn_banner"],
                    "reactions": match.get("reactions", []),
                    "chatMessages": match.get("chat_messages", []),
                    "lastChatId": match.get("last_chat_id"),
                    "quitBy": match.get("quit_by"),
                    "replayId": match.get("replay_id"),
                    "opponent": public_profile(get_user(match["players"]["p1" if player_key == "p2" else "p2"])),
                    "you": username,
                }
            json_response(self, 200, payload)
            return

        if path.startswith("/api/replays/"):
            replay_id = path.split("/api/replays/")[1].strip("/")
            if not is_safe_id(replay_id, 8, 64):
                json_response(self, 404, {"ok": False, "error": "not found"})
                return
            with LOCK:
                replay = STATE["replays"].get(replay_id)
                if not replay:
                    json_response(self, 404, {"ok": False, "error": "replay not found"})
                    return
                payload = {"ok": True, "replay": replay}
            json_response(self, 200, payload)
            return

        json_response(self, 404, {"ok": False, "error": "not found"})

    def do_POST(self):
        ip = self.client_address[0] if self.client_address else "unknown"
        with LOCK:
            if not check_ip_rate_limit(ip, "post", 240, 60):
                json_response(self, 429, {"ok": False, "error": "rate limit"})
                return
            STATE["stats"]["requests"] += 1
            prune_stale_matches()
        self._body_error = None
        path, _ = self._query()
        body = self._body()
        if self._body_error:
            json_response(self, 400, {"ok": False, "error": self._body_error})
            return

        if path == "/api/heartbeat":
            username = normalize_text(body.get("username", ""))
            if not username:
                json_response(self, 400, {"ok": False, "error": "username required"})
                return
            with LOCK:
                user = get_user(username)
                user["title"] = normalize_text(body.get("title", ""), "", 32)
                user["accent"] = normalize_color(body.get("accent", "#66d6ff"))
                user["last_seen"] = now()
            json_response(self, 200, {"ok": True})
            return

        if path == "/api/friends/add":
            username = normalize_text(body.get("username", ""))
            friend_name = normalize_text(body.get("friend", ""))
            if not username or not friend_name:
                json_response(self, 400, {"ok": False, "error": "username and friend are required"})
                return
            with LOCK:
                user = get_user(username)
                friend = get_user(friend_name)
                user["friends"].add(friend_name)
                friend["friends"].add(username)
            json_response(self, 200, {"ok": True})
            return

        if path == "/api/matchmaking/join":
            username = normalize_text(body.get("username", ""))
            if not username:
                json_response(self, 400, {"ok": False, "error": "username required"})
                return
            with LOCK:
                prune_queue()
                user = get_user(username)
                user["title"] = normalize_text(body.get("title", ""), "", 32)
                user["accent"] = normalize_color(body.get("accent", "#66d6ff"))
                user["last_seen"] = now()
                if user["pending_match_id"]:
                    match = STATE["matches"].get(user["pending_match_id"])
                    if match:
                        json_response(self, 200, match_payload_for(username, match))
                        return
                if username in STATE["queue"]:
                    json_response(self, 200, {"ok": True, "status": "queued", "queueSize": len(STATE["queue"])})
                    return

                waiting_opponent = next((name for name in STATE["queue"] if name != username), None)
                if waiting_opponent:
                    STATE["queue"] = [name for name in STATE["queue"] if name != waiting_opponent]
                    match = create_match(waiting_opponent, username)
                    json_response(self, 200, match_payload_for(username, match))
                    return

                STATE["queue"].append(username)
                json_response(self, 200, {"ok": True, "status": "queued", "queueSize": len(STATE["queue"])})
                return

        if path == "/api/matchmaking/cancel":
            username = normalize_text(body.get("username", ""))
            with LOCK:
                STATE["queue"] = [name for name in STATE["queue"] if name != username]
            json_response(self, 200, {"ok": True})
            return

        if path.startswith("/api/matches/") and path.endswith("/sync"):
            parts = path.strip("/").split("/")
            match_id = parts[2]
            player_key = body.get("playerKey", "")
            token = body.get("token", "")
            previous_signature = body.get("previousSignature", "")
            submitted_seq = body.get("seq")
            anti_cheat = body.get("antiCheat", "strict")
            candidate_state = body.get("state")
            show_turn_banner = bool(body.get("showTurnBanner", False))
            if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
                json_response(self, 400, {"ok": False, "error": "invalid match credentials"})
                return
            if not isinstance(submitted_seq, int) or submitted_seq < 0:
                json_response(self, 400, {"ok": False, "error": "invalid sync sequence"})
                return
            if previous_signature and not is_safe_id(previous_signature, 20, 80):
                json_response(self, 400, {"ok": False, "error": "invalid signature format"})
                return

            with LOCK:
                match = STATE["matches"].get(match_id)
                if not match or match["tokens"].get(player_key) != token:
                    json_response(self, 403, {"ok": False, "error": "unauthorized"})
                    return
                if match.get("quit_by"):
                    json_response(self, 409, {"ok": False, "error": "match has ended"})
                    return
                if match["signature"] and previous_signature != match["signature"]:
                    STATE["stats"]["rejected_syncs"] += 1
                    json_response(self, 409, {"ok": False, "error": "stale signature"})
                    return
                if submitted_seq != match["seq"]:
                    STATE["stats"]["rejected_syncs"] += 1
                    json_response(self, 409, {"ok": False, "error": "out-of-sync sequence"})
                    return
                valid, reason = validate_state(match, player_key, candidate_state, anti_cheat)
                if not valid:
                    STATE["stats"]["rejected_syncs"] += 1
                    json_response(self, 422, {"ok": False, "error": reason})
                    return

                match["state"] = candidate_state
                match["seq"] += 1
                match["updated_at"] = now()
                match["show_turn_banner"] = show_turn_banner
                match["signature"] = make_signature(match_id, match["seq"], candidate_state)
                match["state_history"].append({
                    "seq": match["seq"],
                    "state": copy.deepcopy(candidate_state),
                    "showTurnBanner": show_turn_banner,
                    "at": now(),
                })
                if len(match["state_history"]) > 500:
                    match["state_history"] = match["state_history"][-500:]
                players = candidate_state["players"]
                if players[0]["hp"] <= 0 or players[1]["hp"] <= 0:
                    p1_user, p2_user = release_match_players(match)
                    p1_user["games"] += 1
                    p2_user["games"] += 1
                    if players[0]["hp"] > players[1]["hp"]:
                        p1_user["wins"] += 1
                    elif players[1]["hp"] > players[0]["hp"]:
                        p2_user["wins"] += 1
                    finalize_match(match, "death")

            json_response(self, 200, {"ok": True, "seq": match["seq"], "signature": match["signature"], "replayId": match.get("replay_id")})
            return

        if path.startswith("/api/matches/") and path.endswith("/reaction"):
            parts = path.strip("/").split("/")
            match_id = parts[2]
            player_key = body.get("playerKey", "")
            token = body.get("token", "")
            message = str(body.get("message", "")).strip()[:8]
            allowed_reactions = {"🔥", "💀", "😅", "👏", "😈"}
            if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
                json_response(self, 400, {"ok": False, "error": "invalid match credentials"})
                return

            with LOCK:
                match = STATE["matches"].get(match_id)
                if not match or match["tokens"].get(player_key) != token:
                    json_response(self, 403, {"ok": False, "error": "unauthorized"})
                    return
                if match.get("quit_by"):
                    json_response(self, 409, {"ok": False, "error": "match has ended"})
                    return
                if message not in allowed_reactions:
                    json_response(self, 400, {"ok": False, "error": "invalid reaction"})
                    return
                now_ts = now()
                if now_ts - match["rate_limit"][player_key]["reaction_at"] < 1:
                    json_response(self, 429, {"ok": False, "error": "reaction rate limit"})
                    return
                reaction_id = secrets.token_hex(6)
                reaction = {
                    "id": reaction_id,
                    "playerKey": player_key,
                    "message": message,
                    "at": now_ts,
                }
                match["reactions"].append(reaction)
                match["last_reaction_id"] = reaction_id
                match["rate_limit"][player_key]["reaction_at"] = now_ts
                match["updated_at"] = now_ts
                if len(match["reactions"]) > 40:
                    match["reactions"] = match["reactions"][-40:]
            json_response(self, 200, {"ok": True, "lastReactionId": reaction_id})
            return

        if path.startswith("/api/matches/") and path.endswith("/chat"):
            parts = path.strip("/").split("/")
            match_id = parts[2]
            player_key = body.get("playerKey", "")
            token = body.get("token", "")
            raw_message = body.get("message", "")
            message = clamp_chat_message(raw_message)
            if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
                json_response(self, 400, {"ok": False, "error": "invalid match credentials"})
                return

            with LOCK:
                match = STATE["matches"].get(match_id)
                if not match or match["tokens"].get(player_key) != token:
                    json_response(self, 403, {"ok": False, "error": "unauthorized"})
                    return
                if match.get("quit_by"):
                    json_response(self, 409, {"ok": False, "error": "match has ended"})
                    return
                if not message:
                    json_response(self, 400, {"ok": False, "error": "message required"})
                    return
                now_ts = now()
                if now_ts - match["rate_limit"][player_key]["chat_at"] < 1:
                    json_response(self, 429, {"ok": False, "error": "chat rate limit"})
                    return
                chat_id = secrets.token_hex(6)
                chat_message = {
                    "id": chat_id,
                    "playerKey": player_key,
                    "message": message,
                    "at": now_ts,
                }
                match["chat_messages"].append(chat_message)
                match["last_chat_id"] = chat_id
                match["rate_limit"][player_key]["chat_at"] = now_ts
                match["updated_at"] = now_ts
                if len(match["chat_messages"]) > 80:
                    match["chat_messages"] = match["chat_messages"][-80:]
            json_response(self, 200, {"ok": True, "lastChatId": chat_id})
            return

        if path.startswith("/api/matches/") and path.endswith("/quit"):
            parts = path.strip("/").split("/")
            match_id = parts[2]
            player_key = body.get("playerKey", "")
            token = body.get("token", "")
            if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
                json_response(self, 400, {"ok": False, "error": "invalid match credentials"})
                return

            with LOCK:
                match = STATE["matches"].get(match_id)
                if not match or match["tokens"].get(player_key) != token:
                    json_response(self, 403, {"ok": False, "error": "unauthorized"})
                    return
                match["quit_by"] = player_key
                match["updated_at"] = now()
                release_match_players(match)
                replay_id = finalize_match(match, "quit")

            json_response(self, 200, {"ok": True, "replayId": replay_id})
            return

        json_response(self, 404, {"ok": False, "error": "not found"})


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), BoneyRadiumHandler)
    print(f"BoneyRadium server running on http://127.0.0.1:{PORT}")
    server.serve_forever()
