import json
import secrets
import copy
import os
import mimetypes
from urllib.parse import parse_qs

from server import (
    MAX_BODY_BYTES,
    ALLOWED_ORIGIN,
    LOCK,
    STATE,
    create_match,
    check_ip_rate_limit,
    get_user,
    is_safe_id,
    is_safe_token,
    is_online,
    make_signature,
    match_payload_for,
    release_downloads,
    RELEASE_DIR,
    sanitize_presence_payload,
    touch_user_presence,
    ensure_match_not_disconnected,
    normalize_color,
    clamp_chat_message,
    normalize_text,
    now,
    prune_queue,
    prune_stale_matches,
    public_profile,
    release_match_players,
    finalize_match,
    server_stats_html,
    validate_state,
)


def _json(status_code, payload):
    body = json.dumps(payload).encode("utf-8")
    return status_code, "application/json", body


def _html(status_code, payload):
    body = payload.encode("utf-8")
    return status_code, "text/html; charset=utf-8", body


def _binary(status_code, content_type, payload):
    return status_code, content_type, payload


def _route(method, path, query, body, remote_ip):
    with LOCK:
        if not check_ip_rate_limit(remote_ip, f"wsgi:{method.lower()}", 220 if method == "GET" else 260, 60):
            return _json(429, {"ok": False, "error": "rate limit"})
        STATE["stats"]["requests"] += 1
        prune_stale_matches()

    if method == "GET" and path in {"/", "/stats"}:
        return _html(200, server_stats_html())

    if method == "GET" and path == "/api/stats":
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
        return _json(200, payload)

    if method == "GET" and path == "/api/releases":
        return _json(200, {"ok": True, "releases": release_downloads()})

    if method == "GET" and path.startswith("/release/"):
        filename = path.split("/release/")[1]
        safe_name = os.path.basename(filename)
        if not safe_name or safe_name != filename:
            return _json(400, {"ok": False, "error": "invalid filename"})
        file_path = os.path.join(RELEASE_DIR, safe_name)
        if not os.path.isfile(file_path):
            return _json(404, {"ok": False, "error": "file not found"})
        with open(file_path, "rb") as file_obj:
            binary = file_obj.read()
        mime_type, _ = mimetypes.guess_type(file_path)
        return _binary(200, mime_type or "application/octet-stream", binary)

    if method == "GET" and path == "/api/friends":
        username = normalize_text(query.get("username", ""))
        with LOCK:
            user = get_user(username)
            friends = []
            if user:
                for friend_name in sorted(user["friends"]):
                    friends.append(public_profile(get_user(friend_name)))
        return _json(200, {"ok": True, "friends": friends})

    if method == "GET" and path == "/api/matchmaking/status":
        username = normalize_text(query.get("username", ""))
        with LOCK:
            prune_queue()
            user = get_user(username)
            if user and user["pending_match_id"]:
                match = STATE["matches"].get(user["pending_match_id"])
                if match:
                    return _json(200, match_payload_for(username, match))
            queue_size = len(STATE["queue"])
        return _json(200, {"ok": True, "status": "queued", "queueSize": queue_size})

    if method == "GET" and path.startswith("/api/matches/") and path.endswith("/state"):
        parts = path.strip("/").split("/")
        match_id = parts[2]
        player_key = query.get("playerKey", "")
        token = query.get("token", "")
        if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
            return _json(400, {"ok": False, "error": "invalid match credentials"})
        with LOCK:
            match = STATE["matches"].get(match_id)
            if not match or match["tokens"].get(player_key) != token:
                return _json(403, {"ok": False, "error": "unauthorized"})
            username = match["players"][player_key]
            touch_user_presence(username)
            ensure_match_not_disconnected(match)
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
                "disconnectWinner": match.get("disconnect_winner"),
                "endReason": match.get("end_reason"),
                "presence": copy.deepcopy(match.get("presence", {})),
                "replayId": match.get("replay_id"),
                "opponent": public_profile(get_user(match["players"]["p1" if player_key == "p2" else "p2"])),
                "you": username,
            }
        return _json(200, payload)

    if method == "GET" and path.startswith("/api/replays/"):
        replay_id = path.split("/api/replays/")[1].strip("/")
        if not is_safe_id(replay_id, 8, 64):
            return _json(404, {"ok": False, "error": "not found"})
        with LOCK:
            replay = STATE["replays"].get(replay_id)
            if not replay:
                return _json(404, {"ok": False, "error": "replay not found"})
        return _json(200, {"ok": True, "replay": replay})

    if method == "POST" and path == "/api/heartbeat":
        username = normalize_text(body.get("username", ""))
        if not username:
            return _json(400, {"ok": False, "error": "username required"})
        with LOCK:
            user = touch_user_presence(username)
            user["title"] = normalize_text(body.get("title", ""), "", 32)
            user["accent"] = normalize_color(body.get("accent", "#66d6ff"))
        return _json(200, {"ok": True})

    if method == "POST" and path == "/api/friends/add":
        username = normalize_text(body.get("username", ""))
        friend_name = normalize_text(body.get("friend", ""))
        if not username or not friend_name:
            return _json(400, {"ok": False, "error": "username and friend are required"})
        with LOCK:
            user = get_user(username)
            friend = get_user(friend_name)
            user["friends"].add(friend_name)
            friend["friends"].add(username)
        return _json(200, {"ok": True})

    if method == "POST" and path == "/api/matchmaking/join":
        username = normalize_text(body.get("username", ""))
        if not username:
            return _json(400, {"ok": False, "error": "username required"})
        with LOCK:
            prune_queue()
            user = touch_user_presence(username)
            user["title"] = normalize_text(body.get("title", ""), "", 32)
            user["accent"] = normalize_color(body.get("accent", "#66d6ff"))
            if user["pending_match_id"]:
                match = STATE["matches"].get(user["pending_match_id"])
                if match:
                    return _json(200, match_payload_for(username, match))
            if username in STATE["queue"]:
                return _json(200, {"ok": True, "status": "queued", "queueSize": len(STATE["queue"])})
            waiting_opponent = next((name for name in STATE["queue"] if name != username), None)
            if waiting_opponent:
                STATE["queue"] = [name for name in STATE["queue"] if name != waiting_opponent]
                match = create_match(waiting_opponent, username)
                return _json(200, match_payload_for(username, match))
            STATE["queue"].append(username)
        return _json(200, {"ok": True, "status": "queued", "queueSize": len(STATE["queue"])})

    if method == "POST" and path == "/api/matchmaking/cancel":
        username = normalize_text(body.get("username", ""))
        with LOCK:
            STATE["queue"] = [name for name in STATE["queue"] if name != username]
        return _json(200, {"ok": True})

    if method == "POST" and path.startswith("/api/matches/") and path.endswith("/sync"):
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
            return _json(400, {"ok": False, "error": "invalid match credentials"})
        if not isinstance(submitted_seq, int) or submitted_seq < 0:
            return _json(400, {"ok": False, "error": "invalid sync sequence"})
        if previous_signature and not is_safe_id(previous_signature, 20, 80):
            return _json(400, {"ok": False, "error": "invalid signature format"})

        with LOCK:
            match = STATE["matches"].get(match_id)
            if not match or match["tokens"].get(player_key) != token:
                return _json(403, {"ok": False, "error": "unauthorized"})
            if match.get("quit_by"):
                return _json(409, {"ok": False, "error": "match has ended"})
            touch_user_presence(match["players"][player_key])
            if match["signature"] and previous_signature != match["signature"]:
                STATE["stats"]["rejected_syncs"] += 1
                return _json(409, {"ok": False, "error": "stale signature"})
            if submitted_seq != match["seq"]:
                STATE["stats"]["rejected_syncs"] += 1
                return _json(409, {"ok": False, "error": "out-of-sync sequence"})
            valid, reason = validate_state(match, player_key, candidate_state, anti_cheat)
            if not valid:
                STATE["stats"]["rejected_syncs"] += 1
                return _json(422, {"ok": False, "error": reason})

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
        return _json(200, {"ok": True, "seq": match["seq"], "signature": match["signature"], "replayId": match.get("replay_id")})

    if method == "POST" and path.startswith("/api/matches/") and path.endswith("/presence"):
        parts = path.strip("/").split("/")
        match_id = parts[2]
        player_key = body.get("playerKey", "")
        token = body.get("token", "")
        presence = sanitize_presence_payload(body.get("presence", {}))
        if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
            return _json(400, {"ok": False, "error": "invalid match credentials"})
        with LOCK:
            match = STATE["matches"].get(match_id)
            if not match or match["tokens"].get(player_key) != token:
                return _json(403, {"ok": False, "error": "unauthorized"})
            if match.get("quit_by"):
                return _json(409, {"ok": False, "error": "match has ended"})
            touch_user_presence(match["players"][player_key])
            match["presence"][player_key] = presence
            match["updated_at"] = now()
        return _json(200, {"ok": True})

    if method == "POST" and path.startswith("/api/matches/") and path.endswith("/reaction"):
        parts = path.strip("/").split("/")
        match_id = parts[2]
        player_key = body.get("playerKey", "")
        token = body.get("token", "")
        message = str(body.get("message", "")).strip()[:8]
        allowed_reactions = {"🔥", "💀", "😅", "👏", "😈"}
        if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
            return _json(400, {"ok": False, "error": "invalid match credentials"})

        with LOCK:
            match = STATE["matches"].get(match_id)
            if not match or match["tokens"].get(player_key) != token:
                return _json(403, {"ok": False, "error": "unauthorized"})
            if match.get("quit_by"):
                return _json(409, {"ok": False, "error": "match has ended"})
            touch_user_presence(match["players"][player_key])
            if message not in allowed_reactions:
                return _json(400, {"ok": False, "error": "invalid reaction"})
            now_ts = now()
            if now_ts - match["rate_limit"][player_key]["reaction_at"] < 1:
                return _json(429, {"ok": False, "error": "reaction rate limit"})
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
        return _json(200, {"ok": True, "lastReactionId": reaction_id})

    if method == "POST" and path.startswith("/api/matches/") and path.endswith("/chat"):
        parts = path.strip("/").split("/")
        match_id = parts[2]
        player_key = body.get("playerKey", "")
        token = body.get("token", "")
        message = clamp_chat_message(body.get("message", ""))
        if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
            return _json(400, {"ok": False, "error": "invalid match credentials"})
        with LOCK:
            match = STATE["matches"].get(match_id)
            if not match or match["tokens"].get(player_key) != token:
                return _json(403, {"ok": False, "error": "unauthorized"})
            if match.get("quit_by"):
                return _json(409, {"ok": False, "error": "match has ended"})
            touch_user_presence(match["players"][player_key])
            if not message:
                return _json(400, {"ok": False, "error": "message required"})
            now_ts = now()
            if now_ts - match["rate_limit"][player_key]["chat_at"] < 1:
                return _json(429, {"ok": False, "error": "chat rate limit"})
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
        return _json(200, {"ok": True, "lastChatId": chat_id})

    if method == "POST" and path.startswith("/api/matches/") and path.endswith("/quit"):
        parts = path.strip("/").split("/")
        match_id = parts[2]
        player_key = body.get("playerKey", "")
        token = body.get("token", "")
        if not is_safe_id(match_id, 8, 24) or player_key not in {"p1", "p2"} or not is_safe_token(token):
            return _json(400, {"ok": False, "error": "invalid match credentials"})

        with LOCK:
            match = STATE["matches"].get(match_id)
            if not match or match["tokens"].get(player_key) != token:
                return _json(403, {"ok": False, "error": "unauthorized"})
            match["quit_by"] = player_key
            match["disconnect_winner"] = "p2" if player_key == "p1" else "p1"
            match["updated_at"] = now()
            release_match_players(match)
            replay_id = finalize_match(match, "quit")
        return _json(200, {"ok": True, "replayId": replay_id})

    return _json(404, {"ok": False, "error": "not found"})


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO", "/")
    query = {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}
    remote_ip = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip() or environ.get("REMOTE_ADDR", "unknown")
    body = {}

    if method in {"POST", "PUT", "PATCH"}:
        try:
            length = int(environ.get("CONTENT_LENGTH", "0") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            status_code, content_type, payload = _json(413, {"ok": False, "error": "payload too large"})
            status_text = "Payload Too Large"
            headers = [
                ("Content-Type", content_type),
                ("Content-Length", str(len(payload))),
                ("Access-Control-Allow-Origin", ALLOWED_ORIGIN),
                ("Access-Control-Allow-Headers", "Content-Type"),
                ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Cache-Control", "no-store"),
            ]
            start_response(f"{status_code} {status_text}", headers)
            return [payload]
        raw = environ["wsgi.input"].read(length) if length > 0 else b""
        if raw:
            try:
                body = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                body = {}

    if method == "OPTIONS":
        status_code, content_type, payload = _json(200, {"ok": True})
    else:
        status_code, content_type, payload = _route(method, path, query, body, remote_ip)

    status_text = {
        200: "OK",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        413: "Payload Too Large",
        429: "Too Many Requests",
        422: "Unprocessable Entity",
    }.get(status_code, "OK")

    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(payload))),
        ("Access-Control-Allow-Origin", ALLOWED_ORIGIN),
        ("Access-Control-Allow-Headers", "Content-Type"),
        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
    ]
    start_response(f"{status_code} {status_text}", headers)
    return [payload]
