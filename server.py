#!/usr/bin/env python3
"""Authenticated Signal send proxy.

Exposes a minimal REST surface for LAN clients (e.g. Home Assistant) in front
of the unauthenticated signal-cli daemon on 127.0.0.1:8080.

- POST /send  {"to": "+32...", "message": "..."}         (recipient allowlist)
- POST /send  {"to": "group:<base64 groupId>", "message": "..."}  (group allowlist)
- GET  /health  -> {"ok": true, "daemon": <version>}

Auth: X-API-Key header, compared against config. Source IPs restricted to the
configured networks. Method forwarding is impossible: this proxy only ever
calls signal-cli's 'send' and 'version' RPCs and builds the payload itself.
"""
import http.server
import ipaddress
import json
import os
import re
import sys
import urllib.request
import base64

CONFIG_PATH = os.environ.get("SIGNAL_PROXY_CONFIG",
                             os.path.expanduser("~/.config/signal-api-proxy/config.json"))
DAEMON = "http://127.0.0.1:8080/api/v1/rpc"
MAX_BODY = 20 * 1024 * 1024  # allows HA base64_attachments (JSON body, not multipart)
MAX_MESSAGE = 6000
MAX_ATT_BYTES = 10 * 1024 * 1024
MAX_ATT_COUNT = 4
SPOOL_DIR = os.path.expanduser("~/.local/share/signal-api-proxy/spool")
# magic bytes -> extension; only these types accepted
ATT_SIGNATURES = [
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"RIFF", "webp"),  # validated further below
    (b"\x1aE\xdf\xa3", "webm"),
]
GROUP_RE = re.compile(r"^group:[A-Za-z0-9+/=]{20,120}$")


def att_kind(head: bytes) -> str | None:
    for sig, ext in ATT_SIGNATURES:
        if head.startswith(sig):
            if ext == "webp" and head[8:12] != b"WEBP":
                continue
            return ext
    if head[4:8] == b"ftyp":
        return "mp4"
    return None


def spool_attachments(payload: dict) -> tuple[list, list]:
    """Decode HA/bbernhard base64_attachments to spool files. Returns (paths, errors)."""
    raw = payload.get("base64_attachments") or payload.get("attachments") or []
    if isinstance(raw, str):
        raw = [raw]
    errors, paths = [], []
    if not raw:
        return paths, errors
    if len(raw) > MAX_ATT_COUNT:
        return paths, ["too many attachments (max %d)" % MAX_ATT_COUNT]
    os.makedirs(SPOOL_DIR, mode=0o700, exist_ok=True)
    for i, b64 in enumerate(raw):
        try:
            data = base64.b64decode(str(b64), validate=True)
        except Exception:
            errors.append("attachment %d: invalid base64" % i)
            continue
        if not data or len(data) > MAX_ATT_BYTES:
            errors.append("attachment %d: size 1B-%dMB required" % (i, MAX_ATT_BYTES // (1024 * 1024)))
            continue
        ext = att_kind(data[:12])
        if ext is None:
            errors.append("attachment %d: unsupported type (jpg/png/gif/webp/mp4/webm only)" % i)
            continue
        path = os.path.join(SPOOL_DIR, "att-%d-%s.%s" % (os.getpid(), i, ext))
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o600)
        paths.append(path)
    if errors:
        for p in paths:
            try:
                os.remove(p)
            except OSError:
                pass
        return [], errors
    return paths, errors


def canon_recipient(n: str, allow: list) -> str | None:
    """Accept E.164 as-is; accept plus-less digits ONLY if '+'+digits is explicitly
    allowlisted — no country-code guessing, strict allowlist normalization."""
    n = n.strip()
    if re.match(r"^\+\d{6,15}$", n):
        return n if n in allow else None
    if re.match(r"^\d{6,15}$", n) and ("+" + n) in allow:
        return "+" + n
    return None


def load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def rpc(method: str, params: dict) -> dict:
    req = urllib.request.Request(
        DAEMON,
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers={"Content-Type": "application/json", "Host": "127.0.0.1:8080"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "SignalSendProxy/1"

    def log_message(self, fmt, *args):  # compact, but keep source IP for audit
        sys.stderr.write("%s [%s] %s\n" % (self.log_date_time_string(), self.client_address[0], fmt % args))

    def _deny(self, code: int, why: str) -> None:
        self._json(code, {"ok": False, "error": why})

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _peer_in_allowed_networks(self, cfg: dict) -> bool:
        peer = self.client_address[0]
        nets = [ipaddress.ip_network(n) for n in cfg.get("allowed_networks", [])]
        return (not nets) or any(ipaddress.ip_address(peer) in n for n in nets)

    def _authorized(self, cfg: dict, allow_lan_open: bool = False) -> bool:
        if not self._peer_in_allowed_networks(cfg):
            return False
        if allow_lan_open and cfg.get("v2send_lan_unauthenticated", False):
            return True
        expected = cfg.get("api_key", "")
        if not expected:
            return False
        supplied = self.headers.get("X-API-Key", "")
        if not supplied:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            supplied = (qs.get("api_key") or qs.get("auth_key") or [""])[0]
        import hmac
        return hmac.compare_digest(supplied, expected)

    def _route_path(self) -> str:
        # self.path is 'path?query'; do NOT urlparse() it: a leading '//' would be
        # parsed as a netloc (e.g. '//v1/about' -> host 'v1'). Split manually and
        # collapse duplicate slashes so a trailing slash in the client's base URL
        # (e.g. http://host:8090/) cannot break routing.
        p = self.path.split("?", 1)[0]
        p = re.sub(r"/{2,}", "/", p)
        return p.rstrip("/") or "/"

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self._route_path()
        if path == "/health":
            cfg = load_config()
            if not self._authorized(cfg):
                self._deny(401, "unauthorized")
                return
            try:
                v = rpc("version", {}).get("result")
                self._json(200, {"ok": True, "daemon": v})
            except Exception as e:
                self._json(502, {"ok": False, "error": "daemon unreachable: %r" % (e,)})
            return
        if path == "/v1/about":
            # bbernhard-compatible capability discovery (pysignalclirestapi requires it).
            cfg = load_config()
            if not self._authorized(cfg, allow_lan_open=True):
                self._deny(401, "unauthorized")
                return
            self._json(200, {
                "version": "0.14.1",
                "build": 1,
                "versions": ["v1", "v2"],
                "mode": "native",
                "release_mode": "source",
                "os_info": "debian",
                "easter_egg": "",
                "capabilities": {"v2/send": [], "v1/send": []},
            })
            return
        if path.startswith("/v2/check/account/"):
            # bbernhard-compat: 204 No Content when the queried number is this host's
            # registered sending account, 400 otherwise.
            cfg = load_config()
            if not self._authorized(cfg, allow_lan_open=True):
                self._deny(401, "unauthorized")
                return
            queried = urllib.parse.unquote(path[len("/v2/check/account/"):]).strip()
            if queried == cfg.get("local_account", ""):
                self.send_response(204)
                self.end_headers()
            else:
                self._deny(400, "account not registered on this instance")
            return
        self._deny(404, "not found")

    def do_POST(self):
        path = self._route_path()
        if path == "/send":
            self._handle_v1_send()
        elif path == "/v2/send":
            self._handle_v2_send()
        else:
            self._deny(404, "not found")

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                self._deny(400, "bad content length")
                return None
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._deny(400, "invalid JSON body")
            return None

    def _handle_v2_send(self):
        cfg = load_config()
        if not self._authorized(cfg, allow_lan_open=True):
            self._deny(401, "unauthorized")
            return
        payload = self._read_body()
        if payload is None:
            return
        message = str(payload.get("message", ""))
        if not message or len(message) > MAX_MESSAGE:
            self._deny(400, "message must be 1-%d chars" % MAX_MESSAGE)
            return
        numbers = payload.get("recipients") if payload.get("recipients") else payload.get("number") or []
        if payload.get("recipients"):
            # multi-account style (pysignalclirestapi >= 0.3.x): "number" is the SENDER
            sender = str(payload.get("number", "")).strip()
            if sender and sender != cfg.get("local_account", ""):
                self._deny(400, "sender account not available on this instance")
                return
        groups = payload.get("group") or payload.get("group_ids") or []
        if isinstance(numbers, str):
            numbers = [numbers]
        if isinstance(groups, str):
            groups = [groups]
        att_paths, att_errors = spool_attachments(payload)
        if att_errors:
            sys.stderr.write("v2/send rejected attachments: %s\n" % "; ".join(att_errors))
            self._json(400, {"error": "; ".join(att_errors)})
            return
        timestamps = []
        errors = []
        try:
            for n in numbers:
                n = str(n).strip()
                canon = canon_recipient(n, cfg.get("allowed_recipients", []))
                if canon is None:
                    errors.append("bad or non-allowlisted number: %r" % n[:30])
                    continue
                params = {"recipient": [canon], "message": message}
                if att_paths:
                    params["attachments"] = att_paths
                try:
                    res = rpc("send", params)
                    if "error" in res:
                        errors.append(res["error"].get("message", "rpc error"))
                    else:
                        timestamps.append(res.get("result", {}).get("timestamp"))
                except Exception as e:
                    errors.append("daemon unreachable: %r" % (e,))
            for g in groups:
                g = str(g).strip()
                if not GROUP_RE.match("group:" + g) or g not in cfg.get("allowed_groups", []):
                    errors.append("group not allowlisted")
                    continue
                params = {"groupId": g, "message": message}
                if att_paths:
                    params["attachments"] = att_paths
                try:
                    res = rpc("send", params)
                    if "error" in res:
                        errors.append(res["error"].get("message", "rpc error"))
                    else:
                        timestamps.append(res.get("result", {}).get("timestamp"))
                except Exception as e:
                    errors.append("daemon unreachable: %r" % (e,))
        finally:
            for p in att_paths:
                try:
                    os.remove(p)
                except OSError:
                    pass
        if not numbers and not groups:
            sys.stderr.write("v2/send rejected: no number or group given; body keys=%s\n" % sorted(payload.keys()))
            self._deny(400, "no number or group given")
        elif errors and not timestamps:
            sys.stderr.write("v2/send rejected: %s | recipients=%s groups=%s sender=%r\n" % (
                "; ".join(errors), numbers[:3], groups[:3], payload.get("number")))
            self._json(400, {"error": "; ".join(errors)})
        elif errors:
            self._json(207, {"result": timestamps[-1], "partial_errors": errors})
        else:
            self._json(201, {"result": timestamps[0]})

    def _handle_v1_send(self):
        cfg = load_config()
        if not self._authorized(cfg):
            self._deny(401, "unauthorized")
            return
        payload = self._read_body()
        if payload is None:
            return
        to = str(payload.get("to", "")).strip()
        message = str(payload.get("message", ""))
        if not message or len(message) > MAX_MESSAGE:
            self._deny(400, "message must be 1-%d chars" % MAX_MESSAGE)
            return
        params = {}
        if to.startswith("group:"):
            if not GROUP_RE.match(to):
                self._deny(400, "bad group id")
                return
            gid = to[len("group:"):]
            if gid not in cfg.get("allowed_groups", []):
                self._deny(403, "group not allowlisted")
                return
            params = {"groupId": gid, "message": message}
        else:
            if not re.match(r"^\+\d{6,15}$", to):
                self._deny(400, "recipient must be E.164 (+...) or group:<id>")
                return
            if to not in cfg.get("allowed_recipients", []):
                self._deny(403, "recipient not allowlisted")
                return
            params = {"recipient": [to], "message": message}
        try:
            res = rpc("send", params)
        except Exception as e:
            self._json(502, {"ok": False, "error": "daemon unreachable: %r" % (e,)})
            return
        if "error" in res:
            self._json(502, {"ok": False, "error": res["error"].get("message", "rpc error")})
            return
        self._json(200, {"ok": True, "timestamp": res.get("result", {}).get("timestamp")})


def main() -> int:
    cfg = load_config()
    host = cfg.get("bind", "0.0.0.0")
    port = int(cfg.get("port", 8090))
    srv = http.server.ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("SignalSendProxy listening on %s:%d (send-only, api-key auth)\n" % (host, port))
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
