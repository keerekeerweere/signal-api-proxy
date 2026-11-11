# signal-api-proxy

Minimal, stdlib-only Python proxy that safely exposes the **unauthenticated**
signal-cli HTTP daemon (127.0.0.1:8080) to LAN clients — built for Home
Assistant's native `signal_messenger` notify platform.

Canonical source lives in this folder; the systemd unit runs this copy
directly (no separate deployment step).

## Layout

| File | Purpose |
|---|---|
| `server.py` | the proxy — run via the systemd unit |
| `signal-api-proxy.service` | copy into `~/.config/systemd/user/`, then `systemctl --user daemon-reload && systemctl --user enable --now signal-api-proxy.service` |
| `config.json.example` | copy to `~/.config/signal-api-proxy/config.json`, `chmod 600`, fill in secrets |

Runtime data (not in repo): attachment spool + the live config.

## What it exposes

- `POST /send` `{"to":"+E164"|"group:<id>","message":"..."}` — always requires the `X-API-Key` header (keys in the URL are not accepted)
- `GET /health` — requires key
- bbernhard-compatible surface for HA native platform (keyless **only** when
  `v2send_lan_unauthenticated: true`, then gated by `allowed_networks`):
  - `GET /v1/about` — capability handshake HA's client requires
  - `GET /v2/check/account/<num>` → 204 iff `num == local_account`
  - `POST /v2/send` → HTTP **201** on success; accepts `recipients`/`number`
    (sender) style, `group`/`group_ids`, and `base64_attachments` (max 4 x
    10 MB; jpg/png/gif/webp/mp4/webm by magic bytes; spooled and deleted
    after send)

Clients can never choose a daemon RPC method: the proxy builds the JSON-RPC
body itself and only ever calls `send`/`version`.

## Enforcement layers

1. Source IP must match `allowed_networks` (CIDRs); an empty list admits nobody
2. API key constant-time compare (except the gated v2 endpoints above)
3. Recipient + group allowlists — plus-less numbers accepted only when
   `+`-prefixed form is explicitly allowlisted (no country-code guessing)
4. Body/attachment size and type limits; max 10 de-duplicated recipients per request
5. POSTs carrying an `Origin` header or a browser form content type are refused
   (blocks web pages in a LAN browser from using the keyless endpoints)
6. Loop guard: the same recipients + message + attachments go out at most
   `duplicate_limit` (3) times per rolling `duplicate_window_seconds` (600 =
   10 minutes); further identical requests get HTTP 429. `"duplicate_limit": 0`
   disables it. Both are read from `config.json` on every request,
   so changes apply without a restart. Counters are in memory (reset on restart).

## HA client facts (pinned pysignalclirestapi)

- YAML `number:` = SENDING account (registered on this host); `recipients:` = targets
- Platform cannot send credentials → v2 keyless mode or use `rest_command` with `X-API-Key`
- `url:` must be the bare base (`http://host:8090`); trailing slash is tolerated
- Success must be HTTP 201 or the client errors

## Host requirement

signal-cli must be the **Java build** (this host: `~/.local/share/signal-cli-java`,
JDK 25 at `~/.local/share/jdk/`). The GraalVM native build cannot process
attachments (`Can't load library: awt`).

## Docker (optional, proxy only)

The image contains **only the proxy**. signal-cli stays on the host, registered
and run exactly as before — nothing about its setup changes.

```
mkdir -p ~/.config/signal-api-proxy ~/.local/share/signal-api-proxy/spool
cp config.json.example ~/.config/signal-api-proxy/config.json   # edit, chmod 600
cp compose.example.yaml compose.yaml
docker compose up -d --build
```

- `network_mode: host`: the proxy reaches the daemon on the host's loopback and
  sees real client IPs for `allowed_networks`. On a bridge network the daemon
  would have to listen beyond loopback, and client IPs can be masked.
- The spool is mounted at the **same path** inside and outside the container,
  because signal-cli reads attachments by the path the proxy gives it.
- `PUID`/`PGID` (default 1000) must match the user running signal-cli.
- Use either the systemd unit or the container, not both (same port).

Environment overrides: `SIGNAL_PROXY_CONFIG`, `SIGNAL_PROXY_SPOOL`,
`SIGNAL_PROXY_DAEMON` (default `http://127.0.0.1:8080/api/v1/rpc`).

## Operations

```
systemctl --user status signal-api-proxy.service
journalctl --user -u signal-api-proxy.service   # request lines carry source IP; rejections log the reason
python3 -m py_compile server.py                 # syntax check before restart
systemctl --user restart signal-api-proxy.service
```

Config is re-read on every request — allowlist edits need no restart; code
changes do.
