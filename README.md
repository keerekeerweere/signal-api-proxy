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

- `POST /send` `{"to":"+E164"|"group:<id>","message":"..."}` — always requires `X-API-Key` (or `?api_key=`)
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

1. Source IP must match `allowed_networks` (CIDRs)
2. API key constant-time compare (except the gated v2 endpoints above)
3. Recipient + group allowlists — plus-less numbers accepted only when
   `+`-prefixed form is explicitly allowlisted (no country-code guessing)
4. Body/attachment size and type limits

## HA client facts (pinned pysignalclirestapi)

- YAML `number:` = SENDING account (registered on this host); `recipients:` = targets
- Platform cannot send credentials → v2 keyless mode or use `rest_command` with `X-API-Key`
- `url:` must be the bare base (`http://host:8090`); trailing slash is tolerated
- Success must be HTTP 201 or the client errors

## Host requirement

signal-cli must be the **Java build** (this host: `~/.local/share/signal-cli-java`,
JDK 25 at `~/.local/share/jdk/`). The GraalVM native build cannot process
attachments (`Can't load library: awt`).

## Operations

```
systemctl --user status signal-api-proxy.service
journalctl --user -u signal-api-proxy.service   # request lines carry source IP; rejections log the reason
python3 -m py_compile server.py                 # syntax check before restart
systemctl --user restart signal-api-proxy.service
```

Config is re-read on every request — allowlist edits need no restart; code
changes do.
