# raydog

A minimal Common Lisp VPN client. Brings up a system-wide TUN tunnel over
any sing-box outbound (Shadowsocks, VLESS, etc). No GUI, no v2box.

Controlled from the REPL, no system daemon. `(connect)` in `dog.lisp` starts
the tunnel plus a background watcher thread that keeps it alive — checks
proxy liveness and network changes on its own, calls `stop-full`/`start-full`
as needed. For just the tunnel with no watcher, use `singbox.lisp` /
`tun.lisp` directly (`start-full` / `stop-full`).

## Files

- **`singbox.lisp`** — starts/stops sing-box (SOCKS5 inbound on
  `127.0.0.1:1080`). Runs unprivileged via `setsid`.
- **`tun.lisp`** — creates the TUN interface, redirects traffic, rolls
  back routes on stop. All privileged work goes through one root helper
  (below), never called directly.
- **`config.lisp`** — parses `vless://`/`ss://` URIs and writes a matching
  sing-box JSON config for each. No network or process code; pure parsing +
  JSON generation.
- **`dog.lisp`** — the only file you load. Pulls in the three files above
  and adds a watcher thread doing two jobs on every tick:
  1. **Proxy liveness** — TCP-checks the server; N failures in a row →
     fall back to direct (no VPN). On repeated failure it also rotates to
     the next entry in the config pool round-robin, rather than retrying
     the same dead server forever. M successes back → tunnel restored.
  2. **Network changes** — Wi-Fi toggle, sleep/wake, network switch. Forces
     a full teardown+rebuild rather than waiting for liveness to catch it.

## How it works

```
all system traffic → default route → TUN (utun9) → tun2socks
   → 127.0.0.1:1080 (sing-box inbound) → sing-box outbound → your proxy
```

Traffic to the proxy itself is excluded from the TUN to avoid a routing loop.

## Dependencies

```bash
brew install sing-box
brew install util-linux   # for setsid (keg-only)
# tun2socks: not in homebrew core, grab a binary from
# https://github.com/xjasonlyu/tun2socks/releases
sudo mv tun2socks-darwin-arm64 /usr/local/bin/tun2socks
```

Set `*singbox-bin*` / `*setsid-bin*` in `singbox.lisp` to match `which
sing-box` / the util-linux path on your machine.

`nc` at the hardcoded path `/usr/bin/nc` is also required — both sing-box
startup polling (`port-open-p` in `singbox.lisp`) and the watcher's proxy
liveness check (`server-alive-p` in `dog.lisp`) shell out to it. Ships
with macOS by default, nothing to install, but if it's ever missing or
moved the watcher thread degrades to reading the proxy as unreachable
rather than crashing — check for a `server-alive-p check errored` log
line if liveness checks look wrong.

No Quicklisp, no third-party Lisp libraries — base64, URL-decoding, and
JSON generation in config.lisp are hand-rolled on purpose, to keep the
whole thing self-contained (just SBCL + uiop, which ships with it).

## Privileged helper

Creating the TUN and changing routes needs root. Rather than granting sudo
on `setsid`/`route`/`ifconfig`/`kill` directly (equivalent to unrestricted
root), everything privileged goes through `lisp-vpn-priv.c`: a fixed
command vocabulary (`setup-routes`, `teardown-routes`, `assign-tun`,
`start-tun`, `stop-tun`), validated arguments, fixed absolute-path
binaries, no shell.

```bash
clang -Wall -Wextra -Werror -O2 lisp-vpn-priv.c -o lisp-vpn-priv
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec
sudo install -o root -g wheel -m 0755 lisp-vpn-priv /usr/local/libexec/lisp-vpn-priv
# root-owned copy — the helper always execs *this* path, never your
# Homebrew/user-writable tun2socks. Only the source path here should
# change to match where tun2socks is installed; re-run after updating it.
sudo install -o root -g wheel -m 0755 /usr/local/bin/tun2socks \
  /usr/local/libexec/lisp-vpn-tun2socks
```

```sudoers
your_username ALL=(root) NOPASSWD: /usr/local/libexec/lisp-vpn-priv
```

Remove any older sudoers entries for `setsid`/`route`/`ifconfig`/`kill`.

Each subcommand does exactly one thing — `setup-routes`/`teardown-routes
proxy-IPv4` capture/restore the default gateway, `start-tun`/`stop-tun
utunN` run tun2socks, `assign-tun utunN` brings the TUN up. All rollback
logic, input validation, and PID-reuse safety live as short comments
directly above the relevant code in `lisp-vpn-priv.c` (~180 lines) — read it
there rather than here; it won't drift out of sync with itself.

Note the helper only ever excludes a single proxy IP from the tunnel (one
host route) — that's why the pool below is cycled through one entry at a
time rather than run concurrently.

## Config

`*config-path*` in `singbox.lisp` points at a sing-box JSON config. You
don't write these by hand — `dog.lisp` reads one `vless://`/`ss://` URI per
line from `*server-list-path*` (default `/tmp/servers.txt`, `#` for
comments) and `config.lisp` generates a matching config per line. `(connect)`
starts on entry 0; on failure the watcher rotates through the rest.

Minimal example of what gets generated (Shadowsocks):

```json
{
  "log": { "level": "warn" },
  "dns": {
    "servers": [
      {
        "tag": "proxy-dns",
        "type": "https",
        "server": "1.1.1.1",
        "detour": "proxy"
      }
    ]
  },
  "inbounds": [{ "type": "mixed", "listen": "127.0.0.1", "listen_port": 1080 }],
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "proxy",
      "server": "your.server.ip",
      "server_port": 8080,
      "method": "chacha20-ietf-poly1305",
      "password": "..."
    }
  ]
}
```

`dns` matters — without it, DNS leaks outside the tunnel even though your
traffic doesn't.

## Usage

```lisp
(load "dog.lisp")
(connect)     ; sing-box → tun2socks → routes → watcher, all in one
(watch?)      ; current mode, thread status, interface
(disconnect)  ; stop watcher, wait for it, roll everything back
```

Manual (no watcher/failover):

```lisp
(load "singbox.lisp")
(load "tun.lisp")
(start-full)
(status)
(stop-full)
```

Verify: `curl https://cloudflare.com/cdn-cgi/trace` should show the proxy's
IP, not yours.

## If you lose internet

```bash
sudo route delete default
sudo route add default <your_usual_gateway>   # note this beforehand: route -n get default
```

Or just toggle Wi-Fi to let DHCP reassign the route.

## Notable gotchas

- `setsid` forks rather than exec'ing, so the PID from `run-program` points
  at the wrong process. Processes are found and killed by command-line name
  (`pgrep -f`), not by PID — this is the primary mechanism, not a fallback.
- The TUN subnet (`198.18.0.1`) is hardcoded in `lisp-vpn-priv.c` as
  `TUN_IP`, not a Lisp variable — change it there and rebuild the helper.
- tun2socks's PID lives in `/var/run/lisp-vpn-tun2socks.pid`; after a crash
  or reboot it can block the next `start-tun` until removed.
- tun2socks logs to `/var/log/lisp-vpn-tun2socks.log`, not Lisp's stdout (see
  the comment above `start-tun` in `lisp-vpn-priv.c` for why).
- Always pass `:input nil` to sudo'd background processes in
  `run-program`, or they can hang waiting on a tty.
