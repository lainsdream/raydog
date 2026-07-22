# raydog

A minimal Common Lisp VPN client. Brings up a system-wide TUN tunnel over
any sing-box outbound (Shadowsocks, VLESS, etc). No GUI, no v2box.

Controlled from the REPL, no system daemon. `(connect)` in `dog.lisp` starts
the tunnel plus a background watcher thread that keeps it alive — checks
proxy liveness and network changes on its own, calls `stop-full`/`start-full`
as needed. For just the tunnel with no watcher, use `singbox-ctl.lisp` /
`tun-ctl.lisp` directly (`start-full` / `stop-full`).

## Files

- **`singbox-ctl.lisp`** — starts/stops sing-box (SOCKS5 inbound on
  `127.0.0.1:1080`). Runs unprivileged via `setsid`.
- **`tun-ctl.lisp`** — creates the TUN interface, redirects traffic, rolls
  back routes on stop. All privileged work goes through one root helper
  (below), never called directly.
- **`dog.lisp`** — the only file you load. Pulls in the two files above and
  adds a watcher thread doing two jobs on every tick:
  1. **Proxy liveness** — TCP-checks the server; N failures in a row →
     fall back to direct (no VPN); M successes back → restore the tunnel.
  2. **Network changes** — Wi-Fi toggle, sleep/wake, network switch. Forces
     a full teardown+rebuild rather than waiting for liveness to catch it.
- **`lisp-vpn-priv.c`** — the root helper. Fixed subcommand set
  (`setup-routes`, `teardown-routes`, `assign-tun`, `start-tun`, `stop-tun`),
  runs `route`/`ifconfig`/`tun2socks` by absolute path, no shell involved.

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

Set `*singbox-bin*` / `*setsid-bin*` in `singbox-ctl.lisp` to match `which
sing-box` / the util-linux path on your machine.

## Privileged helper

The helper replaces unsafe sudoers grants for `setsid`, `route`, `ifconfig`,
and `kill`. It accepts only a fixed command vocabulary with validated
arguments, runs fixed absolute-path binaries, and never invokes a shell.

### Build and install (macOS)

From the repository root:

```bash
clang -Wall -Wextra -Werror -O2 lisp-vpn-priv.c -o lisp-vpn-priv
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec
sudo install -o root -g wheel -m 0755 lisp-vpn-priv /usr/local/libexec/lisp-vpn-priv
sudo install -o root -g wheel -m 0755 /usr/local/bin/tun2socks \
  /usr/local/libexec/lisp-vpn-tun2socks
```

The helper always executes the root-owned copy at
`/usr/local/libexec/lisp-vpn-tun2socks`, never the Homebrew/user-writable
one. Only the source path in the last command should change to match where
`tun2socks` is installed. Re-run that command whenever you update it.

### Passwordless sudo

```sudoers
your_username ALL=(root) NOPASSWD: /usr/local/libexec/lisp-vpn-priv
```

`NOPASSWD` on those bare commands is effectively unrestricted root access.
Allowlisting the helper alone is safe because it validates all inputs and
calls binaries directly.

### Helper commands and limits

- **`start-tun utunN` / `stop-tun`** — start/stop tun2socks; its PID is in
  `/var/run/lisp-vpn-tun2socks.pid`.
- **`assign-tun utunN`** — bring the TUN interface up with the fixed tunnel IP.
- **`setup-routes proxy-IPv4`** — atomically captures the current default
  gateway, adds a host route to the proxy through it, then points the default
  route at the TUN. On failure it rolls back the change.
- **`teardown-routes proxy-IPv4`** — restores the captured default gateway,
  removes the proxy host route, and clears state.

The helper can touch only the default route and one IPv4 host route. It
accepts only `utun<digits>`, IPv4 addresses validated with `inet_pton`, the
fixed local SOCKS endpoint, and the fixed root-owned tun2socks binary.

After a crash or reboot, the PID file above and
`/var/run/lisp-vpn-original-gw` may be stale. Check `route -n get default`
before manually removing either file. A second `setup-routes` refuses to run
while the gateway-state file exists, rather than risking an overwrite.

## Config

`*config-path*` in `singbox-ctl.lisp` points at a sing-box JSON config:

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

**`dns` is required** — without it, DNS leaks outside the tunnel even
though your traffic doesn't. `outbounds[0].tag`, `dns.servers[0].detour`,
and `inbounds[0]` must stay exactly as shown; only `outbounds[0]` itself
changes between configs.

You don't build these by hand — `dog.lisp` reads one `vless://`/`ss://` URI
per line from `*server-list-path*` (default `/tmp/servers.txt`) and
generates a config per line via `load-server-pool`. `(connect)` starts on
entry 0; `switch-to-config` keeps `*proxy-server-ip*`/`*proxy-server-port*`
in sync automatically.

## Usage

```lisp
(load "dog.lisp")
(connect)     ; sing-box → tun2socks → routes → watcher, all in one
(watch?)      ; current mode, thread status, interface
(disconnect)  ; stop watcher, wait for it, roll everything back
```

Manual (no watcher/failover):

```lisp
(load "singbox-ctl.lisp")
(load "tun-ctl.lisp")
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
  `TUN_IP`, not a Lisp variable — change it there and rebuild.
- tun2socks's PID lives in `/var/run/lisp-vpn-tun2socks.pid`; after a crash
  or reboot it can block the next `start-tun` until removed.
- tun2socks logs to `/var/log/lisp-vpn-tun2socks.log`, not Lisp's stdout —
  it outlives the helper process that launched it.
- Always pass `:input nil` to sudo'd background processes in
  `run-program`, or they can hang waiting on a tty.
