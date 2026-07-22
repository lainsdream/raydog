# Narrow sudo wrapper for lisp-vpn

Replaces the unsafe sudoers grant for `setsid`, `route`, `ifconfig`, and
`kill` with one helper: a fixed command vocabulary, validated arguments,
fixed absolute-path binaries, no shell.

## Build and install (macOS)

```sh
clang -Wall -Wextra -Werror -O2 lisp-vpn-priv.c -o lisp-vpn-priv
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec
sudo install -o root -g wheel -m 0755 lisp-vpn-priv /usr/local/libexec/lisp-vpn-priv
sudo install -o root -g wheel -m 0755 /usr/local/bin/tun2socks \
  /usr/local/libexec/lisp-vpn-tun2socks
```

The helper always executes the root-owned copy at
`/usr/local/libexec/lisp-vpn-tun2socks` — never the Homebrew/user-writable
one. Only the _source_ path in the last command should change to match
where your `tun2socks` actually lives.

## sudoers

```sudoers
your_username ALL=(root) NOPASSWD: /usr/local/libexec/lisp-vpn-priv
```

Remove any older entries for `setsid`, `route`, `ifconfig`, `kill` —
`NOPASSWD` on bare `setsid` is equivalent to unrestricted root.

## Commands

- **`start-tun utunN` / `stop-tun`** — start/stop tun2socks; PID tracked in
  `/var/run/lisp-vpn-tun2socks.pid`.
- **`assign-tun utunN`** — bring the TUN interface up with the fixed tunnel IP.
- **`setup-routes proxy-IPv4`** — one atomic transaction: capture and persist
  the current default gateway, add a host route to the proxy via that
  gateway (so proxy traffic isn't pulled into the tunnel), then point the
  default route at the TUN interface. Any failure after capturing the
  gateway rolls everything back — never leaves the machine half-configured.
- **`teardown-routes proxy-IPv4`** — the inverse: restore the captured
  gateway as default, remove the proxy host route, clear the captured
  state — unconditionally, even if restoring the route fails (e.g. gateway
  unreachable after a network change). Still leaves the helper ready for
  the next `setup-routes`; just reports that the route wasn't actually
  restored, so you can check `route -n get default` yourself.

## Deliberate limits

- Can only touch the default route and one IPv4 host route — nothing else,
  and can't execute arbitrary programs as root.
- Only accepts `utun<digits>`, the one fixed root-owned tun2socks binary,
  the fixed local SOCKS endpoint, and IPv4 args validated via `inet_pton`.
- tun2socks's PID file (`/var/run/lisp-vpn-tun2socks.pid`) can go stale
  after a crash/reboot — check and remove by hand if so.
- The original gateway is stored in `/var/run/lisp-vpn-original-gw`,
  written with `O_EXCL`: a second `setup-routes` without a prior
  `teardown-routes` refuses outright rather than risk overwriting it with
  the tunnel's own gateway. If stale after a crash, check
  `route -n get default` and remove the file manually first.
- The caller (Lisp) never sees or passes a gateway address anywhere in this
  interface, so it can't hand the helper a stale or forged one.
