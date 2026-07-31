;;; A single watcher serializes tunnel reconfiguration.

(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; Must run BEFORE singbox.lisp/tun.lisp load — those files defparameter
  ;; *process*/*proxy-server-ip*/etc, which would silently drop the handle
  ;; to a live tunnel out from under us. At this point in the reload,
  ;; *thread*/disconn (if bound at all) are still the OLD ones from the
  ;; previous load, seeing the still-live state — exactly what we need to
  ;; tear it down cleanly instead of leaking it.
  (when (and (boundp '*thread*) (symbol-value '*thread*)
             (sb-thread:thread-alive-p (symbol-value '*thread*))
             (fboundp 'disconn))
    (format t "~&[dog] reloading while connected — running (disconn) on the old session first~%")
    (handler-case (funcall (symbol-function 'disconn))
      (error (e)
        (format t "~&[dog] auto-disconn failed (~a) — check `ps aux | grep tun2socks`, ~
                   `route -n get default`, and /var/run/lisp-vpn-* by hand before continuing~%" e))))
  (let ((here (or *load-truename* *load-pathname*
                  *compile-file-truename* *compile-file-pathname*
                  (error "dog.lisp must be loaded via (load ...), not evaluated form by form — ~
                          *load-truename* is how it finds singbox.lisp and tun.lisp next to it"))))
    (load (merge-pathnames "singbox.lisp" here))
    (load (merge-pathnames "tun.lisp" here))
    (load (merge-pathnames "config.lisp" here))))


(defparameter *proxy-server-port* nil
  "Port of the currently active proxy server. Kept in sync with
   *proxy-server-ip* automatically by switch-to-config; set manually only
   on the no-pool path.")

(defparameter *server-list-path* "/tmp/servers.txt"
  "One vless:// or ss:// URI per line, # for comments/blank lines ignored.
   See config.lisp's read-uri-lines/load-server-pool.")

(defparameter *pool-config-dir* "/tmp/pool-configs/"
  "Where load-server-pool writes one complete sing-box config file per
   entry in *server-list-path*.")

(defun try-load-server-pool ()
  "Wraps load-server-pool so a missing/unreadable *server-list-path* never
   aborts loading the rest of dog.lisp. Degrades to an empty pool, which
   the sweep logic in cycle already treats as \"nothing to try, fall back
   to direct on first failure\"."
  (handler-case (load-server-pool *server-list-path* *pool-config-dir*)
    (error (e)
      (format t "~&[dog] couldn't load ~a (~a) — starting with an empty pool.~%~
                 [dog] create it (one vless:// or ss:// URI per line) and call ~
                 (reload-server-pool) when ready.~%"
              *server-list-path* e)
      nil)))

(defparameter *config-pool* (try-load-server-pool)
  "List of (:label :path :ip :port) plists, one per line in
   *server-list-path*, in the same order. Re-run (reload-server-pool) to
   pick up changes to the .txt file without restarting the Lisp image.")

(defun reload-server-pool ()
  "Re-parse *server-list-path* into *config-pool*. Does NOT touch the
   currently running tunnel or *pool-index* — only takes effect the next
   time switch-to-config runs (i.e. next failure/sweep), so editing the
   .txt file never itself causes a reconnect."
  (setf *config-pool* (try-load-server-pool))
  (format t "~&[dog] pool reloaded: ~a entries~%" (length *config-pool*)))

(defparameter *pool-index* 0
  "Index into *config-pool* of the currently active entry.")

(defparameter *sweep-tries* 0
  "How many distinct pool entries have failed in a row during the current
   sweep. Reset to 0 the moment any check succeeds. Reaching (length
   *config-pool*) means every entry has been tried and failed without a
   single success in between — only then do we give up and fall back to
   :direct, rather than after just one entry dies.")

(defparameter *poll-interval* 5
  "Seconds between checks — both proxy liveness and network state are
   checked on the same tick. Kept fairly relaxed on purpose: false
   verdicts cost more (needless reconfigures) than a slightly slower
   reaction to a real change, since recovery is automatic anyway.
   *fail-threshold* and *revive-threshold* both give ~40s windows at this
   interval; a false positive either way just costs one extra reconfigure
   cycle, the next tick catches and corrects it.")

(defparameter *fail-threshold* 8
  "Consecutive failed proxy checks before declaring the server dead and
   falling back to direct.")

(defparameter *revive-threshold* 8
  "Consecutive successful proxy checks (while in fallback) before
   restoring the tunnel.")


(defparameter *watched-interface* "en0"
  "Physical interface to watch for status/IP changes — Wi-Fi on most Macs.
   Check `networksetup -listallhardwareports` if en0 isn't right on yours.")

(defparameter *sleep-gap-threshold* 20
  "If more wall-clock time passes between two ticks than this, suspect the
   machine was asleep. This alone no longer triggers a reconfigure — see
   CYCLE, which confirms the suspicion by comparing the actual default
   gateway before and after, and only reconfigures if it really changed.
   Must be comfortably larger than *poll-interval*.")

(defparameter *settle-delay* 5
  "Seconds to wait after detecting a network change, before reconfiguring
   — gives DHCP/DNS a moment to actually come back up. Reconfiguring
   against a half-up interface just reproduces the original 'no internet'
   failure mode.")


(defparameter *thread* nil)
(defparameter *running* nil)
(defparameter *regime* :tunnel)


(defun server-alive-p ()
  "TCP connect check via port-open-p (singbox.lisp) — deliberately not an
   ICMP ping: many hosts firewall ICMP while the actual proxy port is
   fine, and ping-ok says nothing about whether the proxy service itself
   is still alive. A longer one-shot timeout than wait-until's polling
   default, since this runs once per tick rather than in a tight loop.

   Wrapped in ignore-errors: tick-tunnel/tick-direct call this every
   cycle tick with nothing else guarding it, unlike the reconfigure calls
   around them which are all (ignore-errors ...). Without this, a broken
   /usr/bin/nc (missing binary, bad PATH, etc) would signal out of cycle
   and silently kill the watcher thread instead of just reading as
   'server unreachable' like any other failed check."
  (multiple-value-bind (alive condition)
      (ignore-errors (port-open-p *proxy-server-ip* *proxy-server-port* :timeout 3))
    (when condition
      (format t "~&[dog] server-alive-p check errored (~a) — treating as unreachable~%" condition))
    alive))

(defparameter *tunnel-check-host* "1.1.1.1"
  "External host used to confirm traffic is actually flowing through the
   tunnel (TUN -> tun2socks -> sing-box -> proxy -> internet), as opposed
   to server-alive-p's raw check against *proxy-server-ip*, which is
   excluded from the TUN by its own host route and so says nothing about
   whether the tunnel plumbing itself still works.")
(defparameter *tunnel-check-port* 443)

(defun tunnel-functional-p ()
  "True only if the TUN interface exists AND traffic sent through it
   actually reaches the internet. Unlike server-alive-p (which checks the
   proxy's own reachability over a route that bypasses the TUN), this is
   the one check that can detect a dead/vanished utun interface, a wedged
   tun2socks, or a dead sing-box-side connection to the remote proxy
   after sleep/wake — any of which can break TCP, not just UDP.

   Gates the choice between the two recovery paths in CYCLE: if this is
   false, TCP itself is down, and full-reconfigure (stop-full/start-full
   + a full route rebuild) runs. If this is true but DNS-OVER-UDP-ALIVE-P
   is false, RESTART-TUNNEL-STACK runs instead — cheaper, since it skips
   re-capturing the gateway and re-adding the proxy host route, neither
   of which is what's broken in that case.

   NOTE: RESTART-TUNNEL-STACK now restarts sing-box as well as tun2socks
   (see its docstring — restarting tun2socks alone once left DNS dead
   even with this check passing), so the two recovery paths overlap more
   than they used to; the remaining reason to keep this check separate
   from DNS-OVER-UDP-ALIVE-P is purely the route/gateway cost, not which
   processes get restarted. Once dropped that distinction entirely
   (skipping straight to the cheap path always) and that left the
   internet reliably dead after some real sleep/wake gaps — so keep this
   gate until there's a concrete case showing it's provably redundant,
   not just a theory that it should be."
  (and (ignore-errors (tun-interface-up-p *tun-name*))
       (ignore-errors (port-open-p *tunnel-check-host* *tunnel-check-port* :timeout 3))))

(defun dns-over-udp-alive-p (&key (host *tunnel-check-host*) (timeout 2) (tries 2))
  "True if a real UDP DNS query to HOST:53 gets an answer within TIMEOUT
   seconds per attempt, retrying up to TRIES times. This is the check
   that can see the specific failure this project has been chasing:
   SOCKS5's UDP ASSOCIATE session (which tun2socks needs for anything
   UDP, including DNS) can die across a sleep/wake gap while ordinary
   TCP CONNECT sessions — including the one TUNNEL-FUNCTIONAL-P uses —
   keep working, since each TCP connection opens fresh and shares none
   of that state. A tunnel that passes TUNNEL-FUNCTIONAL-P but fails
   this is exactly 'processes and interface look fine, TCP works, but
   there is no internet.'

   TRIES defaults to 2, not 1: right after a real wake, the very first
   UDP packet through a still-settling path (ARP, the proxy's first
   round-trip since sleep) can occasionally be genuinely slow rather
   than actually dead, and a single 2s/no-retry attempt read that as
   'DNS is dead' often enough to trigger an unwanted restart-tunnel-stack
   (or worse, toggle-wifi) on sleeps that were actually fine — dig's own
   +tries flag does this retry internally, so this is one run-program
   call either way, not TRIES separate ones.
   Uses /usr/bin/dig, which ships with macOS. Queries cloudflare.com as
   a placeholder — the answer's content doesn't matter, only whether a
   NOERROR reply comes back at all within the time budget."
  (let ((lines (run-program-lines "/usr/bin/dig"
                                  (list (format nil "@~a" host)
                                        (format nil "+time=~a" timeout)
                                        (format nil "+tries=~a" tries)
                                        "cloudflare.com"))))
    (and lines (some (lambda (l) (search "status: NOERROR" l)) lines))))

(defun switch-to-config (index)
  "Point everything at *config-pool* entry INDEX and bring the tunnel up
   on it: stop whatever's running, swap *config-path*/*proxy-server-ip*/
   *proxy-server-port* to match, start-full again. Callers are
   responsible for fail-count/sweep bookkeeping around this."
  (let ((entry (nth index *config-pool*)))
    (unless entry
      (error "No pool entry at index ~a (pool has ~a entries)"
             index (length *config-pool*)))
    (destructuring-bind (&key label path ip port) entry
      (format t "~&[dog] switching to pool entry ~a: ~a (~a:~a)~%" index label ip port)
      (ignore-errors (stop-full))
      (setf *config-path* path *proxy-server-ip* ip *proxy-server-port* port)
      (start-full)
      (setf *pool-index* index))))


(defun run-program-lines (program args)
  "Runs PROGRAM with ARGS, returns its stdout as a list of lines, or nil
   if the run errors or produces nothing. Shared by IF-STATUS and
   PHYSICAL-GATEWAY, both of which shell out and scrape a line of output."
  (let ((output (ignore-errors
                 (with-output-to-string (s)
                   (sb-ext:run-program program args :output s :error nil :wait t)))))
    (when output (uiop:split-string output :separator '(#\Newline)))))

(defun field-at (line separator n)
  "Trims LINE, splits it on SEPARATOR, and returns the Nth field, also
   trimmed. Returns nil if LINE is nil (e.g. the line we were looking
   for wasn't found)."
  (when line
    (string-trim '(#\Space #\Tab)
                 (nth n (uiop:split-string (string-trim '(#\Space #\Tab) line)
                                           :separator (list separator))))))

(defun if-status ()
  "Returns (values status ip) for *watched-interface*, e.g. (\"active\"
   \"192.168.1.23\") or (\"inactive\" nil). Never errors — a missing or
   unreadable interface just reads as inactive/nil, which is itself a
   valid 'something about the network changed' signal."
  (let ((lines (run-program-lines "/sbin/ifconfig" (list *watched-interface*))))
    (unless lines (return-from if-status (values "inactive" nil)))
    (values (or (field-at (find-if (lambda (l) (search "status:" l)) lines) #\: 1) "unknown")
            (field-at (find-if (lambda (l) (search "inet " l)) lines) #\Space 1))))

(defun detect-network-change (last-status last-ip cur-status cur-ip)
  "Returns a reason string if ifconfig itself reports something changed
   since the last tick (interface status flip or IP change), else nil.
   This is direct evidence, trusted immediately. A suspected sleep/wake
   gap is a separate, weaker signal — see SLEEP-GAP-P and its handling in
   CYCLE, which requires confirmation against the real gateway before
   acting on it."
  (cond
    ((not (string= cur-status last-status))
     (format nil "~a status ~a -> ~a" *watched-interface* last-status cur-status))
    ((not (equal cur-ip last-ip))
     (format nil "~a IP changed ~a -> ~a" *watched-interface* last-ip cur-ip))))

(defun sleep-gap-p (last-tick now)
  "True if more wall-clock time passed between ticks than
   *sleep-gap-threshold* — grounds to suspect (not conclude) sleep/wake."
  (> (- now last-tick) *sleep-gap-threshold*))

(defun physical-gateway (interface)
  "Returns INTERFACE's real upstream router IPv4 (from its DHCP lease),
   or nil if it can't be determined. Unlike CURRENT-GATEWAY, this reads
   ipconfig's cached lease info directly rather than the kernel routing
   table, so it isn't affected by SETUP-ROUTES having overridden the
   default route to TUN_IP — it keeps seeing the actual router even
   while the tunnel is up."
  (let* ((lines (run-program-lines "/usr/sbin/ipconfig" (list "getoption" interface "router")))
         (gw (and lines (string-trim '(#\Space #\Tab #\Return) (first lines)))))
    (when (and gw (plusp (length gw))) gw)))

(defun toggle-wifi (&optional (interface *watched-interface*) (timeout 30))
  "Power-cycles the Wi-Fi radio on INTERFACE via networksetup, then
   BLOCKS until it's genuinely back (status active AND a real gateway
   reachable via physical-gateway) or TIMEOUT seconds pass. This is the
   fix for a documented macOS/Wi-Fi-driver issue where, after sleep, the
   physical interface itself — below sing-box, tun2socks, and the TUN
   entirely — silently stops carrying UDP while TCP keeps working.
   Confirmed the hard way in this project: restarting sing-box and
   tun2socks both, fresh processes and all, did not fix a case of this,
   because the break sits underneath both of them, in the radio/driver
   state, not in anything this codebase runs. Toggling the interface is
   the only known lever at this layer.

   The wait is not optional. A first version of this returned right
   after issuing the 'on' command, on the theory that CYCLE's own
   network-change detection would pick up the bounce on a later tick.
   In practice, ifconfig can report status \"active\" before DHCP/
   reassociation is actually done, so ticks landing in that window fall
   through to ordinary tick-tunnel logic, which calls server-alive-p —
   and with no real network yet, that fails for a reason that has
   nothing to do with the proxy, indistinguishable (from tick-tunnel's
   side) from 'this pool entry is dead'. Enough consecutive failures
   there rotates through the whole pool and falls back to *regime*
   :direct — confirmed happening in practice once. Blocking here, in
   this single-threaded loop, means no tick can run against a
   half-reassociated interface at all, closing that window rather than
   racing it."
  (ignore-errors
    (sb-ext:run-program "/usr/sbin/networksetup"
                        (list "-setairportpower" interface "off")
                        :input nil :wait t))
  (sleep 2)
  (ignore-errors
    (sb-ext:run-program "/usr/sbin/networksetup"
                        (list "-setairportpower" interface "on")
                        :input nil :wait t))
  (handler-case
      (progn
        (wait-until (lambda ()
                      (multiple-value-bind (status ip) (if-status)
                        (declare (ignore ip))
                        (and (string= status "active") (physical-gateway interface))))
                    :timeout timeout
                    :description (format nil "~a reassociation after Wi-Fi toggle" interface))
        (format t "~&[dog] toggled ~a Wi-Fi radio off/on, reassociated~%" interface)
        t)
    (error (e)
      (format t "~&[dog] toggled ~a Wi-Fi radio off/on, but it did not reassociate within ~as (~a)~%"
              interface timeout e)
      nil)))

(defun full-reconfigure (reason)
  (format t "~&[dog] network change (~a), waiting ~as to settle~%" reason *settle-delay*)
  (sleep *settle-delay*)
  ;; Clear helper state even if the old gateway is unreachable, so restart captures the new one.
  (ignore-errors (stop-full))
  (sleep 1)
  (ignore-errors (start-full))
  (format t "~&[dog] reconfigure done~%"))


(defun local-plumbing-alive-p ()
  "Cheap, no-network liveness check for the local tunnel machinery itself:
   does the TUN interface still exist, and is tun2socks still running.
   Unlike server-alive-p (raw reachability to the proxy, which bypasses
   the TUN and so can't see tun2socks/utun dying) or
   tunnel-functional-p/dns-over-udp-alive-p (real network round-trips,
   reserved for the post-sleep gap check), this only shells out to
   ifconfig/pgrep — safe to run on every single tick without adding
   constant background network traffic. Exists because tun2socks/utun can
   die silently *between* ticks, not just at
   a detected sleep/wake gap or interface change — server-alive-p alone
   would never notice that."
  (and (ignore-errors (tun-interface-up-p *tun-name*))
       (ignore-errors
        (plusp (length (string-trim '(#\Newline #\Space #\Return)
                                     (with-output-to-string (s)
                                       (sb-ext:run-program "/usr/bin/pgrep" (list "-f" "lisp-vpn-tun2socks")
                                                           :output s :error nil :wait t))))))))

(defun tick-tunnel (fail-count)
  "One liveness check while *regime* is :tunnel. Returns the new
   fail-count. On repeated failure, rotates to the next pool entry, or —
   once every entry has failed in this sweep — falls back to :direct."
  (if (not (local-plumbing-alive-p))
      ;; The local pipeline itself (TUN interface / tun2socks) is gone —
      ;; this is not "proxy is down" (server-alive-p wouldn't even catch
      ;; it, see above), so a plain reconfigure is the right fix, not a
      ;; pool rotation to a different server.
      (progn
        (format t "~&[dog] local tunnel plumbing dead (interface/tun2socks gone) — reconfiguring~%")
        (ignore-errors (full-reconfigure "tun2socks/interface vanished mid-tunnel"))
        (setf *sweep-tries* 0)
        0)
      (if (server-alive-p)
          (progn (setf *sweep-tries* 0) 0)
          (let ((fail-count (1+ fail-count)))
            (format t "~&[dog] server unreachable ~a/~a~%" fail-count *fail-threshold*)
            (when (>= fail-count *fail-threshold*)
              (incf *sweep-tries*)
              (format t "~&[dog] pool entry ~a (~a) presumed dead (sweep ~a/~a)~%"
                      *pool-index* (getf (nth *pool-index* *config-pool*) :label)
                      *sweep-tries* (length *config-pool*))
              (setf fail-count 0)
              (if (>= *sweep-tries* (length *config-pool*))
                  ;; Fall back only after every pool entry fails.
                  (progn
                    (format t "~&[dog] whole pool exhausted, falling back to direct~%")
                    (ignore-errors (stop-full))
                    (setf *sweep-tries* 0 *regime* :direct))
                  (let ((next (mod (1+ *pool-index*) (length *config-pool*))))
                    (ignore-errors (switch-to-config next)))))
            fail-count))))

(defun tick-direct (ok-count)
  "One liveness check while *regime* is :direct. Returns the new
   ok-count. Once *revive-threshold* successes in a row, restores the
   tunnel."
  (if (server-alive-p)
      (let ((ok-count (1+ ok-count)))
        (format t "~&[dog] server responding again ~a/~a~%" ok-count *revive-threshold*)
        (when (>= ok-count *revive-threshold*)
          (format t "~&[dog] server revived, restoring tunnel~%")
          (ignore-errors (start-full))
          (setf *regime* :tunnel)
          (setf ok-count 0))
        ok-count)
      0))

(defun cycle ()
  (let ((fail-count 0) (ok-count 0))
    (multiple-value-bind (if-status0 if-ip0) (if-status)
      (let ((last-if-status if-status0)
            (last-if-ip if-ip0)
            (last-gateway (physical-gateway *watched-interface*))
            (last-tick (get-universal-time)))
        (loop while *running* do
              (sleep *poll-interval*)
              (let* ((now (get-universal-time))
                     (gap-seconds (- now last-tick))
                     (gap-p (sleep-gap-p last-tick now)))
                (multiple-value-bind (cur-if-status cur-if-ip) (if-status)
                  (let ((reason (detect-network-change last-if-status last-if-ip
                                                       cur-if-status cur-if-ip)))
                    (setf last-if-status cur-if-status last-if-ip cur-if-ip)
                    (cond
                      ;; ifconfig itself proved something changed — act on it directly.
                      ;; Reconfigure only after an active interface can supply a gateway.
                      ((and reason (string= cur-if-status "active") (eq *regime* :tunnel))
                       (full-reconfigure reason)
                       (setf last-gateway (physical-gateway *watched-interface*))
                       ;; A network change does not count as a pool failure.
                       (setf fail-count 0 ok-count 0 *sweep-tries* 0))
                      ;; Interface is down (Wi-Fi off, etc) — there's no network at
                      ;; all, not "every server died". local-plumbing-alive-p alone
                      ;; can't tell these apart (utun/tun2socks are still alive with
                      ;; no Wi-Fi), so without this branch tick-tunnel would burn
                      ;; through the whole pool via server-alive-p failures that are
                      ;; guaranteed to fail regardless of which server it's pointed
                      ;; at. Skip all checks and hold the counters at zero until the
                      ;; interface comes back — the (reason ...) / gap-p / (t ...)
                      ;; branches below are for when there IS a network to check.
                      ((string= cur-if-status "inactive")
                       (when reason
                         (format t "~&[dog] ~a — interface inactive, pausing checks~%" reason))
                       (setf fail-count 0 ok-count 0 *sweep-tries* 0))
                      (reason
                       (format t "~&[dog] network change (~a) noted, not reconfiguring~%" reason))
                      ;; Suspected sleep/wake: a time gap alone is not proof. Confirm
                      ;; against the actual default gateway before paying for a full
                      ;; teardown+rebuild — most short sleeps come back to the same one.
                      ((and gap-p (eq *regime* :tunnel))
                       (format t "~&[dog] ~as gap since last check, likely sleep/wake — confirming gateway~%"
                               gap-seconds)
                       (sleep *settle-delay*)
                       (let ((cur-gateway (physical-gateway *watched-interface*)))
                         (cond
                           ((null cur-gateway)
                            ;; Can't confirm either way — reconfiguring is the safe
                            ;; default here, same spirit as the old unconditional path.
                            (format t "~&[dog] gateway unreadable after gap, reconfiguring to be safe~%")
                            (full-reconfigure "sleep/wake gap, gateway unreadable")
                            (setf last-gateway (physical-gateway *watched-interface*))
                            (setf fail-count 0 ok-count 0 *sweep-tries* 0))
                           ((not (equal cur-gateway last-gateway))
                            (full-reconfigure (format nil "gateway changed ~a -> ~a after sleep/wake gap"
                                                      last-gateway cur-gateway))
                            (setf last-gateway cur-gateway)
                            (setf fail-count 0 ok-count 0 *sweep-tries* 0))
                           ((not (tunnel-functional-p))
                            ;; TCP through the tunnel is down too, not just
                            ;; UDP/DNS. full-reconfigure (stop-full/start-full +
                            ;; full route rebuild) is still the response here —
                            ;; not because restart-tunnel-stack couldn't fix a
                            ;; dead sing-box connection (it can, see its
                            ;; docstring), but because a gap this broken
                            ;; warrants recapturing the gateway/routes too,
                            ;; rather than assuming they're still fine.
                            (format t "~&[dog] gateway unchanged (~a) but tunnel not functional after gap, reconfiguring~%"
                                    cur-gateway)
                            (full-reconfigure "sleep/wake gap, tunnel not functional")
                            (setf last-gateway (physical-gateway *watched-interface*))
                            (setf fail-count 0 ok-count 0 *sweep-tries* 0))
                           ((not (dns-over-udp-alive-p))
                            ;; TCP through the tunnel is fine, but UDP/DNS
                            ;; specifically is dead. First try the cheap fix:
                            ;; restart-tunnel-stack (sing-box + tun2socks),
                            ;; without touching routes/gateway.
                            (format t "~&[dog] gateway unchanged (~a), tunnel functional, but UDP/DNS dead after gap — restarting tunnel stack~%"
                                    cur-gateway)
                            (ignore-errors (restart-tunnel-stack))
                            (sleep 2)
                            (unless (ignore-errors (dns-over-udp-alive-p))
                              ;; Software restart alone didn't fix it — this
                              ;; points below sing-box/tun2socks entirely, to
                              ;; a documented macOS Wi-Fi driver quirk where
                              ;; the radio silently stops carrying UDP after
                              ;; sleep while TCP keeps working, and no amount
                              ;; of restarting userspace processes touches
                              ;; it. The only known fix is power-cycling the
                              ;; Wi-Fi radio itself.
                              (format t "~&[dog] still dead after tunnel stack restart — toggling Wi-Fi radio~%")
                              (if (ignore-errors (toggle-wifi))
                                  (progn
                                    ;; toggle-wifi already blocked until real
                                    ;; reassociation, so rebuild explicitly now
                                    ;; rather than betting on the next tick's
                                    ;; detect-network-change to notice — if
                                    ;; DHCP happens to hand back the exact same
                                    ;; IP, there's no IP-change for it to catch,
                                    ;; and nothing would ever rebuild the
                                    ;; tunnel. Resync last-if-status/last-if-ip
                                    ;; to the post-toggle state too, so that
                                    ;; tick doesn't also see a "change" and fire
                                    ;; a second, redundant reconfigure.
                                    (full-reconfigure "Wi-Fi toggle recovered from stuck UDP")
                                    (multiple-value-bind (s i) (if-status)
                                      (setf last-if-status s last-if-ip i))
                                    (setf last-gateway (physical-gateway *watched-interface*)))
                                  ;; toggle-wifi itself timed out waiting for
                                  ;; reassociation — nothing this codebase runs
                                  ;; can fix that; leave *regime* as-is and let
                                  ;; the next gap/tick keep retrying rather than
                                  ;; guessing further here.
                                  (format t "~&[dog] Wi-Fi did not reassociate — leaving for next tick to retry~%")))
                            (setf fail-count 0 ok-count 0 *sweep-tries* 0))
                           (t
                            (format t "~&[dog] gateway unchanged (~a), tunnel and DNS functional, skipping reconfigure~%"
                                    cur-gateway)))))
                      (t
                       ;; Quiet tick: keep our notion of the current gateway fresh so
                       ;; the next gap (if any) has an accurate baseline to compare to.
                       (setf last-gateway (or (physical-gateway *watched-interface*) last-gateway))
                       (ecase *regime*
                         (:tunnel (setf fail-count (tick-tunnel fail-count)))
                         (:direct (setf ok-count (tick-direct ok-count))))))
                    ;; Stamped last, after all of the above (including any blocking
                    ;; full-reconfigure) has finished — gap-seconds on the NEXT tick
                    ;; must measure real idle time between checks, not the time this
                    ;; tick itself spent reconfiguring. Stamping this at the top of
                    ;; the tick (before reconfigure ran) made every reconfigure look
                    ;; like a fresh sleep/wake gap on the following tick, which kept
                    ;; re-triggering itself into an infinite reconfigure loop.
                    (setf last-tick (get-universal-time))))))))))


(defun watch ()
  (when (and *thread* (sb-thread:thread-alive-p *thread*))
    (format t "~&Already watching~%")
    (return-from watch))
  (setf *regime* :tunnel)
  (setf *running* t)
  ;; Threads do not inherit REPL stream bindings.
  (let ((out *standard-output*)
        (err *error-output*))
    (setf *thread*
          (sb-thread:make-thread
           (lambda ()
             (let ((*standard-output* out)
                   (*error-output* err))
               (cycle)))
           :name "dog")))
  (format t "~&Watching started~%"))

(defun unwatch ()
  (setf *running* nil)
  (format t "~&Watching stopping (will exit after current sleep)~%"))

(defun watch? ()
  (multiple-value-bind (status ip) (if-status)
    (format t "~&Regime: ~a~%Running: ~a~%Watching: ~a:~a~%Interface: ~a (status ~a, ip ~a)~%"
            *regime*
            (and *thread* (sb-thread:thread-alive-p *thread*))
            *proxy-server-ip* *proxy-server-port*
            *watched-interface* status ip)))


(defun connect ()
  "(load \"dog.lisp\") (connect) — nothing else to load or call by hand."
  (if *config-pool*
      (switch-to-config 0)
      (start-full))
  (watch))

(defun disconn ()
  "Inverse of connect. unwatch only flips a flag — the watcher thread
   might be mid-iteration and could still be running its own stop-full/
   start-full right now. Join it first, so this thread's stop-full below
   can never run concurrently with one from the watcher thread."
  (unwatch)
  (when (and *thread* (sb-thread:thread-alive-p *thread*))
    (sb-thread:join-thread *thread* :default nil))
  (stop-full))