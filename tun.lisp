(defparameter *priv-helper-bin* "/usr/local/libexec/lisp-vpn-priv")
(defparameter *tun-name* "utun9")
(defparameter *proxy-server-ip* nil
  "IP of the currently active server — important to exclude it from the
   tunnel via a host route. Not hardcoded here: dog.lisp overwrites it via
   (setf *proxy-server-ip* ...) in switch-to-config on every pool-entry
   switch, before the first start-full. Declared here as a special var
   because setup-routes/teardown-routes in this file are its only
   consumers.")
(defparameter *tun-start-timeout* 10
  "Seconds to wait for the TUN interface to actually appear after
   start-tun. lisp-vpn-priv's start-tun subcommand spawns tun2socks via
   setsid in the background and returns as soon as it's launched, not
   once the interface exists — so `privileged` returning is not itself a
   readiness signal, same reasoning as sing-box's SOCKS port in
   singbox.lisp.")

;; The privileged helper alone captures and restores the original gateway.

(defun tun-interface-up-p (name)
  "True once NAME shows up as a real interface via ifconfig — this is the
   actual readiness signal for start-tun, polled by wait-until (defined in
   singbox.lisp, loaded before this file) instead of guessing with a
   fixed sleep."
  (zerop (sb-ext:process-exit-code
          (sb-ext:run-program "/sbin/ifconfig" (list name)
                              :output nil :error nil :wait t))))

(defun privileged (&rest arguments)
  (let ((proc (sb-ext:run-program "/usr/bin/sudo"
                                  (append (list "-n" *priv-helper-bin*) arguments)
                                  :output *standard-output* :error :output
                                  :input nil :wait t)))
    (unless (zerop (sb-ext:process-exit-code proc))
      (error "lisp-vpn-priv failed: ~{~a~^ ~}" arguments))))

(defun setup-routes ()
  (privileged "setup-routes" *proxy-server-ip*))

(defun teardown-routes ()
  (privileged "teardown-routes" *proxy-server-ip*))

(defun assign-tun-ip ()
  (privileged "assign-tun" *tun-name*))

(defun start-tun ()
  (privileged "start-tun" *tun-name*)
  (wait-until (lambda () (tun-interface-up-p *tun-name*))
              :timeout *tun-start-timeout*
              :description (format nil "TUN interface ~a to appear" *tun-name*))
  (format t "~&tun2socks started~%"))

(defun stop-tun ()
  (privileged "stop-tun")
  (format t "~&tun2socks stopped~%"))

(defun reassert-default-route ()
  "Re-points the kernel's default route at TUN_IP without touching the
   captured original gateway or the proxy host route — unlike
   setup-routes, safe to call again even though GWFILE already exists.
   Needed because macOS drops the default route entry when the utun
   interface it points through is destroyed (which stop-tun does, since
   killing tun2socks tears down the utun device with it) — so recreating
   utun9 via start-tun brings the interface back with the same IP, but
   nothing re-points default at it until this runs."
  (privileged "reassert-default"))

(defun restart-tunnel-stack ()
  "Restarts sing-box and tun2socks (sing-box first, then tun2socks +
   assign-tun-ip + reassert-default-route), without touching
   setup-routes/teardown-routes or the captured gateway.

   Originally this (as RESTART-TUN2SOCKS) restarted only tun2socks, on
   the theory that a dead SOCKS5 UDP ASSOCIATE session was purely local
   to tun2socks's side of that association, so restarting sing-box too
   would just be extra cost for no extra benefit. In practice that left
   DNS/UDP dead even in cases where tunnel-functional-p (TCP) had passed
   right before the restart — meaning the stale state can also live on
   sing-box's side (its own connection/session to the remote proxy),
   which restarting tun2socks alone can never touch, since sing-box
   itself was never killed. Restarting sing-box first forces a fresh
   end-to-end connection to the remote proxy; tun2socks then reconnects
   to a clean SOCKS5 endpoint rather than a stale one.

   Still far cheaper than full-reconfigure: no teardown-routes/
   setup-routes round-trip, no gateway re-capture, no proxy host route
   change — those were never what was broken here.

   reassert-default-route is not optional — without it tun2socks's
   interface comes back but nothing sends traffic through it at all,
   since the kernel default route was dropped along with the old utun9."
  (ignore-errors (stop))
  (start)
  (ignore-errors (stop-tun))
  (start-tun)
  (assign-tun-ip)
  (reassert-default-route)
  (format t "~&[dog] tunnel stack restarted (sing-box + tun2socks)~%"))

(defun start-full ()
  (start)
  (start-tun)
  (assign-tun-ip)
  (setup-routes)
  (format t "~&Full TUN setup complete~%"))

(defun stop-full ()
  (ignore-errors (teardown-routes))
  (ignore-errors (stop-tun))
  (ignore-errors (stop))
  (format t "~&Routes restored~%"))