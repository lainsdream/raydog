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

(defun restart-tun2socks ()
  "Restarts just tun2socks (stop-tun + start-tun + assign-tun-ip +
   reassert-default-route) without touching setup-routes/teardown-routes
   or the captured gateway. This is the targeted fix for tun2socks's
   SOCKS5 UDP ASSOCIATE session dying across a sleep/wake gap (breaking
   UDP — in particular DNS — while ordinary TCP keeps working, since
   each TCP connection opens fresh): the interface disappears and comes
   back via stop-tun/start-tun, which is enough to reset that session,
   without paying for a full teardown+rebuild of the gateway capture or
   proxy host route, which were never actually broken.

   reassert-default-route is not optional here — without it the
   interface comes back but nothing sends traffic through it at all,
   since the kernel default route was dropped along with the old utun9."
  (ignore-errors (stop-tun))
  (start-tun)
  (assign-tun-ip)
  (reassert-default-route)
  (format t "~&[dog] tun2socks restarted~%"))

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