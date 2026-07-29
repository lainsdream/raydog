(defparameter *setsid-bin* "/opt/homebrew/opt/util-linux/bin/setsid")
(defparameter *singbox-bin* "/opt/homebrew/bin/sing-box")
(defparameter *config-path* nil
  "Path to the sing-box JSON config. Not hardcoded here when going through
   dog.lisp/connect — switch-to-config overwrites it via
   (setf *config-path* ...) on every pool-entry switch, before the first
   (start). On the manual path (without dog.lisp), set it yourself, e.g.
   (setf *config-path* \"/tmp/ss-config.json\"), before calling
   (start)/(start-full).")
(defparameter *log-path* "/tmp/singbox.log")
(defparameter *socks-port* 1080
  "Must match listen_port of the `mixed`/socks inbound in *config-path* —
   this is what we poll to decide sing-box is actually up.")
(defparameter *start-timeout* 10
  "Seconds to wait for sing-box's SOCKS port before giving up. Generous on
   purpose: a cold sing-box start (DNS resolution of the outbound server,
   TLS handshake setup, etc.) can occasionally take a couple of seconds,
   and a spurious timeout error is a much better failure mode than racing
   ahead with tun2socks/routes and only failing to make one clear.")
(defparameter *process* nil)
(defparameter *singbox-pid* nil
  "PID of the actual sing-box process, captured via PGREP-SINGBOX-PID once
   the SOCKS port is confirmed open. *process* (the run-program handle) is
   NOT reliable for this: *setsid-bin* forks and the parent exits almost
   immediately, so *process* tracks setsid, not sing-box, and goes dead
   moments after start returns -- confirmed empirically via
   (sb-ext:process-alive-p *process*) reading NIL while the tunnel was
   still up and traffic still flowing. STOP kills by this PID (after a
   same-instant identity re-check, see SINGBOX-PID-MATCHES-P) instead of
   relying on *process*.")

(defun pgrep-singbox-pid ()
  "Finds the sing-box process running with our *config-path*, via
   `pgrep -f`. Matching on the full config path (not just \"sing-box
   run\") disambiguates from any other sing-box instance that might be
   running with a different config, which a bare name match can't do --
   see FIND-AND-KILL-BY-NAME's comment on this same risk. Returns the PID
   as an integer, or NIL if none/multiple/unparseable matched -- callers
   fall back to FIND-AND-KILL-BY-NAME in that case, same as before this
   existed."
  (let ((output (with-output-to-string (s)
                  (ignore-errors
                   (sb-ext:run-program "/usr/bin/pgrep"
                                       (list "-f" (format nil "sing-box run -c ~a" *config-path*))
                                       :output s :wait t)))))
    (let ((pids (remove-if (lambda (l) (zerop (length l)))
                            (uiop:split-string output :separator '(#\Newline)))))
      (when (= (length pids) 1)
        (ignore-errors (parse-integer (string-trim '(#\Space #\Return) (first pids))))))))

(defun singbox-pid-matches-p (pid)
  "Re-checks, at kill time, that PID is still a sing-box process running
   our *config-path* -- guards against PID reuse in the gap between
   capturing *singbox-pid* in START and calling STOP later (same spirit
   as is_our_tun2socks in lisp-vpn-priv.c, just without a privileged
   proc_pidpath lookup available here)."
  (let ((cmd (with-output-to-string (s)
               (ignore-errors
                (sb-ext:run-program "/bin/ps" (list "-p" (princ-to-string pid) "-o" "command=")
                                    :output s :wait t)))))
    (search *config-path* cmd)))

(defun wait-until (predicate &key (timeout 10) (interval 0.2) description)
  "Poll PREDICATE every INTERVAL seconds until it returns true, or signal
   an error naming DESCRIPTION once TIMEOUT seconds have passed."
  (let ((deadline (+ (get-internal-real-time)
                      (round (* timeout internal-time-units-per-second)))))
    (loop
      (when (funcall predicate)
        (return t))
      (when (> (get-internal-real-time) deadline)
        (error "Timed out after ~as waiting for ~a"
               timeout (or description "condition")))
      (sleep interval))))

(defun port-open-p (host port &key (timeout 1))
  "True if something accepts a TCP connection on host:port within TIMEOUT
   seconds. Default is a short 1s timeout, meant for wait-until's repeated
   polling; dog.lisp's server-alive-p passes a longer timeout since it's a
   one-shot liveness check instead."
  (zerop (sb-ext:process-exit-code
          (sb-ext:run-program "/usr/bin/nc"
                              (list "-z" "-w" (princ-to-string timeout)
                                    host (princ-to-string port))
                              :output nil :error nil :wait t))))

(defun start ()
  (when (and *process* (sb-ext:process-alive-p *process*))
    (format t "~&Already running~%")
    (return-from start))
  (setf *process*
        (sb-ext:run-program *setsid-bin*
                            (list *singbox-bin* "run" "-c" *config-path*)
                            :output *log-path*
                            :error :output
                            :if-output-exists :supersede
                            :wait nil))
  ;; setsid exits after forking; only the SOCKS port confirms sing-box readiness.
  (wait-until (lambda () (port-open-p "127.0.0.1" *socks-port*))
              :timeout *start-timeout*
              :description (format nil "sing-box SOCKS port 127.0.0.1:~a (check ~a)"
                                    *socks-port* *log-path*))
  (setf *singbox-pid* (pgrep-singbox-pid))
  (format t "~&Started, pid ~a~%" (or *singbox-pid* "unknown -- stop will fall back to pgrep -f by name")))

;; This fallback remains unprivileged even when the process handle is lost.
(defun find-and-kill-by-name (name)
  (let ((output (with-output-to-string (s)
                  (ignore-errors
                   (sb-ext:run-program "/usr/bin/pgrep" (list "-f" name)
                                       :output s :wait t)))))
    (dolist (line (uiop:split-string output :separator '(#\Newline)))
      (let ((pid (string-trim '(#\Space #\Return) line)))
        (when (plusp (length pid))
          (sb-ext:run-program "/bin/kill" (list "-9" pid)
                              :input nil :wait t))))))

(defun stop ()
  (cond
    ;; Preferred path: kill the specific, identity-checked sing-box PID.
    ((and *singbox-pid* (singbox-pid-matches-p *singbox-pid*))
     (sb-ext:run-program "/bin/kill" (list "-9" (princ-to-string *singbox-pid*))
                         :input nil :wait t))
    ;; *process* is almost always already dead by the time STOP runs (see
    ;; *singbox-pid*'s docstring) -- kept as a secondary path in case
    ;; *singbox-pid* was never captured (e.g. START's pgrep raced/failed).
    ((and *process* (sb-ext:process-alive-p *process*))
     (sb-ext:process-kill *process* 9)
     (sb-ext:process-wait *process*))
    ;; Last resort: match by command-line name only, same caveat as ever
    ;; -- can hit an unrelated sing-box process. See README.
    (t (find-and-kill-by-name "sing-box run")))
  (setf *process* nil *singbox-pid* nil)
  (format t "~&Stopped~%"))

(defun status ()
  (cond
    ((and *singbox-pid* (singbox-pid-matches-p *singbox-pid*))
     (format t "~&Running, pid ~a~%" *singbox-pid*))
    ((and *process* (sb-ext:process-alive-p *process*))
     (format t "~&Running, pid ~a~%" (sb-ext:process-pid *process*)))
    (t (format t "~&Not running~%"))))