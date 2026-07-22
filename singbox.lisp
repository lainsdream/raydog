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
  (format t "~&Started, pid ~a~%" (sb-ext:process-pid *process*)))

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
  (if (and *process* (sb-ext:process-alive-p *process*))
      (progn
        (sb-ext:process-kill *process* 9)
        (sb-ext:process-wait *process*))
      (find-and-kill-by-name "sing-box run"))
  (setf *process* nil)
  (format t "~&Stopped~%"))

(defun status ()
  (if (and *process* (sb-ext:process-alive-p *process*))
      (format t "~&Running, pid ~a~%" (sb-ext:process-pid *process*))
      (format t "~&Not running~%")))
