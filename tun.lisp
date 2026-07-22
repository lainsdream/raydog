(defparameter *priv-helper-bin* "/usr/local/libexec/lisp-vpn-priv")
(defparameter *tun-name* "utun9")
(defparameter *proxy-server-ip* nil
  "IP текущего активного сервера — ВАЖНО исключить его из туннеля
   host-route'ом. Само значение сюда не хардкодится: dog.lisp
   перезаписывает его через (setf *proxy-server-ip* ...) в
   switch-to-config при каждом переключении на новый пул-энтри, ещё до
   первого start-full. Переменная объявлена здесь как special var,
   потому что setup-routes/teardown-routes в этом файле — единственные
   её потребители.")
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

(defun start-full ()
  (start)
  (start-tun)
  (assign-tun-ip)
  (setup-routes)
  (format t "~&Full TUN setup complete~%"))

(defun stop-full ()
  (teardown-routes)
  (stop-tun)
  (stop)
  (format t "~&Routes restored~%"))
