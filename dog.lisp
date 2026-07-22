;;; A single watcher serializes tunnel reconfiguration.

(let ((here (or *load-truename* *load-pathname*
                (error "dog.lisp must be loaded via (load ...), not evaluated form by form — ~
                        *load-truename* is how it finds singbox-ctl.lisp and tun-ctl.lisp next to it"))))
  (load (merge-pathnames "singbox-ctl.lisp" here))
  (load (merge-pathnames "tun-ctl.lisp" here))
  (load (merge-pathnames "singbox-outbound.lisp" here)))


(defparameter *proxy-server-port* 8080
  "Port of the currently active proxy server. Update this alongside
   *proxy-server-ip* whenever you switch configs.")

;;; Keep one live outbound: the privileged helper excludes only one proxy IP from the tunnel.
(defparameter *server-list-path* "/tmp/servers.txt"
  "One vless:// or ss:// URI per line, # for comments/blank lines ignored.
   See singbox-outbound.lisp's read-uri-lines/load-server-pool.")

(defparameter *pool-config-dir* "/tmp/pool-configs/"
  "Where load-server-pool writes one complete sing-box config file per
   entry in *server-list-path*.")

(defun try-load-server-pool ()
  "Wraps load-server-pool so a missing/unreadable *server-list-path* never
   aborts loading the rest of dog.lisp — everything below this point
   (watch, connect, cycle...) must still get defined even on a fresh
   checkout with no servers.txt yet. Degrades to an empty pool instead,
   which the sweep logic in cycle already treats as \"nothing to try,
   fall back to direct on first failure\" — the same behavior as before
   the pool existed at all."
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
   reaction to a real change, since recovery is automatic anyway.")

(defparameter *fail-threshold* 8
  "Consecutive failed proxy checks before declaring the server dead and
   falling back to direct. At *poll-interval*=5 this is ~40s.")

(defparameter *revive-threshold* 8
  "Consecutive successful proxy checks (while in fallback) before
   restoring the tunnel. Same ~40s window as *fail-threshold* — a false
   positive either way just costs one extra reconfigure cycle, the next
   tick catches and corrects it.")


(defparameter *watched-interface* "en0"
  "Physical interface to watch for status/IP changes — Wi-Fi on most Macs.
   Check `networksetup -listallhardwareports` if en0 isn't right on yours.")

(defparameter *sleep-gap-threshold* 20
  "If more wall-clock time passes between two ticks than this, conclude
   the machine was asleep, regardless of what ifconfig reports right now.
   Must be comfortably larger than *poll-interval*.")

(defparameter *settle-delay* 5
  "Seconds to wait after detecting a network change, before reconfiguring
   — gives DHCP/DNS a moment to actually come back up. Reconfiguring
   against a half-up interface just reproduces the original 'no internet'
   failure mode.")


(defparameter *thread* nil)
(defparameter *running* nil)
(defparameter *regime* :tunnel)


(defun tcp-alive-p (host port &key (timeout 3))
  "TCP connect check via nc — true if something accepts a connection
   on host:port within timeout seconds. Deliberately not an ICMP
   ping: many hosts firewall ICMP while the actual proxy port is
   fine, and ping-ok says nothing about whether the proxy service
   itself is still alive."
  (let ((proc (sb-ext:run-program "/usr/bin/nc"
                                  (list "-z" "-w" (princ-to-string timeout)
                                        host (princ-to-string port))
                                  :output nil :error nil :wait t)))
    (zerop (sb-ext:process-exit-code proc))))

(defun server-alive-p ()
  (tcp-alive-p *proxy-server-ip* *proxy-server-port*))

(defun switch-to-config (index)
  "Point everything at *config-pool* entry INDEX and bring the tunnel up
   on it: stop whatever's running, swap *config-path*/*proxy-server-ip*/
   *proxy-server-port* to match, start-full again. Callers are
   responsible for fail-count/sweep bookkeeping around this."
  (let* ((entry (nth index *config-pool*)))
    (unless entry
      (error "No pool entry at index ~a (pool has ~a entries)"
             index (length *config-pool*)))
    (format t "~&[dog] switching to pool entry ~a: ~a (~a:~a)~%"
            index (getf entry :label) (getf entry :ip) (getf entry :port))
    (ignore-errors (stop-full))
    (setf *config-path* (getf entry :path))
    (setf *proxy-server-ip* (getf entry :ip))
    (setf *proxy-server-port* (getf entry :port))
    (start-full)
    (setf *pool-index* index)))


(defun if-status ()
  "Returns (values status ip) for *watched-interface*, e.g. (\"active\"
   \"192.168.1.23\") or (\"inactive\" nil). Never errors — a missing or
   unreadable interface just reads as inactive/nil, which is itself a
   valid 'something about the network changed' signal."
  (let ((output (ignore-errors
                 (with-output-to-string (s)
                   (sb-ext:run-program "/sbin/ifconfig" (list *watched-interface*)
                                       :output s :error nil :wait t)))))
    (unless output
      (return-from if-status (values "inactive" nil)))
    (let* ((lines (uiop:split-string output :separator '(#\Newline)))
           (status-line (find-if (lambda (l) (search "status:" l)) lines))
           (inet-line (find-if (lambda (l) (search "inet " l)) lines))
           (status (if status-line
                       (string-trim '(#\Space #\Tab)
                                    (second (uiop:split-string status-line :separator '(#\:))))
                       "unknown"))
           (ip (when inet-line
                 (second (uiop:split-string (string-trim '(#\Space #\Tab) inet-line)
                                            :separator '(#\Space))))))
      (values status ip))))

(defun detect-network-change (last-status last-ip last-tick now cur-status cur-ip)
  "Returns a reason string if something changed since the last tick, else nil."
  (cond
    ((> (- now last-tick) *sleep-gap-threshold*)
     (format nil "~as gap since last check, likely sleep/wake" (- now last-tick)))
    ((not (string= cur-status last-status))
     (format nil "~a status ~a -> ~a" *watched-interface* last-status cur-status))
    ((not (equal cur-ip last-ip))
     (format nil "~a IP changed ~a -> ~a" *watched-interface* last-ip cur-ip))))


(defun full-reconfigure (reason)
  (format t "~&[dog] network change (~a), waiting ~as to settle~%" reason *settle-delay*)
  (sleep *settle-delay*)
  ;; Clear helper state even if the old gateway is unreachable, so restart captures the new one.
  (ignore-errors (stop-full))
  (sleep 1)
  (ignore-errors (start-full))
  (format t "~&[dog] reconfigure done~%"))


(defun cycle ()
  (let ((fail-count 0) (ok-count 0))
    (multiple-value-bind (if-status0 if-ip0) (if-status)
      (let ((last-if-status if-status0)
            (last-if-ip if-ip0)
            (last-tick (get-universal-time)))
        (loop while *running* do
              (sleep *poll-interval*)
              (let ((now (get-universal-time)))
                (multiple-value-bind (cur-if-status cur-if-ip) (if-status)
                  (let ((reason (detect-network-change last-if-status last-if-ip last-tick
                                                       now cur-if-status cur-if-ip)))
                    (setf last-if-status cur-if-status last-if-ip cur-if-ip last-tick now)
                    (cond
                      ;; Reconfigure only after an active interface can supply a gateway.
                      ((and reason (string= cur-if-status "active") (eq *regime* :tunnel))
                       (full-reconfigure reason)
                       ;; A network change does not count as a pool failure.
                       (setf fail-count 0 ok-count 0 *sweep-tries* 0))
                      (reason
                       (format t "~&[dog] network change (~a) noted, not reconfiguring~%" reason))
                      (t
                       (ecase *regime*
                         (:tunnel
                          (if (server-alive-p)
                              (progn (setf fail-count 0) (setf *sweep-tries* 0))
                              (progn
                                (incf fail-count)
                                (format t "~&[dog] server unreachable ~a/~a~%"
                                        fail-count *fail-threshold*)
                                (when (>= fail-count *fail-threshold*)
                                  (incf *sweep-tries*)
                                  (format t "~&[dog] pool entry ~a (~a) presumed dead (sweep ~a/~a)~%"
                                          *pool-index*
                                          (getf (nth *pool-index* *config-pool*) :label)
                                          *sweep-tries* (length *config-pool*))
                                  (setf fail-count 0)
                                  (if (>= *sweep-tries* (length *config-pool*))
                                      ;; Fall back only after every pool entry fails.
                                      (progn
                                        (format t "~&[dog] whole pool exhausted, falling back to direct~%")
                                        (ignore-errors (stop-full))
                                        (setf ok-count 0 *sweep-tries* 0)
                                        (setf *regime* :direct))
                                      (let ((next (mod (1+ *pool-index*) (length *config-pool*))))
                                        (ignore-errors (switch-to-config next))))))))
                         (:direct
                          (if (server-alive-p)
                              (progn
                                (incf ok-count)
                                (format t "~&[dog] server responding again ~a/~a~%"
                                        ok-count *revive-threshold*)
                                (when (>= ok-count *revive-threshold*)
                                  (format t "~&[dog] server revived, restoring tunnel~%")
                                  (ignore-errors (start-full))
                                  (setf fail-count 0 ok-count 0)
                                  (setf *regime* :tunnel)))
                              (setf ok-count 0))))))))))))))


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
  (multiple-value-bind (if-status ip) (if-status)
    (format t "~&Regime: ~a~%Running: ~a~%Watching: ~a:~a~%Interface: ~a (status ~a, ip ~a)~%"
            *regime*
            (and *thread* (sb-thread:thread-alive-p *thread*))
            *proxy-server-ip* *proxy-server-port*
            *watched-interface* if-status ip)))


(defun connect ()
  "(load \"dog.lisp\") (connect) — the whole thing: sing-box, tun2socks,
   routes, and the watcher thread. Nothing else to load or call by hand."
  (if *config-pool*
      (switch-to-config 0)
      (start-full))
  (watch))

(defun disconnect ()
  "Inverse of connect. unwatch only flips a flag — the watcher thread
   might be mid-iteration and could still be running its own stop-full/
   start-full right now. Join it first, so this thread's stop-full below
   can never run concurrently with one from the watcher thread."
  (unwatch)
  (when (and *thread* (sb-thread:thread-alive-p *thread*))
    (sb-thread:join-thread *thread* :default nil))
  (stop-full))
