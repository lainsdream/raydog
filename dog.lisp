;;; A single watcher serializes tunnel reconfiguration.

(eval-when (:compile-toplevel :load-toplevel :execute)
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
   CURRENT-GATEWAY, both of which shell out and scrape a line of output."
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

(defun current-gateway ()
  "Returns the current default gateway IPv4 as a string, or nil if it
   can't be determined (no default route, /sbin/route missing/erred, or
   unparseable output). Used to confirm a suspected sleep/wake gap
   actually changed something real, instead of trusting the gap alone.
   Never errors — a failure to read just reads as nil, same spirit as
   IF-STATUS reading a missing interface as inactive/nil."
  (let* ((lines (run-program-lines "/sbin/route" (list "-n" "get" "default")))
         (gw (field-at (find-if (lambda (l) (search "gateway:" l)) lines) #\: 1)))
    (when (and gw (plusp (length gw))) gw)))


(defun full-reconfigure (reason)
  (format t "~&[dog] network change (~a), waiting ~as to settle~%" reason *settle-delay*)
  (sleep *settle-delay*)
  ;; Clear helper state even if the old gateway is unreachable, so restart captures the new one.
  (ignore-errors (stop-full))
  (sleep 1)
  (ignore-errors (start-full))
  (format t "~&[dog] reconfigure done~%"))


(defun tick-tunnel (fail-count)
  "One liveness check while *regime* is :tunnel. Returns the new
   fail-count. On repeated failure, rotates to the next pool entry, or —
   once every entry has failed in this sweep — falls back to :direct."
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
        fail-count)))

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
            (last-gateway (current-gateway))
            (last-tick (get-universal-time)))
        (loop while *running* do
              (sleep *poll-interval*)
              (let* ((now (get-universal-time))
                     (gap-seconds (- now last-tick))
                     (gap-p (sleep-gap-p last-tick now)))
                (multiple-value-bind (cur-if-status cur-if-ip) (if-status)
                  (let ((reason (detect-network-change last-if-status last-if-ip
                                                       cur-if-status cur-if-ip)))
                    ;; last-tick is overwritten to now right here — gap-seconds above
                    ;; is captured first so later log lines don't show a bogus "0s".
                    (setf last-if-status cur-if-status last-if-ip cur-if-ip last-tick now)
                    (cond
                      ;; ifconfig itself proved something changed — act on it directly.
                      ;; Reconfigure only after an active interface can supply a gateway.
                      ((and reason (string= cur-if-status "active") (eq *regime* :tunnel))
                       (full-reconfigure reason)
                       (setf last-gateway (current-gateway))
                       ;; A network change does not count as a pool failure.
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
                       (let ((cur-gateway (current-gateway)))
                         (cond
                           ((null cur-gateway)
                            ;; Can't confirm either way — reconfiguring is the safe
                            ;; default here, same spirit as the old unconditional path.
                            (format t "~&[dog] gateway unreadable after gap, reconfiguring to be safe~%")
                            (full-reconfigure "sleep/wake gap, gateway unreadable")
                            (setf last-gateway (current-gateway))
                            (setf fail-count 0 ok-count 0 *sweep-tries* 0))
                           ((equal cur-gateway last-gateway)
                            (format t "~&[dog] gateway unchanged (~a) after gap, skipping reconfigure~%"
                                    cur-gateway))
                           (t
                            (full-reconfigure (format nil "gateway changed ~a -> ~a after sleep/wake gap"
                                                      last-gateway cur-gateway))
                            (setf last-gateway cur-gateway)
                            (setf fail-count 0 ok-count 0 *sweep-tries* 0)))))
                      (t
                       ;; Quiet tick: keep our notion of the current gateway fresh so
                       ;; the next gap (if any) has an accurate baseline to compare to.
                       (setf last-gateway (or (current-gateway) last-gateway))
                       (ecase *regime*
                         (:tunnel (setf fail-count (tick-tunnel fail-count)))
                         (:direct (setf ok-count (tick-direct ok-count))))))))))))))


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

(defun disconnect ()
  "Inverse of connect. unwatch only flips a flag — the watcher thread
   might be mid-iteration and could still be running its own stop-full/
   start-full right now. Join it first, so this thread's stop-full below
   can never run concurrently with one from the watcher thread."
  (unwatch)
  (when (and *thread* (sb-thread:thread-alive-p *thread*))
    (sb-thread:join-thread *thread* :default nil))
  (stop-full))
