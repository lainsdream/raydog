;;; Tests for config.lisp only — the one file here with no side effects
;;; (no sudo, no processes, no network). singbox.lisp/tun.lisp/dog.lisp
;;; are exercised by hand via (connect) + the curl check in README, not
;;; here; mocking sudo/routes/processes would cost more than it catches.
;;;
;;; Usage:
;;;   (load "tests.lisp")   ; loads config.lisp itself, no need to load it first
;;;   (run-tests)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (let ((here (or *load-truename* *load-pathname*
                  *compile-file-truename* *compile-file-pathname*
                  (error "tests.lisp must be loaded via (load ...), not evaluated form by form"))))
    (load (merge-pathnames "config.lisp" here))))

(defparameter *fail-count* 0)
(defparameter *check-count* 0)

(defmacro check (label form expected)
  "Evaluate FORM once, compare to EXPECTED with EQUAL. Prints on failure
   only — a clean run is silent except for the final summary."
  `(progn
     (incf *check-count*)
     (let ((got ,form))
       (unless (equal got ,expected)
         (incf *fail-count*)
         (format t "~&FAIL ~a~%     got:      ~s~%     expected: ~s~%"
                 ,label got ,expected)))))

(defmacro check-error (label &body form)
  "Like check, but expects FORM to signal an error rather than return."
  `(progn
     (incf *check-count*)
     (let ((signalled nil))
       (handler-case (progn ,@form)
         (error () (setf signalled t)))
       (unless signalled
         (incf *fail-count*)
         (format t "~&FAIL ~a~%     expected an error, form returned normally~%" ,label)))))


;;; --- b64-decode ---

(defun test-b64-decode ()
  (check "b64-decode: padded"        (b64-decode "SGVsbG8=") "Hello")
  (check "b64-decode: no padding"    (b64-decode "SGVsbG8")  "Hello")
  (check "b64-decode: url-safe -_"   (b64-decode "-_") (b64-decode "+/"))
  (check "b64-decode: empty"         (b64-decode "") ""))


;;; --- url-decode ---

(defun test-url-decode ()
  (check "url-decode: plain passthrough" (url-decode "hello") "hello")
  (check "url-decode: percent-escape"    (url-decode "a%20b") "a b")
  (check "url-decode: trailing literal %" (url-decode "100%") "100%"))


;;; --- split-once / split-last / str-split / parse-query ---

(defun test-splitting ()
  (check "split-once: found"     (multiple-value-list (split-once "a:b:c" #\:)) '("a" "b:c"))
  (check "split-once: not found" (multiple-value-list (split-once "abc" #\:))   '("abc" nil))
  (check "split-last: found"     (multiple-value-list (split-last "a:b:c" #\:)) '("a:b" "c"))
  (check "str-split: basic"      (str-split "a,b,,c" #\,) '("a" "b" "" "c"))
  (check "parse-query: basic"
         (parse-query "a=1&b=2")
         '(("a" . "1") ("b" . "2")))
  (check "parse-query: empty value" (parse-query "flag=") '(("flag" . ""))))


;;; --- parse-vless ---

(defun test-parse-vless ()
  (let ((cfg (parse-vless
              "vless://uuid-123@example.com:443?security=reality&sni=foo.com&pbk=KEY&sid=1a&fp=chrome#My%20Server")))
    (check "vless: host"     (proxy-config-host cfg) "example.com")
    (check "vless: port"     (proxy-config-port cfg) 443)
    (check "vless: uuid"     (proxy-config-uuid cfg) "uuid-123")
    (check "vless: tag from fragment" (proxy-config-tag cfg) "My Server")
    (check "vless: extra sni" (qval (proxy-config-extra cfg) "sni") "foo.com"))
  (let ((cfg (parse-vless "vless://uuid@1.2.3.4:8443")))
    (check "vless: tag falls back to host" (proxy-config-tag cfg) "1.2.3.4"))
  (check-error "vless: missing @ errors"
    (parse-vless "vless://no-at-sign-here:443")))


;;; --- parse-shadowsocks ---

(defun test-parse-shadowsocks ()
  ;; Modern form, plain "method:password" userinfo (contains a colon, so
  ;; not base64-decoded).
  (let ((cfg (parse-shadowsocks "ss://chacha20-ietf-poly1305:secret@1.2.3.4:8080#tag1")))
    (check "ss modern plain: method"   (proxy-config-method cfg) "chacha20-ietf-poly1305")
    (check "ss modern plain: password" (proxy-config-password cfg) "secret")
    (check "ss modern plain: host"     (proxy-config-host cfg) "1.2.3.4")
    (check "ss modern plain: port"     (proxy-config-port cfg) 8080)
    (check "ss modern plain: tag"      (proxy-config-tag cfg) "tag1"))
  ;; Modern form, base64-encoded userinfo (no colon in the URI itself) —
  ;; base64("method:password") before the @.
  (let ((cfg (parse-shadowsocks "ss://YWVzLTI1Ni1nY206cGFzczI=@5.6.7.8:9000")))
    (check "ss modern b64: method"   (proxy-config-method cfg) "aes-256-gcm")
    (check "ss modern b64: password" (proxy-config-password cfg) "pass2")
    (check "ss modern b64: host"     (proxy-config-host cfg) "5.6.7.8")
    (check "ss modern b64: port"     (proxy-config-port cfg) 9000))
  ;; Legacy fully-base64 form: base64("method:password@host:port").
  (let ((cfg (parse-shadowsocks "ss://YWVzLTEyOC1nY206cHc5QDkuOS45Ljk6MTIzNA==#legacy")))
    (check "ss legacy: method"   (proxy-config-method cfg) "aes-128-gcm")
    (check "ss legacy: password" (proxy-config-password cfg) "pw9")
    (check "ss legacy: host"     (proxy-config-host cfg) "9.9.9.9")
    (check "ss legacy: port"     (proxy-config-port cfg) 1234)
    (check "ss legacy: tag"      (proxy-config-tag cfg) "legacy")))


;;; --- parse-config-uri dispatch ---

(defun test-parse-config-uri ()
  (check "dispatch: vless kind" (proxy-config-kind (parse-config-uri "vless://u@h:1")) :vless)
  (check "dispatch: ss kind"    (proxy-config-kind (parse-config-uri "ss://m:p@h:1")) :shadowsocks)
  (check "dispatch: unknown scheme -> nil" (parse-config-uri "http://not-a-proxy") nil)
  (check "dispatch: trims whitespace"
         (proxy-config-kind (parse-config-uri "  vless://u@h:1  "))
         :vless))


;;; --- json-write ---

(defun test-json-write ()
  (check "json: string escaping"
         (with-output-to-string (s) (json-write "a\"b\\c" s))
         "\"a\\\"b\\\\c\"")
  (check "json: number"  (with-output-to-string (s) (json-write 1080 s)) "1080")
  (check "json: true"    (with-output-to-string (s) (json-write t s)) "true")
  (check "json: false"   (with-output-to-string (s) (json-write :false s)) "false")
  (check "json: obj"
         (with-output-to-string (s) (json-write (list :obj (cons "a" 1) (cons "b" "x")) s))
         "{\"a\":1,\"b\":\"x\"}")
  (check "json: arr"
         (with-output-to-string (s) (json-write (list :arr 1 2 "x") s))
         "[1,2,\"x\"]"))


;;; --- build-singbox-config (end-to-end sanity, not a full schema check) ---

(defun test-build-singbox-config ()
  (let* ((cfg (parse-config-uri "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw==@1.2.3.4:8080"))
         (out (with-output-to-string (s) (json-write (build-singbox-config cfg) s))))
    (check "singbox config: outbound tag present"
           (and (search "\"tag\":\"proxy\"" out) t) t)
    (check "singbox config: dns detour is proxy"
           (and (search "\"detour\":\"proxy\"" out) t) t)))


(defun run-tests ()
  (setf *fail-count* 0 *check-count* 0)
  (test-b64-decode)
  (test-url-decode)
  (test-splitting)
  (test-parse-vless)
  (test-parse-shadowsocks)
  (test-parse-config-uri)
  (test-json-write)
  (test-build-singbox-config)
  (format t "~&[tests] ~a/~a passed~%" (- *check-count* *fail-count*) *check-count*)
  (zerop *fail-count*))
