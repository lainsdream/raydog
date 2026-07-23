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


;;; --- test-only helper: base64 encode (config.lisp only ships a decoder,
;;; but vmess tests need to construct sample "vmess://<base64 json>" URIs) ---

(defun base64-encode-json (json-str)
  (let ((out (make-array 0 :element-type 'character :adjustable t :fill-pointer 0))
        (bytes (map 'vector #'char-code json-str)))
    (loop for i from 0 below (length bytes) by 3
          do (let* ((b0 (aref bytes i))
                     (b1 (if (< (1+ i) (length bytes)) (aref bytes (1+ i)) 0))
                     (b2 (if (< (+ i 2) (length bytes)) (aref bytes (+ i 2)) 0))
                     (n  (logior (ash b0 16) (ash b1 8) b2)))
                (vector-push-extend (char *b64-table* (ldb (byte 6 18) n)) out)
                (vector-push-extend (char *b64-table* (ldb (byte 6 12) n)) out)
                (vector-push-extend (if (< (1+ i) (length bytes)) (char *b64-table* (ldb (byte 6 6) n)) #\=) out)
                (vector-push-extend (if (< (+ i 2) (length bytes)) (char *b64-table* (ldb (byte 6 0) n)) #\=) out)))
    (coerce out 'simple-string)))


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


;;; --- parse-trojan ---
;;; Shares parse-simple-uri with parse-vless, so this mostly exercises the
;;; bits that differ: password instead of uuid, and the tls-by-default extra.

(defun test-parse-trojan ()
  (let ((cfg (parse-trojan
              "trojan://s3cret@example.com:443?sni=foo.com&type=ws&path=%2Fws&host=cdn.com#My%20Trojan")))
    (check "trojan: host"     (proxy-config-host cfg) "example.com")
    (check "trojan: port"     (proxy-config-port cfg) 443)
    (check "trojan: password" (proxy-config-password cfg) "s3cret")
    (check "trojan: tag from fragment" (proxy-config-tag cfg) "My Trojan")
    (check "trojan: extra sni"  (qval (proxy-config-extra cfg) "sni") "foo.com")
    (check "trojan: extra path" (qval (proxy-config-extra cfg) "path") "/ws"))
  ;; No explicit security= in the query: trojan defaults to tls anyway.
  (let ((cfg (parse-trojan "trojan://pw@1.2.3.4:443")))
    (check "trojan: security defaults to tls"
           (qval (proxy-config-extra cfg) "security") "tls")
    (check "trojan: tag falls back to host" (proxy-config-tag cfg) "1.2.3.4"))
  ;; An explicit security= in the query is not overridden by the default.
  (let ((cfg (parse-trojan "trojan://pw@1.2.3.4:443?security=none")))
    (check "trojan: explicit security is not overridden"
           (qval (proxy-config-extra cfg) "security") "none"))
  (check-error "trojan: missing @ errors"
    (parse-trojan "trojan://no-at-sign-here:443")))


;;; --- parse-hysteria2 ---
;;; Shares parse-simple-uri with vless/trojan; auth is an opaque password
;;; (UUID-shaped or base64-ish with +/= in it — never url-decoded, same as
;;; trojan's password).

(defun test-parse-hysteria2 ()
  (let ((cfg (parse-hysteria2
              "hysteria2://s3cret@example.com:8443?sni=foo.com&insecure=1#My%20Server")))
    (check "hysteria2: host"     (proxy-config-host cfg) "example.com")
    (check "hysteria2: port"     (proxy-config-port cfg) 8443)
    (check "hysteria2: password" (proxy-config-password cfg) "s3cret")
    (check "hysteria2: tag from fragment" (proxy-config-tag cfg) "My Server")
    (check "hysteria2: extra sni" (qval (proxy-config-extra cfg) "sni") "foo.com")
    (check "hysteria2: extra insecure" (qval (proxy-config-extra cfg) "insecure") "1"))
  ;; Auth containing +/= (base64-ish obfs password), and a trailing '/'
  ;; before the query string, both seen in the wild.
  (let ((cfg (parse-hysteria2
              "hysteria2://FR+3uZ+qu5lMaeIEV2OeBK3sQJmmMiABg57L4KFWK78=@vpn.example.com:8443/?insecure=1")))
    (check "hysteria2: password with +/= preserved"
           (proxy-config-password cfg) "FR+3uZ+qu5lMaeIEV2OeBK3sQJmmMiABg57L4KFWK78=")
    (check "hysteria2: port survives trailing slash before ?" (proxy-config-port cfg) 8443)
    (check "hysteria2: tag falls back to host" (proxy-config-tag cfg) "vpn.example.com"))
  (check-error "hysteria2: missing @ errors"
    (parse-hysteria2 "hysteria2://no-at-sign-here:443")))


;;; --- parse-vmess ---

(defun test-parse-vmess ()
  ;; ws + tls, all fields present.
  (let ((cfg (parse-vmess
              (format nil "vmess://~a"
                      (base64-encode-json
                       "{\"v\":\"2\",\"ps\":\"My VMess\",\"add\":\"cdn.example.com\",\"port\":\"443\",\"id\":\"uuid-1\",\"aid\":\"0\",\"net\":\"ws\",\"tls\":\"tls\",\"path\":\"/ws\",\"host\":\"cdn.example.com\",\"sni\":\"cdn.example.com\",\"fp\":\"chrome\",\"scy\":\"aes-128-gcm\"}")))))
    (check "vmess: host"     (proxy-config-host cfg) "cdn.example.com")
    (check "vmess: port"     (proxy-config-port cfg) 443)
    (check "vmess: uuid"     (proxy-config-uuid cfg) "uuid-1")
    (check "vmess: tag from ps" (proxy-config-tag cfg) "My VMess")
    (check "vmess: cipher method" (proxy-config-method cfg) "aes-128-gcm")
    (check "vmess: extra type" (qval (proxy-config-extra cfg) "type") "ws")
    (check "vmess: extra security" (qval (proxy-config-extra cfg) "security") "tls")
    (check "vmess: extra path" (qval (proxy-config-extra cfg) "path") "/ws")
    (check "vmess: extra sni" (qval (proxy-config-extra cfg) "sni") "cdn.example.com"))
  ;; grpc: service name is conventionally carried in "path".
  (let ((cfg (parse-vmess
              (format nil "vmess://~a"
                      (base64-encode-json
                       "{\"add\":\"5.6.7.8\",\"port\":443,\"id\":\"uuid-2\",\"net\":\"grpc\",\"path\":\"mygrpc\",\"tls\":\"tls\"}")))))
    (check "vmess grpc: serviceName mirrors path"
           (qval (proxy-config-extra cfg) "serviceName") "mygrpc"))
  ;; Missing ps: tag falls back to the server address, same as vless/trojan
  ;; falling back to host when there's no #fragment.
  (let ((cfg (parse-vmess
              (format nil "vmess://~a"
                      (base64-encode-json
                       "{\"add\":\"9.9.9.9\",\"port\":\"8080\",\"id\":\"uuid-3\",\"net\":\"tcp\",\"tls\":\"\"}")))))
    (check "vmess: tag falls back to host" (proxy-config-tag cfg) "9.9.9.9")
    (check "vmess: no tls -> security none"
           (qval (proxy-config-extra cfg) "security") "none")
    (check "vmess: missing scy defaults to auto" (proxy-config-method cfg) "auto")
    ;; No sni/host in the payload: must NOT appear as "" in extra, or it'd
    ;; shadow singbox-tls-fields's own host-based fallback.
    (check "vmess: absent sni omitted, not blanked"
           (assoc "sni" (proxy-config-extra cfg) :test #'string=) nil))
  (check-error "vmess: bad port errors"
    (parse-vmess (format nil "vmess://~a"
                          (base64-encode-json
                           "{\"add\":\"1.2.3.4\",\"port\":\"not-a-number\",\"id\":\"u\"}"))))
  (check-error "vmess: non-object JSON payload errors"
    (parse-vmess (format nil "vmess://~a" (base64-encode-json "[1,2,3]")))))


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
  (check "dispatch: vless kind"  (proxy-config-kind (parse-config-uri "vless://u@h:1")) :vless)
  (check "dispatch: ss kind"     (proxy-config-kind (parse-config-uri "ss://m:p@h:1")) :shadowsocks)
  (check "dispatch: trojan kind" (proxy-config-kind (parse-config-uri "trojan://p@h:1")) :trojan)
  (check "dispatch: vmess kind"
         (proxy-config-kind
          (parse-config-uri
           (format nil "vmess://~a" (base64-encode-json "{\"add\":\"h\",\"port\":\"1\",\"id\":\"u\"}"))))
         :vmess)
  (check "dispatch: hysteria2 kind"
         (proxy-config-kind (parse-config-uri "hysteria2://pw@h:1")) :hysteria2)
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


;;; --- json-parse (needed for vmess, which is base64+JSON rather than a query string) ---

(defun test-json-parse ()
  (check "json-parse: string with escapes"
         (json-parse "\"a\\\"b\\\\c\\n\"") "a\"b\\c
")
  (check "json-parse: number int"   (json-parse "1080") 1080)
  (check "json-parse: number float" (json-parse "1.5") 1.5d0)
  (check "json-parse: true"  (json-parse "true") t)
  (check "json-parse: false" (json-parse "false") :false)
  (check "json-parse: null"  (json-parse "null") :null)
  (check "json-parse: empty object" (json-parse "{}") (cons :obj nil))
  (check "json-parse: flat object"
         (json-parse "{\"a\":1,\"b\":\"x\"}")
         (list :obj (cons "a" 1) (cons "b" "x")))
  (check "json-parse: nested object"
         (json-parse "{\"a\":{\"b\":2}}")
         (list :obj (cons "a" (list :obj (cons "b" 2)))))
  (check "json-parse: array"
         (json-parse "[1,2,\"x\"]")
         (list :arr 1 2 "x"))
  (check "json-parse: whitespace tolerant"
         (json-parse " { \"a\" : 1 , \"b\" : 2 } ")
         (list :obj (cons "a" 1) (cons "b" 2)))
  ;; json-obj-get / json-as-string, the helpers parse-vmess actually uses.
  (let ((obj (json-parse "{\"port\":443,\"aid\":\"0\",\"ps\":\"\"}")))
    (check "json-obj-get: numeric field coerced to string" (json-obj-get obj "port") "443")
    (check "json-obj-get: string field passthrough" (json-obj-get obj "aid") "0")
    (check "json-obj-get: missing key uses default" (json-obj-get obj "missing" "dflt") "dflt")
    (check "json-obj-get: present-but-empty is \"\", not the default"
           (json-obj-get obj "ps" "fallback") "")))


;;; --- build-singbox-config (end-to-end sanity, not a full schema check) ---

(defun test-build-singbox-config ()
  (let* ((cfg (parse-config-uri "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw==@1.2.3.4:8080"))
         (out (with-output-to-string (s) (json-write (build-singbox-config cfg) s))))
    (check "singbox config: outbound tag present"
           (and (search "\"tag\":\"proxy\"" out) t) t)
    (check "singbox config: dns detour is proxy"
           (and (search "\"detour\":\"proxy\"" out) t) t))
  (let* ((cfg (parse-config-uri "trojan://pw@1.2.3.4:443?sni=example.com&type=ws&path=%2Fws&host=example.com"))
         (out (with-output-to-string (s) (json-write (build-singbox-config cfg) s))))
    (check "singbox trojan: outbound type"  (and (search "\"type\":\"trojan\"" out) t) t)
    (check "singbox trojan: tls enabled"    (and (search "\"tls\":{\"enabled\":true" out) t) t)
    (check "singbox trojan: ws transport"   (and (search "\"transport\":{\"type\":\"ws\"" out) t) t))
  ;; Regression: no host= param, only sni= — Host header must fall back to
  ;; sni (not come out blank), or CDN-fronted ws configs silently break.
  (let* ((cfg (parse-config-uri "trojan://pw@1.2.3.4:443?sni=cdn.example.com&type=ws&path=%2Fws"))
         (out (with-output-to-string (s) (json-write (build-singbox-config cfg) s))))
    (check "singbox trojan: ws Host falls back to sni"
           (and (search "\"Host\":\"cdn.example.com\"" out) t) t))
  (let* ((cfg (parse-config-uri
               (format nil "vmess://~a"
                       (base64-encode-json
                        "{\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"uuid\",\"net\":\"ws\",\"tls\":\"tls\",\"path\":\"/ws\",\"host\":\"h\"}"))))
         (out (with-output-to-string (s) (json-write (build-singbox-config cfg) s))))
    (check "singbox vmess: outbound type" (and (search "\"type\":\"vmess\"" out) t) t)
    (check "singbox vmess: uuid present"  (and (search "\"uuid\":\"uuid\"" out) t) t)
    (check "singbox vmess: tls enabled"   (and (search "\"tls\":{\"enabled\":true" out) t) t))
  ;; No tls, no ws/grpc: the tls/transport keys should be omitted entirely
  ;; rather than emitted with placeholder values.
  (let* ((cfg (parse-config-uri
               (format nil "vmess://~a"
                       (base64-encode-json "{\"add\":\"9.9.9.9\",\"port\":\"80\",\"id\":\"uuid\",\"net\":\"tcp\",\"tls\":\"\"}"))))
         (out (with-output-to-string (s) (json-write (build-singbox-config cfg) s))))
    (check "singbox vmess plain tcp: no tls key"       (search "\"tls\":" out) nil)
    (check "singbox vmess plain tcp: no transport key" (search "\"transport\":" out) nil))
  (let* ((cfg (parse-config-uri "hysteria2://s3cret@1.2.3.4:8443?sni=example.com&insecure=1"))
         (out (with-output-to-string (s) (json-write (build-singbox-config cfg) s))))
    (check "singbox hysteria2: outbound type" (and (search "\"type\":\"hysteria2\"" out) t) t)
    (check "singbox hysteria2: password present" (and (search "\"password\":\"s3cret\"" out) t) t)
    (check "singbox hysteria2: tls enabled" (and (search "\"tls\":{\"enabled\":true" out) t) t)
    (check "singbox hysteria2: sni honored" (and (search "\"server_name\":\"example.com\"" out) t) t)
    (check "singbox hysteria2: insecure honored" (and (search "\"insecure\":true" out) t) t)
    (check "singbox hysteria2: no obfs key when absent" (search "\"obfs\":" out) nil))
  (let* ((cfg (parse-config-uri "hysteria2://s3cret@1.2.3.4:8443?obfs=salamander&obfs-password=op"))
         (out (with-output-to-string (s) (json-write (build-singbox-config cfg) s))))
    (check "singbox hysteria2: obfs type"     (and (search "\"obfs\":{\"type\":\"salamander\"" out) t) t)
    (check "singbox hysteria2: obfs password" (and (search "\"password\":\"op\"" out) t) t)
    (check "singbox hysteria2: tls sni falls back to host"
           (and (search "\"server_name\":\"1.2.3.4\"" out) t) t)))


(defun run-tests ()
  (setf *fail-count* 0 *check-count* 0)
  (test-b64-decode)
  (test-url-decode)
  (test-splitting)
  (test-parse-vless)
  (test-parse-trojan)
  (test-parse-hysteria2)
  (test-parse-vmess)
  (test-parse-shadowsocks)
  (test-parse-config-uri)
  (test-json-write)
  (test-json-parse)
  (test-build-singbox-config)
  (format t "~&[tests] ~a/~a passed~%" (- *check-count* *fail-count*) *check-count*)
  (zerop *fail-count*))