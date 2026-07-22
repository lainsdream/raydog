(defparameter *b64-table*
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun b64-decode (str)
  "Minimal base64 decoder, tolerant of missing padding and url-safe chars."
  (let* ((str  (substitute #\+ #\- (substitute #\/ #\_ str)))
         (str  (remove #\= str))
         (bits 0) (nbits 0)
         (out  (make-array 0 :element-type 'character :adjustable t :fill-pointer 0)))
    (loop for ch across str
          for idx = (position ch *b64-table*)
          when idx do
          (setf bits (logior (ash bits 6) idx))
          (incf nbits 6)
          (when (>= nbits 8)
            (decf nbits 8)
            (vector-push-extend (code-char (logand (ash bits (- nbits)) #xFF)) out)))
    (coerce out 'simple-string)))

(defun write-utf8-octets (octets stream)
  (when (plusp (length octets))
    (write-string
     (sb-ext:octets-to-string
      (coerce octets '(simple-array (unsigned-byte 8) (*)))
      :external-format :utf-8)
     stream)
    (setf (fill-pointer octets) 0)))

(defun url-decode (str)
  "Decode percent-escaped UTF-8 bytes, preserving literal characters."
  (with-output-to-string (out)
    (let ((pending
            (make-array 0
                        :element-type '(unsigned-byte 8)
                        :adjustable t
                        :fill-pointer 0)))
      (loop with i = 0
            while (< i (length str))
            for ch = (char str i)
            if (and (char= ch #\%)
                    (< (+ i 2) (length str))
                    (digit-char-p (char str (1+ i)) 16)
                    (digit-char-p (char str (+ i 2)) 16))
            do (vector-push-extend
                (parse-integer str :start (1+ i) :end (+ i 3) :radix 16)
                pending)
               (incf i 3)
            else
            do (write-utf8-octets pending out)
               (write-char ch out)
               (incf i)
            finally (write-utf8-octets pending out)))))

(defun split-once (str ch)
  "Split STR at first CH. Returns (values before after) or (values str nil)."
  (let ((pos (position ch str)))
    (if pos (values (subseq str 0 pos) (subseq str (1+ pos)))
        (values str nil))))

(defun split-last (str ch)
  "Split STR at last CH."
  (let ((pos (position ch str :from-end t)))
    (if pos (values (subseq str 0 pos) (subseq str (1+ pos)))
        (values str nil))))

(defun str-split (str ch)
  "Split STR on every occurrence of CH; returns list of substrings."
  (loop with start = 0
        for pos = (position ch str :start start)
        collect (subseq str start pos)
        while pos do (setf start (1+ pos))))

(defun parse-query (qs)
  "Parse 'a=b&c=d' query string into an alist of (key . value) strings."
  (when (and qs (> (length qs) 0))
    (loop for pair in (str-split qs #\&)
          for (k v) = (multiple-value-list (split-once pair #\=))
          collect (cons k (url-decode (or v ""))))))


(defun qval (alist key &optional default)
  (or (cdr (assoc key alist :test #'string=)) default))

(defun json-escape-string (s)
  "Return S with JSON-special chars escaped (no surrounding quotes)."
  (with-output-to-string (out)
    (loop for ch across s do
          (case ch
            (#\"      (write-string "\\\"" out))
            (#\\      (write-string "\\\\" out))
            (#\Newline (write-string "\\n"  out))
            (#\Return  (write-string "\\r"  out))
            (#\Tab     (write-string "\\t"  out))
            (t         (write-char ch out))))))

(defun json-write (obj &optional (stream *standard-output*))
  "OBJ: (:obj (k . v) ...) | (:arr v ...) | string | number | T | :false | :null"
  (cond
    ((eq obj :null)  (write-string "null"  stream))
    ((eq obj t)      (write-string "true"  stream))
    ((eq obj :false) (write-string "false" stream))
    ((numberp obj)   (princ obj stream))
    ((stringp obj)
     (write-char #\" stream)
     (write-string (json-escape-string obj) stream)
     (write-char #\" stream))
    ((and (consp obj) (eq (car obj) :obj))
     (write-char #\{ stream)
     (loop for (k . v) in (cdr obj)
           for first = t then nil
           do (unless first (write-char #\, stream))
              (write-char #\" stream)
              (write-string (json-escape-string k) stream)
              (write-char #\" stream)
              (write-char #\: stream)
              (json-write v stream))
     (write-char #\} stream))
    ((and (consp obj) (eq (car obj) :arr))
     (write-char #\[ stream)
     (loop for v in (cdr obj)
           for first = t then nil
           do (unless first (write-char #\, stream))
              (json-write v stream))
     (write-char #\] stream))
    (t (error "bad json obj: ~s" obj))))

(defstruct proxy-config
  kind
  tag
  uuid
  method
  password
  host port
  raw
  extra)

(defun strip-fragment (uri)
  "Return (values uri-without-fragment fragment-or-nil)."
  (multiple-value-bind (before after) (split-once uri #\#)
    (values before (and after (url-decode after)))))

(defun parse-vless (uri)
  (multiple-value-bind (body name) (strip-fragment uri)
    (let* ((body   (subseq body (length "vless://")))
           (at-pos (position #\@ body)))
      (unless at-pos (error "vless: no @ in ~a" uri))
      (let ((uuid (subseq body 0 at-pos))
            (rest (subseq body (1+ at-pos))))
        (multiple-value-bind (hostport query) (split-once rest #\?)
          (multiple-value-bind (host port-str) (split-last hostport #\:)
            (unless port-str (error "vless: no port in ~a" uri))
            (make-proxy-config
             :kind  :vless
             :tag   (or name host)
             :uuid  uuid
             :host  host
             :port  (or (parse-integer port-str :junk-allowed t)
                        (error "vless: bad port ~s" port-str))
             :raw   uri
             :extra (parse-query query))))))))

(defun finish-ss-config (name method password hp uri)
  "Shared tail for both Shadowsocks URI forms once METHOD/PASSWORD/HP
   (host:port) have been pulled out — only how they got there differs
   between the modern and legacy forms."
  (multiple-value-bind (host port-str) (split-last hp #\:)
    (make-proxy-config
     :kind     :shadowsocks
     :tag      (or name host)
     :method   method
     :password password
     :host     host
     :port     (or (parse-integer port-str :junk-allowed t)
                   (error "ss: bad port in ~a" uri))
     :raw      uri
     :extra    nil)))

(defun parse-shadowsocks (uri)
  (multiple-value-bind (body name) (strip-fragment uri)
    (let ((body (subseq body (length "ss://"))))
      (multiple-value-bind (userinfo hostport) (split-once body #\@)
        (if hostport
            ;; Modern Shadowsocks URI form.
            (let ((decoded (if (position #\: userinfo)
                               userinfo
                               (b64-decode userinfo))))
              (multiple-value-bind (method password) (split-once decoded #\:)
                (multiple-value-bind (hp _q) (split-once hostport #\?)
                  (declare (ignore _q))
                  (finish-ss-config name method password hp uri))))
            ;; Legacy base64-encoded URI form.
            (let ((decoded (b64-decode body)))
              (multiple-value-bind (userinfo hp) (split-once decoded #\@)
                (multiple-value-bind (method password) (split-once userinfo #\:)
                  (finish-ss-config name method password hp uri)))))))))

(defun parse-config-uri (uri)
  (let ((uri (string-trim '(#\Space #\Newline #\Return #\Tab) uri)))
    (cond
      ((and (>= (length uri) 8) (string= uri "vless://" :end1 8))
       (parse-vless uri))
      ((and (>= (length uri) 5) (string= uri "ss://" :end1 5))
       (parse-shadowsocks uri))
      (t nil))))

(defun singbox-tls-fields (cfg extra security)
  "Returns an alist of (\"tls\" . <obj>) or nil if there's no TLS at all."
  (cond
    ((string= security "reality")
     (list
      (cons "tls"
            (list :obj
                  (cons "enabled" t)
                  (cons "server_name" (qval extra "sni" ""))
                  (cons "utls" (list :obj
                                     (cons "enabled" t)
                                     (cons "fingerprint" (qval extra "fp" "chrome"))))
                  (cons "reality" (list :obj
                                        (cons "enabled" t)
                                        (cons "public_key" (qval extra "pbk" ""))
                                        (cons "short_id" (qval extra "sid" ""))))))))
    ((string= security "tls")
     (let ((insecure (or (string= (qval extra "allowInsecure" "0") "1")
                         (string= (qval extra "insecure" "0") "1"))))
       (list
        (cons "tls"
              (list :obj
                    (cons "enabled" t)
                    (cons "server_name" (qval extra "sni" (proxy-config-host cfg)))
                    (cons "insecure" (if insecure t :false))
                    (cons "utls" (list :obj
                                       (cons "enabled" t)
                                       (cons "fingerprint" (qval extra "fp" "chrome")))))))))
    (t nil)))

(defun singbox-transport-fields (extra network)
  "Returns an alist of (\"transport\" . <obj>) or nil for plain tcp."
  (cond
    ((string= network "ws")
     (list (cons "transport"
                 (list :obj
                       (cons "type" "ws")
                       (cons "path" (qval extra "path" "/"))
                       (cons "headers" (list :obj (cons "Host" (qval extra "host" ""))))))))
    ((string= network "grpc")
     (list (cons "transport"
                 (list :obj
                       (cons "type" "grpc")
                       (cons "service_name" (qval extra "serviceName" ""))))))
    (t nil)))

(defun vless-outbound-singbox (cfg)
  (let* ((extra    (proxy-config-extra cfg))
         (network  (qval extra "type" "tcp"))
         (security (qval extra "security" "none"))
         (flow     (qval extra "flow" "")))
    (cons :obj
          (append
           (list (cons "type" "vless")
                 (cons "tag" "proxy")
                 (cons "server" (proxy-config-host cfg))
                 (cons "server_port" (proxy-config-port cfg))
                 (cons "uuid" (proxy-config-uuid cfg)))
           ;; Omit empty flow: sing-box distinguishes it from an absent field.
           (when (plusp (length flow)) (list (cons "flow" flow)))
           (singbox-tls-fields cfg extra security)
           (singbox-transport-fields extra network)))))

(defun shadowsocks-outbound-singbox (cfg)
  (list :obj
        (cons "type" "shadowsocks")
        (cons "tag" "proxy")
        (cons "server" (proxy-config-host cfg))
        (cons "server_port" (proxy-config-port cfg))
        (cons "method" (proxy-config-method cfg))
        (cons "password" (proxy-config-password cfg))))

(defun proxy-outbound-singbox (cfg)
  (ecase (proxy-config-kind cfg)
    (:vless       (vless-outbound-singbox cfg))
    (:shadowsocks (shadowsocks-outbound-singbox cfg))))

;;; Keep this inbound port synchronized with *socks-port*.

(defun build-singbox-config (cfg)
  (list :obj
        (cons "log" (list :obj (cons "level" "warn")))
        (cons "dns"
              (list :obj
                    (cons "servers"
                          (list :arr
                                (list :obj
                                      (cons "tag" "proxy-dns")
                                      (cons "type" "https")
                                      (cons "server" "1.1.1.1")
                                      (cons "detour" "proxy"))))))
        (cons "inbounds"
              (list :arr
                    (list :obj
                          (cons "type" "mixed")
                          (cons "listen" "127.0.0.1")
                          (cons "listen_port" 1080))))
        (cons "outbounds" (list :arr (proxy-outbound-singbox cfg)))))


(defun read-uri-lines (txt-path)
  "One vless://or ss:// URI per line. Blank lines and lines starting with
   # are ignored, so you can comment things out or leave notes."
  (with-open-file (in txt-path :direction :input)
    (loop for line = (read-line in nil nil)
          while line
          for trimmed = (string-trim '(#\Space #\Tab #\Return) line)
          unless (or (zerop (length trimmed)) (char= (char trimmed 0) #\#))
          collect trimmed)))

(defun load-server-pool (txt-path config-dir)
  "Parse every URI in TXT-PATH, write each as its own complete sing-box
   config file under CONFIG-DIR, and return a list of plists shaped
   exactly like dog.lisp's *config-pool* entries: (:label :path :ip :port).

   One bad line doesn't abort the whole load — it's reported and skipped,
   since a single malformed entry in someone's pasted server list
   shouldn't cost you every other config in the file."
  (ensure-directories-exist (merge-pathnames "./" config-dir))
  (loop for uri in (read-uri-lines txt-path)
        for i from 1
        for cfg = (handler-case (parse-config-uri uri)
                    (error (e)
                      (format t "~&[pool] skipping line ~a, failed to parse: ~a~%" i e)
                      nil))
        when cfg
        collect (let* ((path (namestring
                              (merge-pathnames (format nil "server-~2,'0d.json" i)
                                               config-dir))))
                  (with-open-file (out path :direction :output
                                            :if-exists :supersede
                                            :if-does-not-exist :create)
                    (json-write (build-singbox-config cfg) out))
                  (list :label (proxy-config-tag cfg)
                        :path  path
                        :ip    (proxy-config-host cfg)
                        :port  (proxy-config-port cfg)))))
