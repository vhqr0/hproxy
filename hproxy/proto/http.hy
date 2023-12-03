(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  io [StringIO]
  hiolib.struct *
  hproxy.proto.base *)

(defclass HTTPStatusError [StructValidationError])



(defn http-pack-addr [host port]
  ;; example:
  ;;   www.google.com,80 => www.google.com:80
  ;;   240c::6666,53 => [240c::6666]:53
  (.format (if (> (.find host ":") 0) "[{}]:{}" "{}:{}")
           host port))

(defn http-unpack-addr [addr]
  ;; example:
  ;;   www.google.com:80 => www.google.com,80
  ;;   [240c::6666]:53 => 240c::6666,53
  (if (= (get addr 0) "[")
      (let [idx (.find addr "]")]
        (unless (> idx 0)
          (raise ValueError))
        (cond (= (+ idx 1) (len addr))
              #((cut addr 1 idx) 80)
              (= (get addr (+ idx 1)) ":")
              #((cut addr 1 idx) (int (cut addr (+ idx 2) None)))
              True
              (raise ValueError)))
      (let [sp (.split addr ":" 1)]
        (ecase (len sp)
               2 #((get sp 0) (int (get sp 1)))
               1 #((get sp 0) 80)))))

(defn http-pack-headers [headers]
  ;; dict[str,str] => list[str]
  ;;
  ;; example:
  ;;   {"Host": "www.google.com", "Connection": "close"} =>
  ;;   ["Host: www.google.com", "Connection: close", ""]
  (doto (lfor #(k v) (headers.items) (.format "{}: {}" k v))
        (.append "")))

(defn http-unpack-headers [headers]
  ;; list[str] => dict[str,str]
  ;;
  ;; example:
  ;;   ["Host: www.google.com", "Connection: close", ""] =>
  ;;   {"Host": "www.google.com", "Connection": "close"}
  (.pop headers)
  (dfor header headers
        :setv #(k v) (.split header ":" 1)
        (.strip k) (.strip v)))



(defstruct HTTPHeaders
  [[line headers
    :sep b"\r\n"
    :repeat-do-until (not it)
    :from (http-pack-headers it)
    :to (http-unpack-headers it)]])

(defstruct HTTPFirstLine
  ;; for request, it is (meth,path,ver)
  ;; for response, it is (ver,status,reason)
  [[line firstline
    :sep b"\r\n"
    :from (.join " " it)
    :to (.split it :maxsplit 2)]])

(defstruct HTTPReq
  [[struct [[meth path ver]] :struct (async-name HTTPFirstLine)]
   [struct [headers] :struct (async-name HTTPHeaders)]])

(defstruct HTTPResp
  [[struct [[ver status reason]] :struct (async-name HTTPFirstLine)]
   [struct [headers] :struct (async-name HTTPHeaders)]])



(async-defclass HTTPConnector [(async-name ProxyConnector)]
  (defn get-next-head-pre-head [self]
    (let [addr (http-pack-addr self.host self.port)]
      (.pack (async-name HTTPReq) "CONNECT" addr "HTTP/1.1" {"Host" addr})))

  (async-defn connect1 [self next-stream]
    (let [#(_ status _ _)
          (async-wait (.unpack-from-stream (async-name HTTPResp) next-stream))]
      (unless (= status "200")
        (raise HTTPStatusError))
      next-stream)))

(async-defclass HTTPAcceptor [(async-name ProxyAcceptor)]
  (async-defn accept1 [self next-stream]
    (let [#(meth path ver headers)
          (async-wait (.unpack-from-stream (async-name HTTPReq) next-stream))
          #(host port) (http-unpack-addr (get headers "Host"))]
      (setv self.host host
            self.port port)
      (if (= meth "CONNECT")
          (async-wait (.pack-bytes-to-stream (async-name HTTPResp) next-stream ver "200" "OK" {"Connection" "close"}))
          (let [headers (dfor #(k v) (.items headers) :if (not (.startswith k "Proxy-")) k v)]
            (setv next-stream.read-buf (+ (.pack (async-name HTTPReq) meth path ver headers) next-stream.read-buf))))
      next-stream)))



(async-defclass HTTPRequester [(async-name Requester)]
  (defn #-- init [self [meth "GET"] [path "/"] [ver "HTTP/1.1"] [host None] [headers None] [content None]]
    (setv self.meth meth
          self.path path
          self.ver ver
          self.host host
          self.headers headers
          self.content content))

  (defn [property] head [self]
    (let [headers (dict)]
      (when self.host
        (setv (get headers "Host") self.host))
      (when self.headers
        (for [#(k v) (.items self.headers)]
          (setv (get headers k) v)))
      (+ (.pack HTTPReq self.meth self.path self.ver headers)
         (or self.content b""))))

  (async-defn request [self stream]
    (let [resp (async-wait (.unpack-from-stream (async-name HTTPResp) stream))
          #(ver status reason headers) resp
          content-length    (.get headers "Content-Length")
          transfer-encoding (.get headers "Transfer-Encoding")
          content b""]
      (when content-length
        (setv content (async-wait (.read-exactly stream (int content-length)))))
      (when (and (not content-length) (= transfer-encoding "chunked"))
        (let [bufs (list)]
          (while True
            (let [chunk-length (.decode (async-wait (.read-line stream)))]
              (when (in chunk-length #("0" ""))
                (break))
              (.append bufs (async-wait (.read-exactly stream (int chunk-length 16))))))
          (setv content (.join b"" bufs))))
      #(resp content)))

  (defn [classmethod] resp-to-str [cls resp]
    (let [#(#(ver status reason headers) content) resp
          sio (StringIO)]
      (.write sio (.format "{} {} {}\n" ver status reason))
      (for [#(k v) (.items headers)]
        (.write sio (.format "{}: {}\n" k v)))
      (.write sio "\n")
      (if (<= (len content) 512)
          (.write sio (.format "{}\n" content))
          (.write sio (.format "{}...\n" (cut content 512))))
      (.getvalue sio)))

  (defn [classmethod] resp-to-bytes [cls resp]
    (let [#(#(ver status reason headers) content) resp]
      content)))

(export
  :objects [HTTPStatusError
            http-pack-addr http-unpack-addr http-pack-headers http-unpack-headers
            HTTPReq AsyncHTTPReq HTTPResp AsyncHTTPResp
            HTTPConnector AsyncHTTPConnector HTTPAcceptor AsyncHTTPAcceptor
            HTTPRequester AsyncHTTPRequester])
