;; https://www.rfc-editor.org/rfc/rfc6455

(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  enum [IntEnum]
  collections [deque]
  random [randbytes]
  base64 [b64encode]
  hashlib [sha1]
  hiolib.stream *
  hiolib.struct *
  hproxy.http *)

(defclass WSOp [IntEnum]
  (setv Cont  0x00
        Text  0x01
        Bin   0x02
        Close 0x08
        Ping  0x09
        Pong  0x0a))


;;; frame

(defn ws-mask-pload [pload mask]
  (let [arr (bytearray pload)]
    (for [i (range (len arr))]
      (^= (get arr i) (get mask (% i 4))))
    (bytes arr)))

(async-defclass WSFramePloadHead [(async-name Struct)]
  (setv names #("plen" "mask"))

  (defn [staticmethod] pack [plen mask]
    (let [mask-bit (int (bool mask))]
      (+ (cond (< plen 126)
               (bits-pack #(7 0) #(mask-bit plen) 1)
               (< plen 65536)
               (+ (bits-pack #(7 0) #(mask-bit 126) 1)
                  (int-pack plen 2))
               True
               (+ (bits-pack #(7 0) #(mask-bit 127) 1)
                  (int-pack plen 8)))
         mask)))

  (async-defn [staticmethod] unpack-from-stream [reader]
    (let [#(mask-bit plen) (bits-unpack
                             #(7 0) #(1 0x7f)
                             (async-wait (.read-exactly reader 1)))
          plen (cond (= plen 126)
                     (int-unpack (async-wait (.read-exactly reader 2)))
                     (= plen 127)
                     (int-unpack (async-wait (.read-exactly reader 8)))
                     True
                     plen)
          mask (if mask-bit
                   (async-wait (.read-exactly reader 4))
                   b"")]
      #(plen mask))))

(defstruct WSFrame
  [[bits [fin op] :lens [1 7]]
   [struct [plen mask] :struct (async-name WSFramePloadHead)]
   [bytes pload
    :len plen
    :from (if mask (ws-mask-pload it mask) it)
    :to (if mask (ws-mask-pload it mask) it)]])


;;; stream

(async-defclass WSStream [(async-name Stream)]
  (defn #-- init [self [do-mask True] #** kwargs]
    (#super-- init #** kwargs)
    (setv self.do-mask do-mask
          self.pings (deque)))

  (async-defn read-frame [self]
    (let [#(fin op _ _ pload)
          (async-wait (.unpack-from-stream (async-name WSFrame) self.next-layer))]
      (while (not fin)
        (let [#(next-fin next-op _ _ next-pload)
              (async-wait (.unpack-from-stream (async-name WSFrame) self.next-layer))]
          (unless (= op next-op)
            (raise RuntimeError))
          (setv fin next-fin)
          (+= pload next-pload)
          (when (> (len pload) self.read-buf-size)
            (raise StreamOverflowError))))
      #(op pload)))

  (async-defn write-frame [self op pload]
    (async-wait (.write self.next-layer (.pack (async-name WSFrame)
                                               :fin True
                                               :op op
                                               :plen (len pload)
                                               :mask (if self.do-mask (randbytes 4) b"")
                                               :pload pload))))

  (async-defn read1 [self]
    (while True
      (let [#(op pload) (async-wait (.read-frame self))]
        (ecase op
               WSOp.Cont  None
               WSOp.Text  (return pload)
               WSOp.Bin   (return pload)
               WSOp.Close (return b"")
               WSOp.Ping  (.append self.pings pload)
               WSOp.Pong  None))))

  (async-defn write1 [self buf]
    (while self.pings
      (let [ping (.popleft self.pings)]
        (async-wait (.write-frame self WSOp.Pong ping))))
    (async-wait (.write-frame self WSOp.Bin buf))))

(async-defclass WSConnector [(async-name Connector)]
  (defn #-- init [self host path #** kwargs]
    (#super-- init #** kwargs)
    (setv self.host host
          self.path path))

  (defn get-next-head-pre-head [self]
    (.pack (async-name HTTPReq)
           "GET" self.path "HTTP/1.1"
           {"Host" self.host
            "Upgrade" "websocket"
            "Connection" "Upgrade"
            "Sec-WebSocket-Key" (.decode (b64encode (randbytes 16)))
            "Sec-WebSocket-Version" "13"}))

  (defn get-next-head-pre-frame [self head]
    (.pack (async-name WSFrame)
           :fin True
           :op WSOp.Bin
           :plen (len head)
           :mask (randbytes 4)
           :pload head))

  (async-defn connect1 [self next-stream]
    (let [#(ver status reason headers)
          (async-wait (.unpack-from-stream (async-name HTTPResp) next-stream))]
      (unless (= status "101")
        (raise HTTPStatusError))
      ((async-name WSStream) :do-mask True :next-layer next-stream))))

(async-defclass WSAcceptor [(async-name Acceptor)]
  (setv magic "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

  (async-defn accept1 [self next-stream]
    (let [#(meth path ver headers)
          (async-wait (.unpack-from-stream (async-name HTTPReq) next-stream))
          host (get headers "Host")
          key (get headers "Sec-WebSocket-Key")
          accept (.decode (b64encode (.digest (sha1 (.encode (+ key self.magic))))))]
      (async-wait (.write next-stream (.pack (async-name HTTPResp)
                                             "HTTP/1.1" "101" "Switching Protocols"
                                             {"Upgrade" "websocket"
                                              "Connection" "Upgrade"
                                              "Sec-WebSocket-Accept" accept})))
      (setv self.host host
            self.path path)
      ((async-name WSStream) :do-mask False :next-layer next-stream))))

(export
  :objects [WSConnector AsyncWSConnector WSAcceptor AsyncWSAcceptor])
