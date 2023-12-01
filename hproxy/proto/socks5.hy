;; socks5: https://www.rfc-editor.org/rfc/rfc1928
;; trojan: https://trojan-gfw.github.io/trojan/protocol

(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  socket
  enum [IntEnum]
  hashlib [sha224]
  hiolib.struct *
  hproxy.proto.proxy *
  hproxy.proto.http *)

(defclass Socks5Atype [IntEnum]
  (setv DN 3 V4 1 V6 4))

(defstruct Socks5V4Host
  [[bytes host
    :len 4
    :from (socket.inet-pton socket.AF-INET it)
    :to (socket.inet-ntop socket.AF-INET it)]])

(defstruct Socks5V6Host
  [[bytes host
    :len 16
    :from (socket.inet-pton socket.AF-INET6 it)
    :to (socket.inet-ntop socket.AF-INET6 it)]])

(defstruct Socks5DNHost
  [[varlen host
    :len 1
    :from (.encode it)
    :to (.decode it)]])

(defstruct Socks5Addr
  [[int atype :len 1]
   [struct [host]
    :struct (ecase atype
                   Socks5Atype.DN (async-name Socks5DNHost)
                   Socks5Atype.V4 (async-name Socks5V4Host)
                   Socks5Atype.V6 (async-name Socks5V6Host))]
   [int port :len 2]])

(defstruct Socks5Req
  [[int ver1 :len 1 :to-validate (= it 5)]
   [varlen meths :len 1 :to-validate (in 0 it)]
   [int ver2 :len 1 :to-validate (= it 5)]
   [int cmd :len 1 :to-validate (= it 1)]
   [int rsv :len 1 :to-validate (= it 0)]
   [struct [atype host port] :struct (async-name Socks5Addr)]])

(defstruct Socks5Rep
  [[int ver1 :len 1 :to-validate (= it 5)]
   [int meth :len 1 :to-validate (= it 0)]
   [int ver2 :len 1 :to-validate (= it 5)]
   [int rep :len 1 :to-validate (= it 0)]
   [int rsv :len 1 :to-validate (= it 0)]
   [struct [atype host port] :struct (async-name Socks5Addr)]])

(defstruct TrojanReq
  [[line auth :sep b"\r\n"]
   [int cmd :len 1 :to-validate (= it 1)]
   [struct [atype host port] :struct (async-name Socks5Addr)]
   [line empty :sep b"\r\n" :to-validate (not it)]])


;;; socks5

(async-defclass Socks5Connector [(async-name ProxyConnector)]
  (defn get-next-head-pre-head [self]
    (.pack (async-name Socks5Req)
           :ver1  5
           :meths b"\x00"
           :ver2  5
           :cmd   1
           :rsv   0
           :atype Socks5Atype.DN
           :host  self.host
           :port  self.port))

  (async-defn connect1 [self next-stream]
    (async-wait (.unpack-from-stream (async-name Socks5Rep) next-stream))
    next-stream))

(async-defclass Socks5Acceptor [(async-name ProxyAcceptor)]
  (async-defn accept1 [self next-stream]
    (async-wait (.pack-bytes-to-stream (async-name Socks5Rep)
                                       next-stream
                                       :ver1  5
                                       :meth  0
                                       :ver2  5
                                       :rep   0
                                       :rsv   0
                                       :atype Socks5Atype.V4
                                       :host  "0.0.0.0"
                                       :port  0))
    (let [#(_ _ _ _ _ _ host port)
          (async-wait (.unpack-from-stream (async-name Socks5Req) next-stream))]
      (setv self.host host
            self.port port))
    next-stream))


;;; auto

(async-defclass AutoAcceptor [(async-name ProxyAcceptor)]
  (async-defn accept1 [self next-stream]
    (let [buf (async-wait (.peek-atleast next-stream 1))]
      (let [acceptor (if (= (get buf 0) 5) ((async-name Socks5Acceptor)) ((async-name HTTPAcceptor)))
            stream (async-wait (.accept1 acceptor next-stream))]
        (setv self.host acceptor.host
              self.port acceptor.port)
        stream))))


;;; trojan

(defclass TrojanAuthError [StructValidationError])

(defclass TrojanACMixin []
  (defn #-- init [self auth #** kwargs]
    (#super-- init #** kwargs)
    (setv self.auth auth)))

(async-defclass TrojanConnector [TrojanACMixin (async-name ProxyConnector)]
  (defn get-next-head-pre-head [self]
    (.pack (async-name TrojanReq) self.auth 1 Socks5Atype.DN self.host self.port "")))

(async-defclass TrojanAcceptor [TrojanACMixin (async-name ProxyAcceptor)]
  (async-defn accept1 [self next-stream]
    (let [#(auth _ _ host port _)
          (async-wait (.unpack-from-stream (async-name TrojanReq) next-stream))]
      (unless (= auth self.auth)
        (raise TrojanAuthError))
      (setv self.host host
            self.port port)
      next-stream)))

(defn get-trojan-auth [password]
  (.hexdigest (sha224 (.encode password))))

(export
  :objects [Socks5Connector AsyncSocks5Connector Socks5Acceptor AsyncSocks5Acceptor
            AutoAcceptor AsyncAutoAcceptor
            TrojanAuthError get-trojan-auth
            TrojanConnector AsyncTrojanConnector TrojanAcceptor AsyncTrojanAcceptor])
