(require
  hiolib.rule :readers * *)

(import
  asyncio
  time
  ssl
  hashlib [sha224]
  functools [cached-property]
  typing [Any Optional]
  pydantic [BaseModel]
  hiolib.stream *
  hiolib.util.ws *
  hiolib.util.proxy *)

(defclass SchemeDispatcher []
  (setv scheme None
        scheme-dict None)

  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (when (and (is-not cls.scheme None) (is-not cls.scheme-dict None))
      (setv (get cls.scheme-dict cls.scheme) cls)))

  (defn [classmethod] from-conf [cls conf]
    ((get cls.scheme-dict conf.scheme) conf)))

(defclass OUBTLSConf [BaseModel]
  #^ str               host
  #^ (of Optional str) cafile)

(defclass OUBWSConf [BaseModel]
  #^ str host
  #^ str path)

(defclass OUBConf [BaseModel]
  #^ str                      name
  #^ (of Optional str)        group
  #^ (of Optional float)      delay
  #^ str                      scheme
  #^ str                      host
  #^ int                      port
  #^ (of Optional OUBTLSConf) tls
  #^ (of Optional OUBWSConf)  ws
  #^ (of dict str Any)        extra)

(async-defclass OUB [SchemeDispatcher]
  (setv scheme-dict (dict)
        connector-class None)

  (defn #-- init [self conf]
    (setv self.conf conf))

  (defn [cached-property] tls-ctx [self]
    (when self.conf.tls
      (ssl.create-default-context :cafile self.conf.tls.cafile)))

  (defn get-ws-connector [self]
    ((async-name WSConnector) :host self.conf.ws.host :path self.conf.ws.path))

  (defn get-lowest-connector [self]
    (when self.conf.ws
      ((async-name WSConnector) :host self.conf.ws.host :path self.conf.ws.path)))

  (defn get-proxy-connector [self host port]
    (self.connector-class :host host :port port))

  (defn get-connector [self host port]
    (let [connector (.get-proxy-connector self host port)]
      (setv connector.lowest-layer.next-layer (.get-lowest-connector self))
      connector))

  (async-defn lowest-open-connection [self]
    (async-wait (if self.conf.tls
                    (.open-connection (async-name TLSStream) self.conf.host self.conf.port self.tls-ctx self.conf.tls.host)
                    (.open-connection (async-name TCPStream) self.conf.host self.conf.port))))

  (async-defn connect [self host port head]
    (let [lowest-stream (async-wait (.lowest-open-connection self))
          connector (.get-connector self host port)]
      (try
        (async-wait (.connect-with-head connector lowest-stream head))
        (except [Exception]
          (async-wait (.close lowest-stream))
          (raise))))))

(defclass INBTLSConf [BaseModel]
  #^ str               certfile
  #^ str               keyfile
  #^ (of Optional str) password)

(defclass INBWSConf [BaseModel])

(defclass INBConf [BaseModel]
  #^ str                      scheme
  #^ str                      host
  #^ int                      port
  #^ (of Optional INBTLSConf) tls
  #^ (of Optional INBWSConf)  ws
  #^ (of dict str Any)        extra)

(async-defclass INB [SchemeDispatcher]
  (setv scheme-dict (dict)
        acceptor-class None)

  (defn #-- init [self conf]
    (setv self.conf conf))

  (defn [cached-property] tls-ctx [self]
    (when self.conf.tls
      (doto (ssl.create-default-context ssl.Purpose.CLIENT_AUTH)
            (.load-cert-chain :certfile self.conf.tls.certfile
                              :keyfile  self.conf.tls.keyfile
                              :password self.conf.tls.password))))

  (defn get-lowest-acceptor [self]
    (when self.conf.ws
      ((async-name WSAcceptor))))

  (defn get-proxy-acceptor [self]
    (self.acceptor-class))

  (defn get-acceptor [self]
    (let [acceptor (.get-proxy-acceptor self)]
      (setv acceptor.lowest-layer.next-layer (.get-lowest-acceptor self))
      acceptor))

  (async-defn lowest-start-server [self callback]
    (async-wait
      (if self.conf.tls
          (.start-server (async-name TLSStream) callback self.conf.host self.conf.port self.tls-ctx)
          (.start-server (async-name TCPStream) callback self.conf.host self.conf.port))))

  (async-defn accept [self lowest-stream]
    (let [acceptor (.get-acceptor self)
          stream (async-wait (.accept acceptor lowest-stream))]
      #(stream acceptor.host acceptor.port))))

(async-defclass BlockOUB [(async-name OUB)]
  (setv scheme "block")
  (async-defn connect [self host port head]
    (async-wait ((async-if asyncio.sleep time.sleep) 0.1))
    ((async-name NullStream))))

(async-defclass DirectOUB [(async-name OUB)]
  (setv scheme "direct")
  (async-defn connect [self host port head]
    (let [stream (async-wait (.open-connection (async-name TCPStream) host port))]
      (try
        (async-wait (.write stream head))
        stream
        (except [Exception]
          (async-wait (.close stream))
          (raise))))))

(async-defclass HTTPOUB [(async-name OUB)]
  (setv scheme "http"
        connector-class (async-name HTTPConnector)))

(async-defclass HTTPINB [(async-name INB)]
  (setv scheme "http"
        acceptor-class (async-name HTTPAcceptor)))

(async-defclass Socks5OUB [(async-name OUB)]
  (setv scheme "socks5"
        connector-class (async-name Socks5Connector)))

(async-defclass Socks5INB [(async-name INB)]
  (setv scheme "socks5"
        acceptor-class (async-name Socks5Acceptor)))

(defclass TrojanMixin []
  (defn [cached-property] auth [self]
    (.hexdigest (sha224 (.encode (get self.conf.extra "password"))))))

(async-defclass TrojanOUB [TrojanMixin (async-name OUB)]
  (setv scheme "trojan")
  (defn get-proxy-connector [self host port]
    ((async-name TrojanConnector) :host host :port port :auth self.auth)))

(async-defclass TrojanINB [TrojanMixin (async-name INB)]
  (setv scheme "trojan")
  (defn get-proxy-acceptor [self]
    ((async-name TrojanAcceptor) :auth self.auth)))

(async-defclass AutoINB [(async-name INB)]
  (setv scheme "auto"
        acceptor-class (async-name AutoAcceptor)))

(export
  :objects [OUBConf OUB AsyncOUB INBConf INB AsyncINB])
