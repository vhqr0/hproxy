(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  ssl
  functools [cached-property]
  typing [Any Optional]
  pydantic [BaseModel]
  hiolib.stream *
  hproxy.ws *)

(async-defclass ProxyConnector [(async-name Connector)]
  (defn #-- init [self host port #** kwargs]
    (#super-- init #** kwargs)
    (setv self.host host
          self.port port)))

(async-defclass ProxyAcceptor [(async-name Acceptor)])


;;; oub/inb/sub conf

(defclass OUBTLSConf [BaseModel]
  #^ str               host
  #^ (of Optional str) cafile)

(defclass OUBWSConf [BaseModel]
  #^ str host
  #^ str path)

(defclass OUBConf [BaseModel]
  ;; - managed: whether this oub is auto managed, if so, some attrs
  ;; will be dynamically configured, such as enabled, dnsname, delay,
  ;; etc.
  ;;
  ;; - enabled: whether to add this oub to oubs when starting the
  ;; service, in order to temporarily disable unavailable auto managed
  ;; oubs.
  ;;
  ;; - host&dnsname: dnsname usually refers to the host we refer to,
  ;; and host is the actual connection address, which can be dnsname
  ;; or the resolved address of dnsname.

  #^ bool                            managed
  #^ bool                            enabled
  #^ str                             name
  #^ str                             group
  #^ str                             dnsname
  #^ float                           delay
  #^ str                             scheme
  #^ str                             host
  #^ int                             port
  #^ (of Optional OUBTLSConf)        tls
  #^ (of Optional OUBWSConf)         ws
  #^ (of Optional (of dict str Any)) extra)

(defclass INBTLSConf [BaseModel]
  #^ str               certfile
  #^ str               keyfile
  #^ (of Optional str) password)

(defclass INBWSConf [BaseModel])

(defclass INBConf [BaseModel]
  #^ str                             scheme
  #^ str                             host
  #^ int                             port
  #^ (of Optional INBTLSConf)        tls
  #^ (of Optional INBWSConf)         ws
  #^ (of Optional (of dict str Any)) extra)

(defclass SUBConf [BaseModel]
  #^ str                             group
  #^ str                             scheme
  #^ str                             url
  #^ (of Optional (of dict str Any)) extra)


;;; oub/inb/sub

(defclass SchemeDispatchMixin []
  (setv scheme None
        scheme-dict None)

  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (when (and (is-not cls.scheme None) (is-not cls.scheme-dict None))
      (setv (get cls.scheme-dict cls.scheme) cls)))

  (defn #-- init [self conf]
    (setv self.conf conf))

  (defn [classmethod] from-conf [cls conf]
    ((get cls.scheme-dict conf.scheme) conf)))

(async-defclass OUB [SchemeDispatchMixin]
  (setv scheme-dict (dict)
        connector-class None)

  (defn [cached-property] tls-ctx [self]
    (when self.conf.tls
      (ssl.create-default-context :cafile self.conf.tls.cafile)))

  (defn get-ws-connector [self]
    ((async-name WSConnector) :host self.conf.ws.host :path self.conf.ws.path))

  (defn get-lowest-connector [self]
    (when self.conf.ws
      (.get-ws-connector self)))

  (defn get-proxy-connector [self host port]
    (self.connector-class :host host :port port))

  (defn get-connector [self host port]
    (let [connector (.get-proxy-connector self host port)]
      (setv connector.lowest-layer.next-layer (.get-lowest-connector self))
      connector))

  (async-defn lowest-tcp-open-connection [self]
    (async-wait (.open-connection (async-name TCPStream) self.conf.host self.conf.port)))

  (async-defn lowest-tls-open-connection [self]
    (async-wait (.open-connection (async-name TLSStream) self.conf.host self.conf.port self.tls-ctx self.conf.tls.host)))

  (async-defn lowest-open-connection [self]
    (async-wait (if self.conf.tls
                    (.lowest-tls-open-connection self)
                    (.lowest-tcp-open-connection self))))

  (async-defn connect [self host port head]
    (let [connector (.get-connector self host port)
          lowest-stream (async-wait (.lowest-open-connection self))]
      (try
        (async-wait (.connect-with-head connector lowest-stream head))
        (except [Exception]
          (async-wait (.close lowest-stream))
          (raise))))))

(async-defclass INB [SchemeDispatchMixin]
  (setv scheme-dict (dict)
        acceptor-class None)

  (defn [cached-property] tls-ctx [self]
    (when self.conf.tls
      (doto (ssl.create-default-context ssl.Purpose.CLIENT_AUTH)
            (.load-cert-chain :certfile self.conf.tls.certfile
                              :keyfile  self.conf.tls.keyfile
                              :password self.conf.tls.password))))

  (defn get-ws-acceptor [self]
    ((async-name WSAcceptor)))

  (defn get-lowest-acceptor [self]
    (when self.conf.ws
      (.get-ws-acceptor self)))

  (defn get-proxy-acceptor [self]
    (self.acceptor-class))

  (defn get-acceptor [self]
    (let [acceptor (.get-proxy-acceptor self)]
      (setv acceptor.lowest-layer.next-layer (.get-lowest-acceptor self))
      acceptor))

  (async-defn lowest-tcp-start-server [self callback]
    (async-wait (.start-server (async-name TCPStream) callback self.conf.host self.conf.port)))

  (async-defn lowest-tls-start-server [self callback]
    (async-wait (.start-server (async-name TLSStream) callback self.conf.host self.conf.port self.tls-ctx)))

  (async-defn lowest-start-server [self callback]
    (async-wait
      (if self.conf.tls
          (.lowest-tls-start-server self callback)
          (.lowest-tcp-start-server self callback))))

  (async-defn accept [self lowest-stream]
    (let [acceptor (.get-acceptor self)
          stream (async-wait (.accept acceptor lowest-stream))]
      #(stream acceptor.host acceptor.port))))

(defclass SUB [SchemeDispatchMixin]
  (setv scheme-dict (dict))

  (defn fetch [self]
    (raise NotImplementedError)))

(export
  :objects [ProxyConnector AsyncProxyConnector ProxyAcceptor AsyncProxyAcceptor
            OUBConf OUB AsyncOUB INBConf INB AsyncINB SUBConf SUB])
