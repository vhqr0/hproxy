(require
  hiolib.rule :readers * *)

(import
  hiolib.stream *)

(async-defclass ProxyConnector [(async-name Connector)]
  (defn #-- init [self host port #** kwargs]
    (#super-- init #** kwargs)
    (setv self.host host
          self.port port)))

(async-defclass ProxyAcceptor [(async-name Acceptor)])

(async-defclass Requester []
  (defn [property] head [self]
    (raise NotImplementedError))

  (async-defn request [self stream]
    (raise NotImplementedError))

  (defn [classmethod] resp-to-str [cls resp]
    (str resp))

  (defn [classmethod] resp-to-bytes [cls resp]
    (bytes resp)))

(export
  :objects [ProxyConnector AsyncProxyConnector ProxyAcceptor AsyncProxyAcceptor Requester AsyncRequester])
