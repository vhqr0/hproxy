(require
  hiolib.rule :readers * *)

(import
  hiolib.stream *)

(async-defclass ProxyConnector [(async-name Connector)]
  #^ str host
  #^ int port

  (defn #-- init [self host port #** kwargs]
    (#super-- init #** kwargs)
    (setv self.host host
          self.port port)))

(async-defclass ProxyAcceptor [(async-name Acceptor)]
  #^ str host
  #^ int port)

(export
  :objects [ProxyConnector AsyncProxyConnector ProxyAcceptor AsyncProxyAcceptor])
