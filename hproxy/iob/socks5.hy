(require
  hiolib.rule :readers * *)

(import
  functools [cached-property]
  hproxy.proto.socks5 *
  hproxy.iob.iob *)

(async-defclass Socks5OUB [(async-name OUB)] (setv scheme "socks5" connector-class (async-name Socks5Connector)))
(async-defclass Socks5INB [(async-name INB)] (setv scheme "socks5" acceptor-class  (async-name Socks5Acceptor)))
(async-defclass AutoINB   [(async-name INB)] (setv scheme "auto"   acceptor-class  (async-name AutoAcceptor)))

(defclass TrojanIOBMixin []
  (defn [cached-property] auth [self]
    (get-trojan-auth (get self.conf.extra "password"))))

(async-defclass TrojanOUB [TrojanIOBMixin (async-name OUB)]
  (setv scheme "trojan")
  (defn get-proxy-connector [self host port]
    ((async-name TrojanConnector) :host host :port port :auth self.auth)))

(async-defclass TrojanINB [TrojanIOBMixin (async-name INB)]
  (setv scheme "trojan")
  (defn get-proxy-acceptor [self]
    ((async-name TrojanAcceptor) :auth self.auth)))

(export
  :objects [])
