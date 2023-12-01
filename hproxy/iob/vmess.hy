(require
  hiolib.rule :readers * *)

(import
  functools [cached-property]
  hproxy.proto.vmess *
  hproxy.iob.iob *)

(async-defclass VMessOUB [(async-name OUB)]
  (setv scheme "vmess")

  (defn [cached-property] id [self]
    (VMessID (get self.conf.extra "id")))

  (defn get-proxy-connector [self host port]
    ((async-name VMessConnector) :host host :port port :id self.id)))

(export
  :objects [])
