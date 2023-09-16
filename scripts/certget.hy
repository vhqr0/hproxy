#!/usr/bin/env hy

(require
  hyrule :readers * *)

(import
  socket
  ssl)

(defmain [_ host [port 443]]
  (let [ctx (ssl.create-default-context)]
    (setv ctx.check-hostname False
          ctx.verify-mode ssl.CERT_NONE)
    (with [sock (socket.create-connection #(host port))]
      (with [ssock (.wrap-socket ctx sock)]
        (print (ssl.DER-cert-to-PEM-cert (.getpeercert ssock True)) :end "")))))
