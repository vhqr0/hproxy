(require
  hiolib.rule :readers * *)

(import
  hproxy.cli.cli *)

(defclass Ls [Command]
  (setv command "ls")

  (defn [property] args-spec [self]
    [["-a" "--all" :action "store_true" :default False]])

  (defn run [self]
    (for [#(tag oubs) (.items self.conf.oubs)
          oub oubs :if (or self.args.all oub.enabled)]
      (let [scheme oub.scheme]
        (cond (and oub.tls oub.ws) (+= scheme "/wss")
              oub.tls              (+= scheme "/tls")
              oub.ws               (+= scheme "/ws"))
        (log-info "tag=%s,group=%s,scheme=%s,name=%s,enabled=%s"
                  tag oub.group scheme oub.name oub.enabled)))))

(export
  :objects [])
