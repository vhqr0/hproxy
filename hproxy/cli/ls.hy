(require
  hiolib.rule :readers * *)

(import
  hproxy.debug :as debug
  hproxy.cli.cli *)

(defclass Ls [Command]
  (setv command "ls")

  (defn run [self args]
    (for [#(tag oubs) (.items self.conf.oubs)]
      (for [oub oubs]
        (debug.log-info "tag=%s,group=%s,scheme=%s,name=%s,enabled=%s"
                        tag oub.group oub.scheme oub.name oub.enabled)))))

(export
  :objects [])
