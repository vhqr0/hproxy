(require
  hiolib.rule :readers * *)

(import
  asyncio
  hproxy.debug :as debug
  hproxy.iob *
  hproxy.server *
  hproxy.cli.cli *)

(defclass Run [Command]
  (setv command "run")

  (defn [property] inb [self]
    (AsyncINB.from-conf self.conf.inb))

  (defn [property] oubs [self]
    (dfor #(tag oubs) (.items self.conf.oubs)
          tag (lfor oub oubs :if oub.enabled (AsyncOUB.from-conf oub))))

  (defn [property] tags [self]
    self.conf.tags)

  (defn [property] server [self]
    (Server :inb self.inb :oubs self.oubs :tags self.tags))

  (defn run [self args]
    (try
      (asyncio.run
        ((fn/a [] (await (.serve-forever self.server)))))
      (except [KeyboardInterrupt]
        (debug.log-info "keyboard quit")))))

(export
  :objects [])
