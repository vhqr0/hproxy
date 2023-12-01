(require
  hiolib.rule :readers * *)

(import
  hproxy.debug :as debug
  hproxy.util.fetch *
  hproxy.cli.cli *)

(defclass Fetch [Command]
  (setv command "fetch")

  (defn [property] fetchers [self]
    (dfor #(tag fetchers) (.items (get self.conf.extra "fetchers"))
          tag (lfor fetcher fetchers (Fetcher :group (get fetcher "group") :url (get fetcher "url")))))

  (defn [property] args-spec [self]
    [["-t" "--tag" :default self.managed-tag]])

  (defn run [self args]
    (let [oubs (list)]
      (for [fetcher (get self.fetchers args.tag)]
        (try
          (for [oub (.fetch fetcher)]
            (.append oubs oub))
          (except [e Exception]
            (debug.log-info-with-exc "group=%s,url=%s,exc=[%s]%s" fetcher.group fetcher.url (type e) e))
          (else
            (debug.log-info "group=%s,url=%s" fetcher.group fetcher.url))))
      (setv (get self.conf.oubs args.tag) oubs)
      (.save self))))

(export
  :objects [])
