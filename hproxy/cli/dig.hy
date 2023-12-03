(require
  hiolib.rule :readers * *)

(import
  argparse
  asyncio
  random [choice]
  collections [deque]
  hproxy.proto.dns *
  hproxy.cli.cli *
  hproxy.cli.curl *)

(defclass Dig [Command]
  (setv command "dig")

  (defn [property] args-spec [self]
    [["-v" "--via-tag" :default "direct"]
     ["-t" "--to-tag" :default "forward"]
     ["-T" "--timeout" :type float :default 3.0]
     ["-m" "--max-workers" :type int :default 8]
     ["-u" "--undig" :action "store_true" :default False]
     ["curl_command" :nargs argparse.REMAINDER]])

  (defn [property] curl-command [self]
    (or self.args.curl-command (.get self.extra "digCurl" [(+ "dns://" (choice (get-default-nameservers)))])))

  (defn/a dig-1 [self oub]
    (unless oub.managed
      (return))

    (setv #(oub.enabled oub.host) #(False ""))

    (unless oub.dnsname
      (return))

    (let [via-oub (choice (lfor oub (get self.conf.oubs self.args.via-tag) :if oub.enabled oub))]
      (try
        (let [curl-command [#* self.curl-command oub.dnsname]
              resp (await (async-curl curl-command oub :timeout self.args.timeout))
              result (.resolve-chaining resp)]
          (unless result.answer
            (raise RuntimeError))
          (setv #(oub.enabled oub.host) #(True (.to-text (choice result.answer)))))
        (except [e Exception]
          (log-info-exc "group=%s,name=%s,host=%s,via=%s,exc=[%s]%s"
                        oub.group oub.name oub.dnsname via-oub.name (type e) e))
        (else
          (log-info "group=%s,name=%s,host=%s,via=%s"
                    oub.group oub.name oub.host via-oub.name)))))

  (defn/a worker [self oubs]
    (while oubs
      (await (.dig-1 self (.popleft oubs)))))

  (defn/a arun [self]
    (when self.args.undig
      (.undig self)
      (return))

    (let [oubs (deque (get self.conf.oubs self.args.to-tag))
          tasks (list)]
      (do-n self.args.max-workers
            (.append tasks (asyncio.create-task (.worker self oubs)))
            (await (asyncio.sleep 0.1)))
      (await (asyncio.wait tasks)))
    (.save self))

  (defn undig [self]
    (for [oub (get self.conf.oubs self.args.to-tag)]
      (setv #(oub.enabled oub.host) #(False oub.dnsname)))
    (.save self)))

(export
  :objects [])
