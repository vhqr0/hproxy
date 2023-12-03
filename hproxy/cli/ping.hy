(require
  hiolib.rule :readers * *)

(import
  argparse
  asyncio
  time [time]
  collections [deque]
  hproxy.iob *
  hproxy.cli.cli *
  hproxy.cli.curl *)

(defclass Ping [Command]
  (setv command "ping")

  (defn [property] args-spec [self]
    [["-t" "--to-tag" :default "forward"]
     ["-T" "--timeout" :type float :default 3.0]
     ["-m" "--max-workers" :type int :default 8]
     ["curl_command" :nargs argparse.REMAINDER]])

  (defn [property] curl-command [self]
    (or self.args.curl-command (.get self.extra "pingCurl" ["http://www.google.com"])))

  (defn/a ping-1 [self oub]
    (unless oub.managed
      (return))

    (setv #(oub.enabled oub.delay) #(False 0.0))

    (unless oub.host
      (return))

    (let [start-time (time)]
      (try
        (await (async-curl self.curl-command oub :timeout self.args.timeout))
        (setv #(oub.enabled oub.delay) #(True (- (time) start-time)))
        (except [e Exception]
          (log-info-exc "group=%s,name=%s,exc=[%s]%s" oub.group oub.name (type e) e))
        (else
          (log-info "group=%s,name=%s,delay=%s" oub.group oub.name oub.delay)))))

  (defn/a worker [self oubs]
    (while oubs
      (await (.ping-1 self (.popleft oubs)))))

  (defn/a arun [self]
    (let [oubs (deque (get self.conf.oubs self.args.to-tag))
          tasks (list)]
      (do-n self.args.max-workers
            (.append tasks (asyncio.create-task (.worker self oubs)))
            (await (asyncio.sleep 0.1)))
      (await (asyncio.wait tasks)))
    (.save self)))

(export
  :objects [])
