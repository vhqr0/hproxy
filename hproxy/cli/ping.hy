(require
  hiolib.rule :readers * *)

(import
  asyncio
  time [time]
  functools [partial]
  concurrent.futures [ThreadPoolExecutor]
  hproxy.debug :as debug
  hproxy.iob *
  hproxy.util.ping *
  hproxy.cli.cli *)

(defn timeit [f #* args #** kwargs]
  (let [ts (time)]
    (f #* args #** kwargs)
    (- (time) ts)))

(defclass Ping [Command]
  (setv command "ping")

  (defn [property] ping-url [self]
    (.get self.conf.extra "pingUrl" "http://www.google.com"))

  (defn [property] args-spec [self]
    [["-t" "--tag" :default self.managed-tag]
     ["-u" "--ping-url" :default self.ping-url]
     ["-T" "--timeout" :type float :default 3.0]])

  (defn ping-oub [self pinger oub timeout]
    (unless oub.managed
      (return))

    (setv oub.enabled False
          oub.delay 0.0)

    (unless oub.host
      (return))

    (defn do-ping-oub []
      (asyncio.run (.ping pinger (AsyncOUB.from-conf oub) :timeout timeout)))

    (try
      (setv oub.delay (timeit do-ping-oub)
            oub.enabled True)
      (except [e Exception]
        (debug.log-info-with-exc "group=%s,name=%s,exc=[%s]%s" oub.group oub.name (type e) e))
      (else
        (debug.log-info "group=%s,name=%s,delay=%s" oub.group oub.name oub.delay))))

  (defn run [self args]
    (with [executor (ThreadPoolExecutor)]
      (.map executor
            (partial self.ping-oub (AsyncPinger args.ping-url) :timeout args.timeout)
            (get self.conf.oubs args.tag)))
    (.save self)))

(export
  :objects [])
