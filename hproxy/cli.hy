(require
  hiolib.rule :readers * *)

(import
  asyncio
  argparse
  random [choice]
  timeit [timeit]
  urllib.parse [urlparse]
  concurrent.futures [ThreadPoolExecutor]
  yaml
  dns.resolver
  dns.query
  dns.message
  dns.rdatatype
  hiolib.rule *
  hiolib.util.ws *
  hproxy
  hproxy.iob *
  hproxy.server *)

(defclass Cli []
  (setv command-dict (dict))

  (setv args-spec [["-d" "--debug" :action "store_true" :default False]
                   ["-c" "--conf-path" :default "config.yaml"]
                   ["command"]
                   ["command_args" :nargs argparse.REMAINDER]])

  (defn run [self [args None]]
    (let [args (parse-args self.args-spec args)]
      (setv hproxy.debug args.debug)
      (.run ((get self.command-dict args.command) :path args.conf-path)
            (or args.command-args (list))))))

(defclass Command []
  (setv command None)

  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (when cls.command
      (setv (get Cli.command-dict cls.command) cls)))

  (defn #-- init [self path]
    (setv self.path path)
    (.load self))

  (defn [property] server [self]
    (Server self.conf))

  (defn [property] managed-tag [self]
    (.get self.conf.extra "managedtag" "forward"))

  (defn load [self]
    (setv self.conf (.model-validate
                      ServerConf
                      (with [f (open self.path)]
                        (yaml.load f :Loader yaml.CLoader)))))

  (defn save [self]
    (with [f (open self.path "w")]
      (yaml.dump (.dict self.conf) f :Dumper yaml.CDumper :sort-keys False)))

  (defn run [self args]
    (raise NotImplementedError)))

(defclass Run [Command]
  (setv command "run")

  (defn run [self args]
    (try
      (asyncio.run ((fn/a [] (await (.serve-forever self.server)))))
      (except [KeyboardInterrupt]
        (print "keyboard quit")))))

(defclass Fetch [Command]
  (setv command "fetch")

  (defn run [self args]
    (let [args (parse-args [["-t" "--tag" :default self.managed-tag]]
                           args)
          oubs (.fetch-subs self.server args.tag)]
      (setv (get self.conf.oubs args.tag) oubs))
    (.save self)))

(defclass ForEachOubCommand [Command]
  (defn for-each-1 [self oub #* args]
    (raise NotImplementedError))

  (defn for-each [self tag args]
    (with [executor (ThreadPoolExecutor)]
      (.map executor
            (fn [oub] (.for-each-1 self oub #* args))
            (gfor oub (get self.conf.oubs tag) :if oub.managed oub)))))

(defclass Dig [ForEachOubCommand]
  (setv rdtype None)

  (defn [property] default-url [self]
    (or (.get self.conf.extra "digurl")
        (let [resolver (dns.resolver.get-default-resolver)]
          (+ "udp://" (get resolver.nameservers 0)))))

  (defn for-each-1 [self oub url]
    (setv oub.host "")
    (when oub.dnsname
      (try
        (let [url (urlparse url)
              resp ((ecase url.scheme
                           "udp" dns.query.udp
                           "tcp" dns.query.tcp
                           "tls" dns.query.tls)
                     (dns.message.make-query oub.dnsname self.rdtype)
                    :where url.hostname
                    :port (or url.port 53)
                    :timeout 3.0)
              ans (lfor a resp.answer :if (= a.rdtype self.rdtype) a)]
          (setv oub.host (.to-text (choice (list (.keys (. (choice ans) items)))))))
        (except [e Exception]
          (print oub.group oub.name (type e) e)
          (when hproxy.debug
            (print (traceback.format-exc))))
        (else
          (print oub.group oub.name oub.host)))))

  (defn run [self args]
    (let [args (parse-args [["-t" "--tag" :default self.managed-tag]
                            ["-u" "--url" :default self.default-url]]
                           args)]
      (.for-each self args.tag #(args.url)))
    (.save self)))

(defclass Dig4 [Dig]
  (setv command "dig4"
        rdtype dns.rdatatype.A))

(defclass Dig6 [Dig]
  (setv command "dig6"
        rdtype dns.rdatatype.AAAA))

(defclass Ping [ForEachOubCommand]
  (setv command "ping")

  (defn [property] default-url [self]
    (.get self.conf.extra "pingurl" "http://www.google.com"))

  (defn for-each-1 [self oub url]
    (setv oub.delay -1.0
          oub.enabled False)
    (when oub.host
      (try
        (let [url (urlparse url)]
          (defn/a tcp-ping []
            (with/a [_ (await (.lowest-open-connection (AsyncOUB.from-conf oub)))]))
          (defn/a http-ping []
            (let [head (.pack AsyncHTTPReq "GET" (or url.path "/") "HTTP/1.1" {"Host" url.hostname})]
              (with/a [stream (await (.connect (AsyncOUB.from-conf oub)
                                               :host url.hostname :port (or url.port 80) :head head))]
                (await (.unpack-from-stream AsyncHTTPResp stream)))))
          (defn/a ping []
            (await (asyncio.wait-for (ecase url.scheme "tcp" (tcp-ping) "http" (http-ping)) :timeout 3.0)))
          (setv oub.delay (timeit (fn [] (asyncio.run (ping))) :number 1)
                oub.enabled True))
        (except [e Exception]
          (print oub.group oub.name (type e) e)
          (when hproxy.debug
            (print (traceback.format-exc))))
        (else
          (print oub.group oub.name oub.delay)))))

  (defn run [self args]
    (let [args (parse-args [["-t" "--tag" :default self.managed-tag]
                            ["-u" "--url" :default self.default-url]]
                           args)]
      (.for-each self args.tag #(args.url)))
    (.save self)))

(export
  :objects [Cli])
