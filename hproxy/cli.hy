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
  hproxy
  hproxy.base *
  hproxy.server *
  hproxy.proto.http *
  hproxy.proto.tls13 *)


;;; base

(defclass Cli []
  (setv command-dict (dict))

  (setv args-spec [["-d" "--debug" :action "store_true" :default False]
                   ["-c" "--conf-path" :default "config.yaml"]
                   ["command"]
                   ["command_args" :nargs argparse.REMAINDER]])

  (defn run [self [args None]]
    (let [args (parse-args self.args-spec args)]
      (setv hproxy.debug args.debug)
      (let [command ((get self.command-dict args.command) :path args.conf-path)
            command-args (parse-args command.args-spec args.command-args)]
        (.run command command-args)))))

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

  (defn [property] extra [self]
    (or self.conf.extra (dict)))

  (defn [property] subs [self]
    (dfor #(tag subs) (.items (get self.extra "subs"))
          tag (lfor sub subs (SUB.from-conf (.model-validate SUBConf sub)))))

  (defn [property] managed-tag [self]
    (.get self.extra "managedTag" "forward"))

  (defn [property] dig-url [self]
    (or (.get self.extra "digUrl")
        (let [resolver (dns.resolver.get-default-resolver)]
          (+ "udp://" (choice resolver.nameservers)))))

  (defn [property] ping-url [self]
    (.get self.extra "pingUrl" "http://www.google.com"))

  (defn load [self]
    (setv self.conf (.model-validate
                      ServerConf
                      (with [f (open self.path)]
                        (yaml.load f :Loader yaml.CLoader)))))

  (defn save [self]
    (with [f (open self.path "w")]
      (yaml.dump (.dict self.conf) f :Dumper yaml.CDumper :sort-keys False)))

  (defn [property] args-spec [self]
    (list))

  (defn run [self args]
    (raise NotImplementedError)))


;;; ls

(defclass Ls [Command]
  (setv command "ls")

  (defn run [self args]
    (for [#(tag oubs) (.items self.conf.oubs)]
      (for [oub oubs]
        (hproxy.log-info "tag=%s,group=%s,name=%s,enabled=%s"
                         tag oub.group oub.name oub.enabled)))))


;;; run

(defclass Run [Command]
  (setv command "run")

  (defn run [self args]
    (try
      (asyncio.run ((fn/a [] (await (.serve-forever self.server)))))
      (except [KeyboardInterrupt]
        (hproxy.log-info "keyboard quit")))))


;;; fetch

(defclass Fetch [Command]
  (setv command "fetch")

  (defn [property] args-spec [self]
    [["-t" "--tag" :default self.managed-tag]])

  (defn run [self args]
    (let [oubs (list)]
      (for [sub (get self.subs args.tag)]
        (try
          (for [oub (.fetch sub)]
            (.append oubs oub))
          (except [e Exception]
            (hproxy.log-info "group=%s,url=%s,exc=[%s]%s"
                             sub.conf.group sub.conf.url (type e) e)
            (hproxy.print-exc))
          (else
            (hproxy.log-info "group=%s,url=%s" sub.conf.group sub.conf.url))))
      (setv (get self.conf.oubs args.tag) oubs))
    (.save self)))


;;; for each base

(defclass ForEachOubCommand [Command]
  (defn for-each-1 [self oub #* args]
    (raise NotImplementedError))

  (defn for-each [self tag args]
    (with [executor (ThreadPoolExecutor)]
      (.map executor
            (fn [oub] (.for-each-1 self oub #* args))
            (gfor oub (get self.conf.oubs tag) :if oub.managed oub)))))


;;; dig

(defclass Dig [ForEachOubCommand]
  (setv rdtype None)

  (defn dig [self url name timeout]
    (let [url (urlparse url)
          query-func (ecase url.scheme
                            "udp"   dns.query.udp
                            "tcp"   dns.query.tcp
                            "tls"   dns.query.tls
                            "https" dns.query.https)
          req (dns.message.make-query name self.rdtype)
          resp (query-func req :where url.hostname :port (or url.port 53) :timeout timeout)
          result (.resolve-chaining resp)]
      (choice result.answer)))

  (defn for-each-1 [self oub url timeout]
    (setv oub.host ""
          oub.enabled False)
    (when oub.dnsname
      (try
        (setv oub.host (.to-text (.dig self url oub.dnsname timeout)))
        (except [e Exception]
          (hproxy.log-info "group=%s,name=%s,exc=[%s]%s"
                           oub.group oub.name (type e) e)
          (hproxy.print-exc))
        (else
          (hproxy.log-info "group=%s,name=%s,host=%s"
                           oub.group oub.name oub.host)))))

  (defn [property] args-spec [self]
    [["-t" "--tag" :default self.managed-tag]
     ["-u" "--url" :default self.dig-url]
     ["-T" "--timeout" :type float :default 3.0]])

  (defn run [self args]
    (.for-each self args.tag #(args.url args.timeout))
    (.save self)))

(defclass Dig4 [Dig]
  (setv command "dig4"
        rdtype dns.rdatatype.A))

(defclass Dig6 [Dig]
  (setv command "dig6"
        rdtype dns.rdatatype.AAAA))


;;; ping

(defclass Ping [ForEachOubCommand]
  (setv command "ping")

  (defn/a aping [self url oub]
    (let [url (urlparse url)
          head (.pack HTTPReq "GET" (or url.path "/") "HTTP/1.1" {"Host" url.hostname})]
      (ecase url.scheme
             "tcp"   (with/a [_ (await (.lowest-tcp-open-connection oub))])
             "http"  (with/a [stream (await (.connect oub :host url.hostname :port (or url.port 80) :head head))]
                       (await (.unpack-from-stream AsyncHTTPResp stream)))
             "https" (with/a [lowest-stream (await (.lowest-open-connection oub))]
                       (let [connector (AsyncTLS13Connector :host url.hostname :next-layer (.get-connector oub url.hostname (or url.port 443)))
                             stream (await (.connect-with-head connector lowest-stream head))]
                         (await (.unpack-from-stream AsyncHTTPResp stream)))))))

  (defn ping [self url oub timeout]
    (asyncio.run
      ((fn/a []
         (await (asyncio.wait-for (.aping self url oub) :timeout timeout))))))

  (defn for-each-1 [self oub url timeout]
    (setv oub.delay -1.0
          oub.enabled False)
    (when oub.host
      (try
        (setv oub.delay (timeit (fn [] (.ping self url (AsyncOUB.from-conf oub) timeout)) :number 1)
              oub.enabled True)
        (except [e Exception]
          (hproxy.log-info "group=%s,name=%s,exc=[%s]%s"
                           oub.group oub.name (type e) e)
          (hproxy.print-exc))
        (else
          (hproxy.log-info "group=%s,name=%s,delay=%s"
                           oub.group oub.name oub.delay)))))

  (defn [property] args-spec [self]
    [["-t" "--tag" :default self.managed-tag]
     ["-u" "--url" :default self.ping-url]
     ["-T" "--timeout" :type float :default 3.0]])

  (defn run [self args]
    (.for-each self args.tag #(args.url args.timeout))
    (.save self)))

(export
  :objects [Cli])
