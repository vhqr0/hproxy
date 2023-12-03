(require
  hiolib.rule :readers * *)

(import
  argparse
  asyncio
  random [choice]
  yarl [URL]
  hiolib.rule *
  hproxy.proto.dns *
  hproxy.proto.http *
  hproxy.proto.tls13 *
  hproxy.iob *
  hproxy.cli.cli *)

(async-defclass Curller []
  (setv scheme None
        scheme-port None
        scheme-dict (dict))

  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (unless (is cls.scheme None)
      (setv (get cls.scheme-dict cls.scheme) cls)))

  (defn [classmethod] from-url [cls url #* args]
    (let [url (URL url)]
      ((get cls.scheme-dict url.scheme) url #* args)))

  (defn #-- init [self url #* args]
    (setv self.url url
          self.args (parse-args (.get-args-spec self) args)
          self.requester (.get-requester self)))

  (defn [property] port [self]
    (or self.url.port self.scheme-port))

  (defn get-args-spec [self]
    (list))

  (defn get-requester [self]
    (raise NotImplementedError))

  (defn resp-to-str [self resp]
    (.resp-to-str self.requester resp))

  (defn resp-to-bytes [self resp]
    (.resp-to-bytes self.requester resp))

  (defn get-highest-connector [self])

  (async-defn curl [self oub [timeout None]]
    (if (is timeout None)
        (async-with [stream (async-wait (.connect oub
                                                  :host self.url.host
                                                  :port self.port
                                                  :head self.requester.head
                                                  :highest-connector (.get-highest-connector self)))]
          (async-wait (.request self.requester stream)))
        (async-if
          (await (asyncio.wait-for (.curl self oub) :timeout timeout))
          (raise NotImplementedError)))))

(async-deffunc curl [args oub [timeout None]]
  (when (isinstance oub OUBConf)
    (setv oub (.from-conf (async-name OUB) oub)))
  (async-wait (.curl (.from-url (async-name Curller) #* args) oub :timeout timeout)))



(async-defclass TLSCurllerMixin []
  (defn get-args-spec [self]
    [["--tls-host" :default self.url.host]
     #* (#super get-args-spec)])

  (defn get-highest-connector [self]
    ((async-name TLS13Connector) :host self.args.tls-host)))

(async-defclass HTTPCurller [(async-name Curller)]
  (setv scheme "http"
        scheme-port 80)

  (defn get-args-spec [self]
    [["-X" "--http-meth" :default "GET"]
     ["-H" "--http-headers" :action "append"]
     ["-d" "--http-content"]])

  (defn get-requester [self]
    ((async-name HTTPRequester)
      :meth self.args.http-meth
      :path self.url.raw-path-qs
      :host self.url.host
      :headers (when self.args.http-headers
                 (http-unpack-headers [#* self.args.http-headers ""]))
      :content (when self.args.http-content
                 (.encode self.args.http-content)))))

(async-defclass HTTPSCurller [(async-name TLSCurllerMixin) (async-name HTTPCurller)]
  (setv scheme "https"
        scheme-port 443))

(async-defclass DNSCurller [(async-name Curller)]
  (setv scheme "dns"
        scheme-port 53)

  (defn get-args-spec [self]
    [["-t" "--dns-rdtype" :default "A"]
     ["-c" "--dns-rdclass" :default "IN"]
     ["dns_name"]])

  (defn get-requester [self]
    ((async-name DNSRequester)
      :name self.args.dns-name
      :rdtype self.args.dns-rdtype
      :rdclass self.args.dns-rdclass)))

(async-defclass DOTCurller [(async-name TLSCurllerMixin) (async-name DNSCurller)]
  (setv scheme "dot"
        scheme-port 853))



(defclass Curl [Command]
  (setv command "curl")

  (defn [property] args-spec [self]
    [["-v" "--via-tag" :default "forward"]
     ["-T" "--timeout" :type float :default 3.0]
     ["-o" "--output"]
     ["-V" "--verbose" :action "store_true" :default False]
     ["curl_command" :nargs argparse.REMAINDER]])

  (defn/a arun [self]
    (let [curller (AsyncCurller.from-url #* self.args.curl-command)
          via-oub (choice (lfor oub (get self.conf.oubs self.args.via-tag) :if oub.enabled oub))]
      (log-info "curl to %s via %s" curller.url via-oub.name)
      (try
        (setv resp (await (.curl curller (AsyncOUB.from-conf via-oub) :timeout self.args.timeout)))
        (except [e Exception]
          (log-info-exc "except while curlling to %s via %s: [%s]%s"
                        curller.url via-oub.name (type e) e)
          (return)))
      (when self.args.output
        (with [f (open self.args.output "wb")]
          (.write f (.resp-to-bytes curller resp))))
      (when (or (not self.args.output) self.args.verbose)
        (print (.resp-to-str curller resp))))))

(export
  :objects [Curller AsyncCurller curl async-curl])
