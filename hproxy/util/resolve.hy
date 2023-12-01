(require
  hiolib.rule :readers * *)

(import
  random [choice]
  urllib.parse [urlparse]
  dns.resolver
  dns.query
  dns.message
  hiolib.rule *)

(defn get-default-dnsserver []
  (let [resolver (dns.resolver.get-default-resolver)]
    (+ "udp://" (choice resolver.nameservers))))

(defclass Resolver []
  (defn #-- init [self url]
    (setv self.url (urlparse url)))

  (defn [property] query-func [self]
    (ecase self.url.scheme
           "udp"   dns.query.udp
           "tcp"   dns.query.tcp
           "tls"   dns.query.tls
           "https" dns.query.https))

  (defn [property] query-host [self]
    self.url.hostname)

  (defn [property] query-port [self]
    (if self.url.port
        self.url.port
        (ecase self.url.scheme
               "udp"    53
               "tcp"    53
               "tls"   853
               "https" 443)))

  (defn query [self name rdtype [timeout None]]
    (self.query-func
      (dns.message.make-query name rdtype)
      :where self.query-host
      :port self.query-port
      :timeout timeout))

  (defn resolve [self name rdtype [timeout None]]
    (let [resp (.query self name rdtype timeout)
          result (.resolve-chaining resp)]
      (unless result.answer
        (raise RuntimeError))
      (.to-text (choice result.answer)))))

(export
  :objects [get-default-dnsserver Resolver])

(defmain []
  (let [args (parse-args [["-u" "--url" :default (get-default-dnsserver)]
                          ["-t" "--rdtype" :default "A"]
                          ["-T" "--timeout" :type float :default 3.0]
                          ["name"]])]
    (-> (Resolver args.url)
        (.query args.name args.rdtype :timeout args.timeout)
        (.to-text)
        (print))))
