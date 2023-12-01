(require
  hiolib.rule :readers * *)

(import
  functools [partial]
  concurrent.futures [ThreadPoolExecutor]
  hproxy.debug :as debug
  hproxy.util.resolve *
  hproxy.cli.cli *
  dns.rdatatype)

(defclass Dig [Command]
  (setv rdtype None)

  (defn [property] dig-url [self]
    (.get self.conf.extra "digUrl" (get-default-dnsserver)))

  (defn [property] args-spec [self]
    [["-t" "--tag" :default self.managed-tag]
     ["-u" "--dig-url" :default self.dig-url]
     ["-T" "--timeout" :type float :default 3.0]])

  (defn dig-oub [self resolver oub timeout]
    (unless oub.managed
      (return))
    (setv oub.enabled False
          oub.host "")
    (when oub.dnsname
      (try
        (setv oub.host (.resolve resolver oub.dnsname self.rdtype))
        (except [e Exception]
          (debug.log-info-with-exc "group=%s,name=%s,exc=[%s]%s" oub.group oub.name (type e) e))
        (else
          (debug.log-info "group=%s,name=%s,host=%s" oub.group oub.name oub.host)))))

  (defn run [self args]
    (with [executor (ThreadPoolExecutor)]
      (.map executor
            (partial self.dig-oub (Resolver args.dig-url) :timeout args.timeout)
            (get self.conf.oubs args.tag)))
    (.save self)))

(defclass Dig4 [Dig]
  (setv command "dig4"
        rdtype dns.rdatatype.A))

(defclass Dig6 [Dig]
  (setv command "dig6"
        rdtype dns.rdatatype.AAAA))

(export
  :objects [])
