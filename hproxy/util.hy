(require
  hiolib.rule :readers * *)

(import
  asyncio
  random [choice]
  timeit [timeit]
  dns.query
  dns.message
  dns.rdatatype
  urllib.parse [urlparse]
  hiolib.util.ws *
  hproxy.iob *)

(defn dig [conf url rdtype]
  (setv conf.host "")
  (when conf.dnsname
    (let [url (urlparse url)
          resp ((ecase url.scheme
                       "udp" dns.query.udp
                       "tcp" dns.query.tcp
                       "tls" dns.query.tls)
                 (dns.message.make-query conf.dnsname rdtype)
                :where url.hostname
                :port (or url.port 53)
                :timeout 3.0)
          ans (lfor a resp.answer :if (= a.rdtype rdtype) a)]
      (setv conf.host (.to-text (choice (list (.keys (. (choice ans) items)))))))))

(defn dig4 [conf url] (dig conf url dns.rdatatype.A))
(defn dig6 [conf url] (dig conf url dns.rdatatype.AAAA))

(defn ping [conf url]
  (setv conf.delay -1.0
        conf.enabled False)
  (when conf.host
    (let [url (urlparse url)
          oub (AsyncOUB.from-conf conf)]
      (defn/a ping-func []
        (ecase url.scheme
               "tcp"  (with/a [_ (await (.lowest-open-connection oub))])
               "http" (let [head (.pack AsyncHTTPReq "GET" (or url.path "/") "HTTP/1.1" {"Host" url.hostname})]
                        (with/a [stream (await (.connect oub :host url.hostname :port (or url.port 80) :head head))]
                          (await (.unpack-from-stream AsyncHTTPResp stream))))))
      (defn/a ping-with-timeout-func []
        (await (asyncio.wait-for (ping-func) :timeout 3.0)))
      (setv conf.delay
            (timeit (fn [] (asyncio.run (ping-with-timeout-func))) :number 1)
            conf.enabled True))))

(export
  :objects [dig4 dig6 ping])
