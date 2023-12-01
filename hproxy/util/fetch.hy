;; https://github.com/2dust/v2rayN/wiki/分享链接格式说明(ver-2)

(require
  hiolib.rule :readers * *)

(import
  json
  base64
  urllib.parse :as urlparse
  requests
  hiolib.rule *
  hproxy.debug :as debug
  hproxy.iob *)

(defn decode-v2rayn-data [data]
  ;; data: bytes, resp.content
  ;; ret: urls str join with \r\n
  (.decode (base64.decodebytes data)))

(defn decode-vmess-data [data]
  ;; data: str, url.netloc
  ;; ret: json format str of vmess conf
  (.decode (base64.decodebytes (.encode data))))

(defclass Fetcher []
  (defn #-- init [self group url]
    (setv self.group group
          self.url url))

  (defn fetch [self [timeout None]]
    (let [resp (requests.get self.url :timeout timeout)]
      (unless (= resp.status-code 200)
        (.raise-for-status resp))
      (.parse self resp.content)))

  (defn parse [self data]
    (let [oubs (list)]
      (for [url (.split (decode-v2rayn-data data) "\r\n")]
        (when url
          (try
            (debug.log-debug "parse url: %s" url)
            (.append oubs (.parse-url self url))
            (except [e Exception]
              (debug.log-info-with-exc "except while parsing: %s" e)))))
      oubs))

  (defn parse-url [self url]
    (let [url (urlparse.urlparse url)]
      ((ecase url.scheme
              "vmess"  self.parse-vmess-url
              "trojan" self.parse-trojan-url)
        url)))

  (defn parse-vmess-url [self url]
    ;; url.hostname downcase origin str, use url.netloc instead
    (let [data (json.loads (decode-vmess-data url.netloc))
          v    (get data "v")
          ps   (get data "ps")
          add  (get data "add")
          port (get data "port")
          id   (get data "id")
          scy  (or (.get data "scy") "auto")
          net  (or (.get data "net") "tcp")
          type (or (.get data "type") "none")
          host (or (.get data "host") add)
          path (or (.get data "path") "/")
          tls  (or (.get data "tls") "")
          sni  (or (.get data "sni") add)]
      (unless (= v "2")              (raise (RuntimeError (.format "invalid v {}"    v))))
      (unless (= scy "auto")         (raise (RuntimeError (.format "invalid scy {}"  scy))))
      (unless (in net #("tcp" "ws")) (raise (RuntimeError (.format "invalid net {}"  net))))
      (unless (= type "none")        (raise (RuntimeError (.format "invalid type {}" type))))
      (unless (in tls #("" "tls"))   (raise (RuntimeError (.format "invalid tls {}"  tls))))
      (OUBConf.model-validate
        {"managed" True
         "enabled" False
         "name"    ps
         "group"   self.group
         "dnsname" add
         "delay"   0.0
         "scheme"  "vmess"
         "host"    add
         "port"    (int port)
         "tls"     (when (= tls "tls") {"host" sni "cafile" None})
         "ws"      (when (= net "ws") {"host" host "path" path})
         "extra"   {"id" id}})))

  (defn parse-trojan-url [self url]
    (let [name (urlparse.unquote url.fragment)
          password url.username
          host url.hostname
          port (or url.port 443)
          query (urlparse.parse-qs url.query)
          sni (if (in "sni" query) (get query "sni" 0) host)]
      (OUBConf.model-validate
        {"managed" True
         "enabled" False
         "name"    name
         "group"   self.group
         "dnsname" host
         "delay"   0.0
         "scheme"  "trojan"
         "host"    host
         "port"    port
         "tls"     {"host" sni "cafile" None}
         "ws"      None
         "extra"   {"password" password}}))))

(export
  :objects [Fetcher])

(defmain []
  (defn url-trans [url]
    (let [url (urlparse.urlparse url)]
      (ecase url.scheme
             "vmess"  (+ "vmess://" (decode-vmess-data url.netloc))
             "trojan" (.geturl url))))
  (let [args (parse-args [["-i" "--input" :default "sub"]])
        data (with [f (open args.input "rb")] (.read f))]
    (for [url (.split (decode-v2rayn-data data) "\r\n")]
      (when url
        (try
          (print (url-trans url))
          (except [e Exception]
            (print (.format "except while parsing url: {}" url))))))))
