;; https://github.com/2dust/v2rayN/wiki/分享链接格式说明(ver-2)

(require
  hiolib.rule :readers * *)

(import
  json
  base64
  urllib.parse :as urlparse
  requests
  hproxy
  hproxy.base *)

(defclass V2rayNSUB [SUB]
  (setv scheme "v2rayn")

  (defn parse-vmess-data [self data]
    (let [data (json.loads (.decode (base64.decodebytes (.encode data))))
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
      (unless (=  v    "2")           (raise (RuntimeError (.format "invalid v {}"    v))))
      (unless (=  scy  "auto")        (raise (RuntimeError (.format "invalid scy {}"  scy))))
      (unless (in net  #("tcp" "ws")) (raise (RuntimeError (.format "invalid net {}"  net))))
      (unless (=  type "none")        (raise (RuntimeError (.format "invalid type {}" type))))
      (unless (in tls  #("" "tls"))   (raise (RuntimeError (.format "invalid tls {}"  tls))))
      (OUBConf.model-validate
        {"managed" True
         "enabled" False
         "name"    ps
         "group"   self.conf.group
         "dnsname" add
         "delay"   0.0
         "scheme"  "vmess"
         "host"    add
         "port"    (int port)
         "tls"     (when (= tls "tls") {"host" sni "cafile" None})
         "ws"      (when (= net "ws") {"host" host "path" path})
         "extra"   {"id" id}})))

  (defn parse-trojan-data [self data]
    (let [url (urlparse.urlparse (+ "trojan://" data))
          name (urlparse.unquote url.fragment)
          #(pwd host) (.split url.netloc  "@" 1)
          port (or url.port 443)
          query (urlparse.parse-qs url.query)
          sni (if (in "sni" query) (get query "sni" 0) host)]
      (OUBConf.model-validate
        {"managed" True
         "enabled" False
         "name"    name
         "group"   self.conf.group
         "dnsname" host
         "delay"   0.0
         "scheme"  "trojan"
         "host"    host
         "port"    port
         "tls"     {"host" sni "cafile" None}
         "ws"      None
         "extra"   {"password" pwd}})))

  (defn parse-url [self url]
    (let [#(scheme data) (.split url "://" 1)]
      ((ecase scheme
              "vmess"  self.parse-vmess-data
              "trojan" self.parse-trojan-data)
        data)))

  (defn parse [self data]
    (let [oubs (list)]
      (for [url (.split (.decode (base64.decodebytes data)) "\r\n")]
        (when url
          (try
            (hproxy.log-debug "parse url: %s" url)
            (.append oubs (.parse-url self url))
            (except [e Exception]
              (hproxy.log-info "except while parsing: %s" e)
              (hproxy.print-exc)))))
      oubs))

  (defn fetch [self]
    (let [resp (requests.get self.conf.url :timeout 3.0)]
      (unless (= resp.status-code 200)
        (.raise-for-status resp))
      (.parse self resp.content))))

(export
  :objects [])
