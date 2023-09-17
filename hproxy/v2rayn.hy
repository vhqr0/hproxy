;; https://github.com/2dust/v2rayN/wiki/分享链接格式说明(ver-2)

(require
  hiolib.rule :readers * *)

(import
  json
  base64
  traceback
  requests
  hproxy.iob *)

(defn v2rayn-parse-url [group url]
  (let [#(scheme data) (.split url "://" 1)]
    (unless (= scheme "vmess")
      (raise (RuntimeError (.format "invalid scheme {}" scheme))))
    (let [data (json.loads (.decode (base64.decodebytes (.encode data))))]
      (unless (= (get data "v") "2")
        (raise (RuntimeError (.format "invalid v {}" (get data "v")))))
      (unless (in (get data "net") #("tcp" "ws"))
        (raise (RuntimeError (.format "invalid net {}" (get data "net")))))
      (unless (= (get data "type") "none")
        (raise (RuntimeError (.format "invalid type {}" (get data "type")))))
      (unless (in (get data "tls") #("" "tls"))
        (raise (RuntimeError (.format "invalid tls {}" (get data "tls")))))
      (unless (or (not-in "scy" data) (= (get data "scy") "auto"))
        (raise (RuntimeError (.format "invalid scy {}" (get data "scy")))))
      (OUBConf.model-validate
        {"managed" True
         "enabled" False
         "name"    (get data "ps")
         "group"   group
         "dnsname" (get data "add")
         "delay"   -1.0
         "scheme"  "vmess"
         "host"    (get data "add")
         "port"    (int (get data "port"))
         "tls"     (when (= (get data "tls") "tls")
                     {"host" (.get data "sni" (get data "host"))
                      "cafile" None})
         "ws"      (when (= (get data "net") "ws")
                     {"host" (get data "host")
                      "path" (get data "path")})
         "extra"   {"id" (get data "id")}}))))

(defn v2rayn-parse [group data debug]
  (let [oubs (list)]
    (for [url (.split (.decode (base64.decodebytes data)) "\r\n")]
      (when url
        (try
          (print (.format "parse url: {}" url))
          (.append oubs (v2rayn-parse-url group url))
          (except [e Exception]
            (print (.format "except while parsing: {}" e))
            (when debug
              (print (traceback.format-exc)))))))
    oubs))

(defn v2rayn-fetch [group url debug]
  (let [resp (.get requests url :timeout 3.0)]
    (unless (= resp.status-code 200)
      (.raise-for-status resp))
    (v2rayn-parse group resp.content debug)))

(export
  :objects [v2rayn-fetch])
