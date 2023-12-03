;; https://github.com/2dust/v2rayN/wiki/分享链接格式说明(ver-2)

(require
  hiolib.rule :readers * *)

(import
  asyncio
  argparse
  random [choice]
  json
  base64
  yarl [URL]
  hiolib.rule *
  hproxy.iob *
  hproxy.cli.cli *
  hproxy.cli.curl *)

(defn decode-v2rayn-data [data]
  ;; data: bytes, resp.content
  ;; ret: url strs joined with \r\n
  (.decode (base64.decodebytes data)))

(defn decode-vmess-data [data]
  ;; data: str, case-sensitive url host
  ;; ret: json format str
  (.decode (base64.decodebytes (.encode data))))

(defclass V2rayNParser []
  (defn #-- init [self group]
    (setv self.group group))

  (defn parse [self data]
    (let [oubs (list)]
      (for [url (.split (decode-v2rayn-data data) "\r\n")]
        (when url
          (try
            (.append oubs (.parse-url self url))
            (except [e Exception]
              (log-info-exc "except while parsing url %s: [%s]%s" url (type e) e)))))
      oubs))

  (defn parse-url [self url]
    ((ebranch (.startswith url it)
              "vmess://"  self.parse-vmess-url
              "trojan://" self.parse-trojan-url)
      url))

  (defn parse-vmess-url [self url]
    (let [data (json.loads (decode-vmess-data (.removeprefix url "vmess://")))
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
    (let [url (URL url)
          name url.fragment
          password url.user
          host url.host
          port (or url.port 443)
          sni (.get url.query "sni" host)]
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

(defclass Fetch [Command]
  (setv command "fetch")

  (defn [property] args-spec [self]
    [["-v" "--via-tag" :default "direct"]
     ["-t" "--to-tag" :default "forward"]
     ["-T" "--timeout" :type float :default 3.0]])

  (defn/a fetch-1 [self fetcher oubs]
    (let [#(group url) #((get fetcher "group") (get fetcher "url"))
          via-oub (choice (lfor oub (get self.conf.oubs self.args.via-tag) :if oub.enabled oub))]
      (log-info "fetch %s %s via %s" group url via-oub.name)
      (try
        (setv #(_ data) (await (async-curl [url] via-oub :timeout self.args.timeout)))
        (except [e Exception]
          (log-info-exc "except while fetching %s %s via %s: [%s]%s" group url via-oub.name (type e) e)
          (return)))
      (try
        (+= oubs (.parse (V2rayNParser group) data))
        (except [e Exception]
          (log-info-exc "except while parsing data: [%s]%s" (type e) e)))))

  (defn/a arun [self]
    (let [oubs (list)]
      (for [fetcher (get self.extra "fetchers" self.args.to-tag)]
        (await (.fetch-1 self fetcher oubs)))
      (setv (get self.conf.oubs self.args.to-tag) oubs))
    (.save self)))

(export
  :objects [])

(defmain []
  (let [args (parse-args [["-i" "--input" :default "subscribe"]])
        data (with [f (open args.input "rb")] (.read f))]
    (for [url (.split (decode-v2rayn-data data) "\r\n")]
      (when url
        (print (ebranch (.startswith url it)
                        "vmess://"  (+ "vmess://" (decode-vmess-data (.removeprefix url "vmess://")))
                        "trojan://" url))))))
