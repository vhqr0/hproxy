(require
  hyrule :readers * *)

(import
  json
  base64
  hyrule *)

(defmain []
  (let [args (parse-args [["-i" "--input" :default "subscribe"]])
        data (with [f (open args.input "rb")] (.read f))
        urls (.split (base64.decodebytes data) b"\r\n")]
    (for [url urls]
      (when url
        (let [#(scheme data) (.split (.decode url) "://" 1)]
          (print
            (ecase scheme
                   "vmess"  (.format "{}://{}" scheme (json.loads (.decode (base64.decodebytes (.encode data)))))
                   "trojan" (.format "{}://{}" scheme data))))))))
