#!/usr/bin/env hy

(require
  hyrule :readers * *)

(import
  hyrule *
  dns.message
  dns.query)

(defmain []
  (let [args (parse-args [["-s" "--server"]
                          ["-t" "--type" :default "A"]
                          ["-v" "--via" :default "udp"]
                          ["name"]])
        msg ((ecase args.via
                    "udp"   dns.query.udp
                    "tcp"   dns.query.tcp
                    "tls"   dns.query.tls
                    "https" dns.query.https)
              (dns.message.make-query args.name args.type)
             args.server)]
    (print (.to-text msg))))
