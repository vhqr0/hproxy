(require
  hiolib.rule :readers * *)

(import
  sys
  yaml
  hproxy.cli.cli *)

(setv skeleton
      {"inb"   {"scheme"   "auto"
                "host"     "localhost"
                "port"     1080
                "tls"      None
                "ws"       None
                "extra"    None}

       "oubs"  {"block"   [{"managed"   False
                            "enabled"   True
                            "name"      "block"
                            "group"     "block"
                            "dnsname"   ""
                            "delay"     0.0
                            "scheme"    "block"
                            "host"      ""
                            "port"      0
                            "tls"       None
                            "ws"        None
                            "extra"     None}]

                "direct"  [{"managed"   False
                            "enabled"   True
                            "name"      "direct"
                            "group"     "direct"
                            "dnsname"   ""
                            "delay"     0.0
                            "scheme"    "direct"
                            "host"      ""
                            "port"      0
                            "tls"       None
                            "ws"        None
                            "extra"     None}]

                "forward" []}

       "tags"  {"*" "direct" "add.your.tags.here" "..."}

       "extra" {"fetchers" {"forward" [{"group" "sub1" "url" "https://your-subscribe-url1/"}
                                       {"group" "sub2" "url" "https://your-subscribe-url2/"}]}}})

(defmain []
  (let [conf (CliConf.model-validate skeleton)]
    (yaml.dump (.model-dump conf) sys.stdout :Dumper yaml.CDumper :sort-keys False)))
