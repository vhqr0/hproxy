(require
  hiolib.rule :readers * *)

(import
  logging
  hproxy.cli *
  hproxy.proto.proxy *
  hproxy.proto.v2ray *)

(defmain []
  (logging.basicConfig
    :level   "INFO"
    :format  "%(asctime)s %(name)s %(levelname)s %(message)s"
    :datefmt "%H:%M")
  (.run (Cli)))
