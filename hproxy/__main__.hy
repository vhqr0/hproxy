(require
  hiolib.rule *)

(import
  logging
  hproxy.vmess *
  hproxy.main *)

(defmain []
  (logging.basicConfig
    :level   "INFO"
    :format  "%(asctime)s %(name)s %(levelname)s %(message)s"
    :datefmt "%H:%M")
  (main))
