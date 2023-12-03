(require
  hiolib.rule :readers * *)

(import
  hproxy.cli *)

(defmain []
  (doto (Cli)
        (.log-config)
        (.run)))
