(require
  hiolib.rule :readers * *)

(import
  hproxy.debug :as debug
  hproxy.cli *)

(defmain []
  (debug.log-config)
  (.run (Cli)))
