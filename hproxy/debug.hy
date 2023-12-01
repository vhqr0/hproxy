(require
  hiolib.rule :readers * *)

(import
  logging
  logging [getLogger]
  traceback [format-exc])

(setv debug False
      logger (getLogger "hproxy"))

(defn log-config []
  (logging.basicConfig
    :level   "INFO"
    :format  "%(asctime)s %(name)s %(levelname)s %(message)s"
    :datefmt "%H:%M"))

(defn log-info [#* args]
  (.info logger #* args))

(defn log-debug [#* args]
  (when debug
    (.info logger #* args)))

(defn print-exc []
  (when debug
    (print (format-exc))))

(defn log-info-with-exc [#* args]
  (log-info #* args)
  (print-exc))

(defn log-debug-with-exc [#* args]
  (log-debug #* args)
  (print-exc))

(export
  :objects [])
