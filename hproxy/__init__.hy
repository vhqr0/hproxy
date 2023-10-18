(require
  hiolib.rule :readers * *)

(import
  logging
  traceback)

(setv debug False
      logger (logging.getLogger "hproxy"))

(defn log-info [#* args]
  (.info logger #* args))

(defn log-debug [#* args]
  (when debug
    (.info logger #* args)))

(defn print-exc []
  (when debug
    (print (traceback.format-exc))))

(export
  :objects [])
