(require
  hiolib.rule :readers * *)

(import
  argparse
  json
  concurrent.futures [ThreadPoolExecutor]
  hiolib.rule *
  hproxy.util *
  hproxy.server *)

(defn do-run [conf debug]
  (let [server (Server conf debug)]
    (try
      (asyncio.run ((fn/a [] (await (.serve-forever server)))))
      (except [KeyboardInterrupt]
        (print "keyboard quit")))))

(defmacro for-each-oub [#* body]
  `(with [executor (ThreadPoolExecutor)]
     (.map executor
           (fn [it] ~@body)
           (gfor oub (get conf.oubs tag) :if oub.managed oub))))

(defn do-dig4 [conf tag url debug]
  (for-each-oub
    (try
      (dig4 it url)
      (except [e Exception]
        (print it.group it.name (type e) e)
        (when debug (raise)))
      (else
        (print it.group it.name it.host)))))

(defn do-dig6 [conf tag url debug]
  (for-each-oub
    (try
      (dig6 it url)
      (except [e Exception]
        (print it.group it.name (type e) e)
        (when debug (raise)))
      (else
        (print it.group it.name it.host)))))

(defn do-ping [conf tag url debug]
  (for-each-oub
    (try
      (ping it url)
      (except [e Exception]
        (print it.group it.name (type e) e)
        (when debug (raise)))
      (else
        (print it.group it.name it.delay)))))

(defn main [[args None]]
  (let [args (parse-args [["-d" "--debug" :action "store_true" :default False]
                          ["-c" "--conf-file" :default "config.json"]
                          ["command"]
                          ["command_args" :nargs argparse.REMAINDER :default (list)]]
                         args)
        debug args.debug
        conf-file args.conf-file
        conf (.model-validate ServerConf (with [f (open conf-file)] (json.load f)))]
    (ecase args.command
           "run"  (do-run conf debug)
           "dig4" (let [args (parse-args [["-t" "--tag" :default (.get conf.extra "managedtag" "forward")]
                                          ["-u" "--url" :default (.get conf.extra "dig4url" "udp://8.8.8.8")]]
                                         args.command-args)]
                    (do-dig4 conf args.tag args.url)
                    (with [f (open conf-file "w")] (json.dump (.dict conf) f)))
           "dig6" (let [args (parse-args [["-t" "--tag" :default (.get conf.extra "managedtag" "forward")]
                                          ["-u" "--url" :default (.get conf.extra "dig6url" "udp://2001:4860:4860::8888")]]
                                         args.command-args)]
                    (do-dig6 conf args.tag args.url debug)
                    (with [f (open conf-file "w")] (json.dump (.dict conf) f)))
           "ping" (let [args (parse-args [["-t" "--tag" :default (.get conf.extra "managedtag" "forward")]
                                          ["-u" "--url" :default (.get conf.extra "pingurl" "http://www.google.com")]]
                                         args.command-args)]
                    (do-ping conf args.tag args.url debug)
                    (with [f (open conf-file "w")] (json.dump (.dict conf) f))))))

(export
  :objects [main])
