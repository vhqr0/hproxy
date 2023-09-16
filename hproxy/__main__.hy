(require
  hiolib.rule :readers * *)

(import
  asyncio
  json
  logging
  hiolib.rule *
  hproxy.server *)

(defmain []
  (logging.basicConfig
    :level   "INFO"
    :format  "%(asctime)s %(name)s %(levelname)s %(message)s"
    :datefmt "%H:%M")
  (let [args (parse-args [["-d" "--debug" :action "store_true" :default False]
                          ["-c" "--config-file" :default "config.json"]])
        conf (.model-validate ServerConf (with [f (open args.config-file)] (json.load f)))
        server (Server conf args.debug)]
    (try
      (asyncio.run ((fn/a [] (await (.serve-forever server)))))
      (except [e KeyboardInterrupt]
        (print "keyboard quit")))))
