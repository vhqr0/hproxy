(require
  hiolib.rule :readers * *)

(import
  argparse
  asyncio
  logging
  traceback [format-exc]
  typing [Any Optional]
  pydantic [BaseModel]
  yaml
  hiolib.rule *
  hproxy.iob *)

(setv debug False)

(setv logger (logging.getLogger "hproxy"))

(defn log-info [#* args]
  (.info logger #* args))

(defn log-info-exc [#* args]
  (log-info #* args)
  (when debug
    (print (format-exc))))



(defclass CliConf [BaseModel]
  #^ INBConf                         inb
  #^ (of dict str (of list OUBConf)) oubs
  #^ (of dict str str)               tags
  #^ (of Optional (of dict str Any)) extra)

(defclass Cli []
  (setv command-dict (dict))

  (setv args-spec [["-d" "--debug" :action "store_true" :default False]
                   ["-c" "--conf-path" :default "config.yaml"]
                   ["command"]
                   ["command_args" :nargs argparse.REMAINDER]])

  (defn log-config [self]
    (logging.basicConfig
      :level   "INFO"
      :format  "%(asctime)s %(name)s %(levelname)s %(message)s"
      :datefmt "%H:%M"))

  (defn run [self [args None]]
    (global debug)
    (let [args (parse-args self.args-spec args)]
      (setv debug args.debug)
      (let [command ((get self.command-dict args.command)
                      :path args.conf-path
                      :args args.command-args)]
        (try
          (.run command)
          (except [e Exception]
            (log-info-exc "except while running %s: [%s]%s" command.command (type e) e))
          (except [KeyboardInterrupt]
            (log-info "keyboard quit")))))))

(defclass Command []
  (setv command None)

  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (when cls.command
      (setv (get Cli.command-dict cls.command) cls)))

  (defn #-- init [self path args]
    (setv self.path path)
    (.load self)                ; load conf first, then get args spec
    (setv self.args (parse-args self.args-spec args)))

  (defn [property] args-spec [self]
    (list))

  (defn [property] extra [self]
    (or self.conf.extra (dict)))

  (defn load [self]
    (setv self.conf (CliConf.model-validate
                      (with [f (open self.path)]
                        (yaml.load f :Loader yaml.CLoader)))))

  (defn save [self]
    (with [f (open self.path "w")]
      (yaml.dump (.model-dump self.conf) f :Dumper yaml.CDumper :sort-keys False)))

  (defn/a arun [self]
    (raise NotImplementedError))

  (defn run [self]
    (asyncio.run (.arun self))))

(export
  :objects [debug log-info log-info-exc CliConf Cli Command])
