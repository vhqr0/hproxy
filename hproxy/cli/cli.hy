(require
  hiolib.rule :readers * *)

(import
  argparse
  typing [Any Optional]
  pydantic [BaseModel]
  yaml
  hiolib.rule *
  hproxy.debug :as debug
  hproxy.iob *)

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

  (defn run [self [args None]]
    (let [args (parse-args self.args-spec args)]
      (setv debug.debug args.debug)
      (let [command ((get self.command-dict args.command) :path args.conf-path)
            command-args (parse-args command.args-spec args.command-args)]
        (.run command command-args)))))

(defclass Command []
  (setv command None)

  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (when cls.command
      (setv (get Cli.command-dict cls.command) cls)))

  (defn #-- init [self path]
    (setv self.path path)
    (.load self))

  (defn [property] server [self]
    (Server self.conf))

  (defn [property] extra [self]
    (or self.conf.extra (dict)))

  (defn [property] managed-tag [self]
    (.get self.extra "managedTag" "forward"))

  (defn load [self]
    (setv self.conf (.model-validate
                      CliConf
                      (with [f (open self.path)]
                        (yaml.load f :Loader yaml.CLoader)))))

  (defn save [self]
    (with [f (open self.path "w")]
      (yaml.dump (.dict self.conf) f :Dumper yaml.CDumper :sort-keys False)))

  (defn [property] args-spec [self]
    (list))

  (defn run [self args]
    (raise NotImplementedError)))

(export
  :objects [Cli Command])
