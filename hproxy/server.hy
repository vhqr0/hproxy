(require
  hiolib.rule :readers * *)

(import
  asyncio
  random [choice]
  logging [getLogger]
  typing [Union]
  functools [cache cached-property]
  pydantic [BaseModel]
  hiolib.stream *
  hproxy.iob *)

(defn/a stream-copy [from-stream to-stream]
  (let [buf (await (.read from-stream))]
    (while buf
      (await (.write to-stream buf))
      (setv buf (await (.read from-stream))))))

(defclass ServerConf [BaseModel]
  #^ INBConf                         inb
  #^ (of dict str (of list OUBConf)) oubs
  #^ (of list (of list str))         tags
  #^ (of dict str str)               extra)

(defclass Server []
  (setv logger (getLogger "hproxy"))

  (defn #-- init [self conf [debug False]]
    (setv self.conf conf
          self.debug debug
          self.inb (AsyncINB.from-conf self.conf.inb)
          self.oubs (dfor #(tag oubs) (.items self.conf.oubs)
                          tag (lfor oub oubs :if oub.enabled (AsyncOUB.from-conf oub)))
          self.tags (dfor #(host tag) (reversed self.conf.tags) host tag)
          self.tasks (set)))

  (defn [cached-property] fallback-tag [self]
    (get self.tags "*"))

  (defn match-tags [self host]
    (let [tag (.get self.tags host)]
      (if tag
          tag
          (let [sp (.split host "." 1)]
            (if (= (len sp) 2)
                (.match-tags self (get sp 1))
                self.fallback-tag)))))

  (defn choice-oub [self host]
    (choice (get self.oubs (.match-tags self host))))

  (defn/a serve-callback [self lowest-stream]
    (with/a [_ lowest-stream]
      (try
        (setv #(inb-stream host port) (await (.accept self.inb lowest-stream))
              head (await (.read inb-stream)))
        (unless head
          (raise StreamEOFError))
        (except [e Exception]
          (.info self.logger "except while accepting: %s" e)
          (if self.debug (raise) (return))))
      (setv oub (.choice-oub self host))
      (.info self.logger "connect to %s %d via %s" host port oub.conf.name)
      (try
        (setv oub-stream (await (.connect oub host port head)))
        (except [e Exception]
          (.info self.logger "except while connecting to %s %d via %s: %s"
                 host port oub.conf.name e)
          (if self.debug (raise) (return))))
      (with/a [_ oub-stream]
        (let [tasks #((asyncio.create-task (stream-copy inb-stream oub-stream))
                       (asyncio.create-task (stream-copy oub-stream inb-stream)))]
          (ap-each tasks
                   (.add self.tasks it)
                   (.add-done-callback it self.tasks.discard))
          (try
            (await (asyncio.gather #* tasks))
            (except [Exception]))
          (ap-each tasks
                   (.cancel it))))))

  (defn/a serve-forever [self]
    (try
      (with/a [server (await (.lowest-start-server self.inb self.serve-callback))]
        (await (.serve-forever server)))
      (except [e Exception]
        (.info self.logger "except while serving: %s" e)
        (if self.debug (raise) (return))))))

(export
  :objects [ServerConf Server])
