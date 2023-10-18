(require
  hiolib.rule :readers * *)

(import
  asyncio
  random [choice]
  typing [Any Optional]
  functools [cache cached-property]
  pydantic [BaseModel]
  hiolib.stream *
  hproxy
  hproxy.http *
  hproxy.base *)

(defn/a stream-copy [from-stream to-stream]
  (let [buf (await (.read from-stream))]
    (while buf
      (await (.write to-stream buf))
      (setv buf (await (.read from-stream))))))

(defclass ServerConf [BaseModel]
  #^ INBConf                         inb
  #^ (of dict str (of list OUBConf)) oubs
  #^ (of dict str str)               tags
  #^ (of Optional (of dict str Any)) extra)

(defclass Server []
  (defn #-- init [self conf]
    (setv self.conf conf
          self.inb (AsyncINB.from-conf self.conf.inb)
          self.oubs (dfor #(tag oubs) (.items self.conf.oubs)
                          tag (lfor oub oubs :if oub.enabled (AsyncOUB.from-conf oub)))
          self.tasks (set)))

  (defn add-task [self task]
    (.add self.tasks task)
    (.add-done-callback task self.tasks.discard))

  (defn [cached-property] default-tag [self]
    (get self.conf.tags "*"))

  (defn match-tags [self host]
    (let [tag (.get self.conf.tags host)]
      (if tag
          tag
          (let [sp (.split host "." 1)]
            (if (= (len sp) 2)
                (.match-tags self (get sp 1))
                self.default-tag)))))

  (defn choice-oub [self host]
    (choice (get self.oubs (.match-tags self host))))

  (defn/a serve-callback [self lowest-stream]
    (.add-task self (asyncio.current-task))
    (with/a [_ lowest-stream]
      (try
        (setv #(inb-stream host port) (await (.accept self.inb lowest-stream))
              head (await (.read inb-stream)))
        (unless head
          (raise StreamEOFError))
        (except [e Exception]
          (hproxy.log-info "except while accepting: [%s]%.60s" (type e) e)
          (hproxy.print-exc)
          (return)))
      (setv oub (.choice-oub self host))
      (hproxy.log-info "connect to %s %d via %s" host port oub.conf.name)
      (try
        (setv oub-stream (await (.connect oub host port head)))
        (except [e Exception]
          (hproxy.log-info "except while connecting to %s %d via %s: [%s]%.60s"
                 host port oub.conf.name (type e) e)
          (hproxy.print-exc)
          (return)))
      (with/a [_ oub-stream]
        (let [tasks #((asyncio.create-task (stream-copy inb-stream oub-stream))
                       (asyncio.create-task (stream-copy oub-stream inb-stream)))]
          (ap-each tasks
                   (.add-task self it))
          (try
            (await (asyncio.gather #* tasks))
            (except [Exception]))
          (ap-each tasks
                   (.cancel it))))))

  (defn/a serve-forever [self]
    (try
      (with/a [server (await (.lowest-start-server self.inb self.serve-callback))]
        (let [addrs (lfor sock server.sockets
                          :setv #(host port) (.getsockname sock)
                          (http-pack-addr host port))]
          (hproxy.log-info "server start at %s" (.join "," addrs)))
        (await (.serve-forever server)))
      (except [e Exception]
        (hproxy.log-info "except while serving: [%s]%s" (type e) e)
        (hproxy.print-exc)))))

(export
  :objects [ServerConf Server])
