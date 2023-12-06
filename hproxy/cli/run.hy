(require
  hiolib.rule :readers * *)

(import
  asyncio
  random [choices]
  functools [cached-property]
  hproxy.proto.http *
  hproxy.iob *
  hproxy.cli.cli *)

(defn/a stream-copy [from-stream to-stream]
  (let [buf (await (.read from-stream))]
    (while buf
      (await (.write to-stream buf))
      (setv buf (await (.read from-stream))))))

(defclass Server []
  (defn #-- init [self inb oubs tags [retry 3] [timeout 3.0]]
    (setv self.inb inb
          self.oubs oubs
          self.tags tags
          self.retry retry
          self.timeout timeout
          self.tasks (set)))

  (defn add-task [self task]
    (.add self.tasks task)
    (.add-done-callback task self.tasks.discard))

  (defn [cached-property] default-tag [self]
    (get self.tags "*"))

  (defn match-tags [self host]
    (let [tag (.get self.tags host)]
      (if tag
          tag
          (let [sp (.split host "." 1)]
            (if (= (len sp) 2)
                (.match-tags self (get sp 1))
                self.default-tag)))))

  (defn choice-oubs [self host]
    (let [oubs (.get self.oubs (.match-tags self host))]
      (unless oubs
        (raise KeyError))
      (if (<= (len oubs) self.retry)
          oubs
          (choices oubs :k self.retry))))

  (defn/a serve-callback [self lowest-stream]
    (.add-task self (asyncio.current-task))

    (with/a [_ lowest-stream]

      (try
        (setv #(inb-stream host port) (await (.accept self.inb lowest-stream))
              head (await (.read-atleast inb-stream 1)))
        (except [e Exception]
          (log-info-exc "except while accepting: [%s]%.60s" (type e) e)
          (return)))

      (for [oub (.choice-oubs self host)]
        (log-info "connect to %s %d via %s" host port oub.conf.name)
        (try
          (setv oub-stream (await (asyncio.wait-for (.connect oub host port head) :timeout self.timeout)))
          (break)
          (except [e Exception]
            (log-info-exc "except while connecting to %s %d via %s: [%s]%.60s"
                          host port oub.conf.name (type e) e)))
        (else
          (log-info "failed to connect to %s %d" host port)
          (return)))

      (with/a [_ oub-stream]
        (let [tasks #((asyncio.create-task (stream-copy inb-stream oub-stream))
                       (asyncio.create-task (stream-copy oub-stream inb-stream)))]
          (ap-each tasks (.add-task self it))
          (try
            (await (asyncio.gather #* tasks))
            (except [Exception]))
          (ap-each tasks (.cancel it))))))

  (defn/a serve-forever [self]
    (try
      (with/a [server (await (.lowest-start-server self.inb self.serve-callback))]
        (let [addrs (lfor sock server.sockets
                          :setv #(host port) (.getsockname sock)
                          (http-pack-addr host port))]
          (log-info "server start at %s" (.join "," addrs)))
        (await (.serve-forever server)))
      (except [e Exception]
        (log-info-exc "except while serving: [%s]%s" (type e) e)))))

(defclass Run [Command]
  (setv command "run")

  (defn [property] args-spec [self]
    [["-r" "--retry" :type int :default 3]
     ["-T" "--timeout" :type float :default 3.0]])

  (defn [property] server [self]
    (Server :inb (AsyncINB.from-conf self.conf.inb)
            :oubs (dfor #(tag oubs) (.items self.conf.oubs)
                        tag (lfor oub oubs :if oub.enabled (AsyncOUB.from-conf oub)))
            :tags self.conf.tags
            :retry self.args.retry
            :timeout self.args.timeout))

  (defn/a arun [self]
    (await (.serve-forever self.server))))

(export
  :objects [Server])
