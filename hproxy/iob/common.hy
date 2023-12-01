(require
  hiolib.rule :readers * *)

(import
  asyncio
  time
  hiolib.stream *
  hproxy.iob.iob *)

(async-defclass BlockOUB [(async-name OUB)]
  (setv scheme "block")
  (async-defn connect [self host port head]
    (async-wait ((async-if asyncio.sleep time.sleep) 0.1))
    ((async-name NullStream))))

(async-defclass DirectOUB [(async-name OUB)]
  (setv scheme "direct")
  (async-defn connect [self host port head]
    (let [stream (async-wait (.open-connection (async-name TCPStream) host port))]
      (try
        (async-wait (.write stream head))
        stream
        (except [Exception]
          (async-wait (.close stream))
          (raise))))))

(export
  :objects [])
