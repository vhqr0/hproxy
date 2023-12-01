(require
  hiolib.rule :readers * *)

(import
  asyncio
  urllib.parse [urlparse]
  hproxy.proto.http *
  hproxy.proto.tls13 *)

(async-defclass Pinger []
  (defn #-- init [self url]
    (setv self.url (urlparse url)))

  (defn [property] http-req [self]
    (.pack HTTPReq "GET" (or self.url.path "/") "HTTP/1.1" {"Host" self.url.hostname}))

  (async-defn unpack-http-resp [self stream]
    (async-wait (.unpack-from-stream (async-name HTTPResp) stream)))

  (defn [property] ping-func [self]
    (ecase self.url.scheme
           "tcp"   self.ping-tcp
           "http"  self.ping-http
           "https" self.ping-https))

  (async-defn ping [self oub [timeout None]]
    (if timeout
        (async-if
          (await (asyncio.wait-for (self.ping-func oub) :timeout timeout))
          (raise NotImplementedError))
        (async-wait (self.ping-func oub))))

  (async-defn ping-tcp [self oub]
    (async-with [lowest-stream (async-wait (.lowest-open-connection oub))]))

  (async-defn ping-http [self oub]
    (async-with [lowest-stream (async-wait (.lowest-open-connection oub))]
      (let [proxy-connector (.get-connector oub :host self.url.hostname :port (or self.url.port 80))
            stream (async-wait (.connect-with-head proxy-connector lowest-stream self.http-req))]
        (async-wait (.unpack-http-resp self stream)))))

  (async-defn ping-https [self oub]
    (async-with [lowest-stream (async-wait (.lowest-open-connection oub))]
      (let [proxy-connector (.get-connector oub :host self.url.hostname :port (or self.url.port 443))
            tls-connector ((async-name TLS13Connector) :host self.url.hostname :next-layer proxy-connector)
            stream (async-wait (.connect-with-head tls-connector lowest-stream self.http-req))]
        (async-wait (.unpack-http-resp self stream))))))

(export
  :objects [Pinger AsyncPinger])
