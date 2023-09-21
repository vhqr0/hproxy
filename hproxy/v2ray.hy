;; site:          https://www.v2fly.org
;; CN:            https://github.com/v2fly/v2fly-github-io/blob/master/docs/developer/protocols/vmess.md
;; EN (outdated): https://github.com/v2fly/v2fly-github-io/blob/master/docs/en_US/developer/protocols/vmess.md
;; V2rayN:        https://github.com/2dust/v2rayN/wiki/分享链接格式说明(ver-2)

(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  time
  json
  base64
  traceback
  random [randbytes getrandbits]
  functools [cached-property]
  uuid [UUID]
  hmac [HMAC]
  hashlib [md5]
  Crypto.Hash.SHAKE128 [SHAKE128-XOF]
  cryptography.hazmat.primitives.ciphers [Cipher]
  cryptography.hazmat.primitives.ciphers.algorithms [AES]
  cryptography.hazmat.primitives.ciphers.modes [CFB]
  cryptography.hazmat.primitives.ciphers.aead [AESGCM]
  requests
  hiolib.struct *
  hiolib.stream *
  hiolib.util.proxy *
  hproxy
  hproxy.iob *)

(defn fnv32a [buf]
  (let [r 0x811c9dc5
        p 0x01000193
        m 0xffffffff]
    (for [c buf]
      (setv r (& (* (^ c r) p) m)))
    (int-pack r 4)))

(defstruct VmessReq
  [[int ver :len 1]
   [bytes iv :len 16]
   [bytes key :len 16]
   [int v :len 1]
   [int opt :len 1]
   [bits [padlen sec] :lens [4 4]]
   [int keep :len 1]
   [int cmd :len 1]
   [int port :len 2]
   [int atype :len 1]
   [varlen host :len 1 :from (.encode it) :to (.decode it)]
   [bytes pad :len p]])

(defstruct VmessResp
  [[int v :len 1]
   [int opt :len 1 :to-validate (= it 0)]
   [int cmd :len 1 :to-validate (= it 0)]
   [int mlen :len 1 :to-validate (= it 0)]])

(defclass VmessID [UUID]
  (setv magic b"c48619fe-8f02-49e0-b9e9-edf763e17e21")

  (defn get-auth [self ts]
    (.digest (HMAC :key self.bytes :msg ts :digestmod md5)))

  (defn [cached-property] req-key [self]
    (.digest (md5 (+ self.bytes self.magic))))

  (defn [staticmethod] get-req-iv [ts]
    (.digest (md5 (* 4 ts)))))

(defclass VmessCryptor []
  (defn #-- init [self key iv [count 0]]
    (setv self.shake (SHAKE128-XOF iv)
          self.aead (AESGCM key)
          self.iv (cut iv 2 12)
          self.count count))

  (defn mask-len [self i]
    (let [mask (int-unpack (.read self.shake 2))]
      (^ i mask)))

  (defn next-iv [self]
    (let [iv (+ (int-pack self.count 2) self.iv)]
      (+= self.count 1)
      iv))

  (defn encrypt-len [self blen]
    (int-pack (.mask-len self blen) 2))

  (defn decrypt-len [self enc-blen]
    (.mask-len self (int-unpack enc-blen)))

  (defn encrypt [self buf]
    (.encrypt self.aead (.next-iv self) buf b""))

  (defn decrypt [self buf]
    (.decrypt self.aead (.next-iv self) buf b""))

  (defn encrypt-with-len [self buf]
    (let [enc-buf (.encrypt self buf)
          enc-blen (.encrypt-len self (len enc-buf))]
      (+ enc-blen enc-buf))))

(async-defclass VmessStream [(async-name Stream)]
  (defn #-- init [self write-encryptor read-decryptor #** kwargs]
    (#super-- init #** kwargs)
    (setv self.write-encryptor write-encryptor
          self.read-decryptor read-decryptor))

  (async-defn write1 [self buf]
    (async-wait (.write self.next-layer (.encrypt-with-len self.write-encryptor buf))))

  (async-defn read1 [self]
    (let [enc-blen (async-wait (.read-exactly self.next-layer 2))
          blen (.decrypt-len self.read-decryptor enc-blen)
          enc-buf (async-wait (.read-exactly self.next-layer blen))]
      (.decrypt self.read-decryptor enc-buf))))

(async-defclass VmessConnector [(async-name ProxyConnector)]
  (defn #-- init [self id #** kwargs]
    (#super-- init #** kwargs)
    (setv self.id id
          self.key (randbytes 16)
          self.iv (randbytes 16)
          self.rkey (.digest (md5 self.key))
          self.riv (.digest (md5 self.iv))
          self.v (getrandbits 8)
          self.pad (randbytes (getrandbits 4))
          self.write-encryptor (VmessCryptor :key self.key :iv self.iv)
          self.read-decryptor (VmessCryptor :key self.rkey :iv self.riv)))

  (defn get-next-head-pre-head [self]
    (let [ts (int-pack (int (time.time)) 8)
          auth (.get-auth self.id ts)
          key self.id.req-key
          iv (.get-req-iv self.id ts)
          req (.pack (async-name VmessReq)
                     :ver    1
                     :iv     self.iv
                     :key    self.key
                     :v      self.v
                     :opt    5  ; M|S
                     :padlen (len self.pad)
                     :sec    3  ; AESGCM
                     :keep   0
                     :cmd    1  ; TCP
                     :port   self.port
                     :atype  2  ; DomainName
                     :host   self.host
                     :pad    self.pad)
          encryptor (.encryptor (Cipher (AES key) (CFB iv)))
          enc-req (.update encryptor (+ req (fnv32a req)))]
      (+ auth enc-req)))

  (defn get-next-head-pre-frame [self head]
    (.encrypt-with-len self.write-encryptor head))

  (async-defn connect1 [self next-stream]
    (let [enc-resp (async-wait (.read-exactly next-stream 4))
          decryptor (.decryptor (Cipher (AES self.rkey) (CFB self.riv)))
          resp (.update decryptor enc-resp)
          #(v _ _ _) (.unpack VmessResp resp)]
      (unless (= v self.v)
        (raise StructValidationError))
      ((async-name VmessStream)
        :write-encryptor self.write-encryptor
        :read-decryptor self.read-decryptor
        :next-layer next-stream))))

(async-defclass VmessOUB [(async-name OUB)]
  (setv scheme "vmess")

  (defn [cached-property] id [self]
    (VmessID (get self.conf.extra "id")))

  (defn get-proxy-connector [self host port]
    ((async-name VmessConnector) :host host :port port :id self.id)))

(defclass V2rayNSUB [SUB]
  (setv scheme "v2rayn")

  (defn parse-url [self url]
    (let [#(scheme data) (.split url "://" 1)]
      (unless (= scheme "vmess")
        (raise (RuntimeError (.format "invalid scheme {}" scheme))))
      (let [data (json.loads (.decode (base64.decodebytes (.encode data))))
            v    (get data "v")
            ps   (get data "ps")
            add  (get data "add")
            port (get data "port")
            id   (get data "id")
            scy  (or (.get data "scy") "auto")
            net  (or (.get data "net") "tcp")
            type (or (.get data "type") "none")
            host (or (.get data "host") add)
            path (or (.get data "path") "/")
            tls  (or (.get data "tls") "")
            sni  (or (.get data "sni") add)]
        (unless (=  v    "2")           (raise (RuntimeError (.format "invalid v {}"    v))))
        (unless (=  scy  "auto")        (raise (RuntimeError (.format "invalid scy {}"  scy))))
        (unless (in net  #("tcp" "ws")) (raise (RuntimeError (.format "invalid net {}"  net))))
        (unless (=  type "none")        (raise (RuntimeError (.format "invalid type {}" type))))
        (unless (in tls  #("" "tls"))   (raise (RuntimeError (.format "invalid tls {}"  tls))))
        (OUBConf.model-validate
          {"managed" True
           "enabled" False
           "name"    ps
           "group"   self.conf.group
           "dnsname" add
           "delay"   -1.0
           "scheme"  "vmess"
           "host"    add
           "port"    (int port)
           "tls"     (when (= tls "tls") {"host" sni "cafile" None})
           "ws"      (when (= net "ws") {"host" host "path" path})
           "extra"   {"id" id}}))))

  (defn parse [self data]
    (let [oubs (list)]
      (for [url (.split (.decode (base64.decodebytes data)) "\r\n")]
        (when url
          (try
            (when hproxy.debug
              (print (.format "parse url: {}" url)))
            (.append oubs (.parse-url self url))
            (except [e Exception]
              (print (.format "except while parsing: {}" e))
              (when hproxy.debug
                (print (traceback.format-exc)))))))
      oubs))

  (defn fetch [self]
    (let [resp (requests.get self.conf.url :timeout 3.0)]
      (unless (= resp.status-code 200)
        (.raise-for-status resp))
      (.parse self resp.content))))

(export
  :objects [])
