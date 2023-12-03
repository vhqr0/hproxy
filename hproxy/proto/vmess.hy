;; Homepage:                             https://www.v2fly.org
;; Legacy CN (outdated):                 https://github.com/v2fly/v2fly-github-io/blob/master/docs/developer/protocols/vmess.md
;; Legacy EN (outdated than the former): https://github.com/v2fly/v2fly-github-io/blob/master/docs/en_US/developer/protocols/vmess.md
;; AEAD CN (partial):                    https://github.com/v2fly/v2fly-github-io/issues/20/

(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  time
  random [randbytes getrandbits]
  functools [cached-property]
  uuid [UUID]
  zlib [crc32]
  hashlib [md5 sha256]
  Crypto.Hash.SHAKE128 [SHAKE128-XOF]
  cryptography.hazmat.primitives.ciphers [Cipher]
  cryptography.hazmat.primitives.ciphers.algorithms [AES]
  cryptography.hazmat.primitives.ciphers.modes [ECB]
  cryptography.hazmat.primitives.ciphers.aead [AESGCM]
  hiolib.struct *
  hiolib.stream *
  hproxy.proto.base *

  ;;; legacy
  ;; hmac [HMAC]
  ;; cryptography.hazmat.primitives.ciphers.modes [CFB]
  )

(setv VMESS-MAGIC        b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
      VMESS-KDF          b"VMess AEAD KDF"
      VMESS-AID          b"AES Auth ID Encryption"
      VMESS-REQ-LEN-KEY  b"VMess Header AEAD Key_Length"
      VMESS-REQ-LEN-IV   b"VMess Header AEAD Nonce_Length"
      VMESS-REQ-KEY      b"VMess Header AEAD Key"
      VMESS-REQ-IV       b"VMess Header AEAD Nonce"
      VMESS-RESP-LEN-KEY b"AEAD Resp Header Len Key"
      VMESS-RESP-LEN-IV  b"AEAD Resp Header Len IV"
      VMESS-RESP-KEY     b"AEAD Resp Header Key"
      VMESS-RESP-IV      b"AEAD Resp Header IV")



(defn hmac2hash [key block-size digest-size hash-func]
  (when (> (len key) block-size)
    (setv key (hash-func key)))
  (setv ikey (lfor _ (range block-size) 0x36)
        okey (lfor _ (range block-size) 0x5c))
  (for [#(i c) (enumerate key)]
    (^= (get ikey i) c)
    (^= (get okey i) c))
  (setv ikey (bytes ikey)
        okey (bytes okey))
  #(block-size
     digest-size
     (fn [data]
       (hash-func
         (+ okey (hash-func (+ ikey data)))))))

(let [okdf-1 (hmac2hash VMESS-KDF 64 32 (fn [data] (.digest (sha256 data))))]
  (defn vmess-kdf [key #* path]
    (let [okdf okdf-1]
      (for [p path]
        (setv okdf (hmac2hash p #* okdf)))
      ((get okdf 2) key))))

(defn fnv1a [buf]
  (let [r 0x811c9dc5
        p 0x01000193
        m 0xffffffff]
    (for [c buf]
      (setv r (& (* (^ c r) p) m)))
    (int-pack r 4)))



(defstruct VMessReq
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

(defstruct VMessResp
  [[int v :len 1]
   [int opt :len 1 :to-validate (= it 0)]
   [int cmd :len 1 :to-validate (= it 0)]
   [int mlen :len 1 :to-validate (= it 0)]])



(defclass VMessID [UUID]
  (defn [cached-property] cmd-key [self]
    (.digest (md5 (+ self.bytes VMESS-MAGIC))))

  (defn [cached-property] aid-key [self]
    (cut (vmess-kdf self.cmd-key VMESS-AID) 16))

;;; legacy
  ;; (defn encrypt-req [self req]
  ;;   (let [ts (int-pack (int (time.time)) 8)
  ;;         auth (.digest (HMAC :key self.bytes :msg ts :digestmod md5))
  ;;         iv (.digest (md5 (* 4 ts)))
  ;;         ereq (-> (Cipher (AES self.cmd-key) (CFB iv))
  ;;                  (.encryptor)
  ;;                  (.update req))]
  ;;     (+ auth ereq)))

  (defn encrypt-req [self req]
    (let [aid (+ (int-pack (int (time.time)) 8) (randbytes 4))
          aid (+ aid (int-pack (crc32 aid) 4))
          eaid (-> (Cipher (AES self.aid-key) (ECB))
                   (.encryptor)
                   (.update aid))
          nonce (randbytes 8)
          elen (-> (AESGCM (cut (vmess-kdf self.cmd-key VMESS-REQ-LEN-KEY eaid nonce) 16))
                   (.encrypt (cut (vmess-kdf self.cmd-key VMESS-REQ-LEN-IV eaid nonce) 12) (int-pack (len req) 2) eaid))
          ereq (-> (AESGCM (cut (vmess-kdf self.cmd-key VMESS-REQ-KEY eaid nonce) 16))
                   (.encrypt (cut (vmess-kdf self.cmd-key VMESS-REQ-IV eaid nonce) 12) req eaid))]
      (+ eaid elen nonce ereq))))



(defclass VMessCryptor []
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

  (defn decrypt-len [self eblen]
    (.mask-len self (int-unpack eblen)))

  (defn encrypt [self buf]
    (.encrypt self.aead (.next-iv self) buf b""))

  (defn decrypt [self buf]
    (.decrypt self.aead (.next-iv self) buf b""))

  (defn encrypt-with-len [self buf]
    (let [ebuf (.encrypt self buf)
          eblen (.encrypt-len self (len ebuf))]
      (+ eblen ebuf))))



(async-defclass VMessStream [(async-name Stream)]
  (defn #-- init [self write-encryptor read-decryptor #** kwargs]
    (#super-- init #** kwargs)
    (setv self.write-encryptor write-encryptor
          self.read-decryptor read-decryptor))

  (async-defn write1 [self buf]
    (async-wait (.write self.next-layer (.encrypt-with-len self.write-encryptor buf))))

  (async-defn read1 [self]
    (let [eblen (async-wait (.read-exactly self.next-layer 2))
          blen (.decrypt-len self.read-decryptor eblen)
          ebuf (async-wait (.read-exactly self.next-layer blen))]
      (.decrypt self.read-decryptor ebuf))))

(async-defclass VMessConnector [(async-name ProxyConnector)]
  (defn #-- init [self id #** kwargs]
    (#super-- init #** kwargs)
    (setv self.id id
          self.key (randbytes 16)
          self.iv (randbytes 16)
          ;;; legacy
          ;; self.rkey (.digest (md5 self.key))
          ;; self.riv (.digest (md5 self.iv))
          self.rkey (cut (.digest (sha256 self.key)) 16)
          self.riv (cut (.digest (sha256 self.iv)) 16)
          self.v (getrandbits 8)
          self.pad (randbytes (getrandbits 4))
          self.write-encryptor (VMessCryptor :key self.key :iv self.iv)
          self.read-decryptor (VMessCryptor :key self.rkey :iv self.riv)))

  (defn get-next-head-pre-head [self]
    (let [req (.pack (async-name VMessReq)
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
          req (+ req (fnv1a req))]
      (.encrypt-req self.id req)))

  (defn get-next-head-pre-frame [self head]
    (.encrypt-with-len self.write-encryptor head))

  ;;; legacy
  ;; (async-defn connect1 [self next-stream]
  ;;   (let [eresp (async-wait (.read-exactly next-stream 4))
  ;;         resp (-> (Cipher (AES self.rkey) (CFB self.riv))
  ;;                  (.decryptor)
  ;;                  (.update eresp))
  ;;         #(v _ _ _) (.unpack VMessResp resp)]
  ;;     (unless (= v self.v)
  ;;       (raise StructValidationError))
  ;;     ((async-name VMessStream)
  ;;       :write-encryptor self.write-encryptor
  ;;       :read-decryptor self.read-decryptor
  ;;       :next-layer next-stream)))

  (async-defn connect1 [self next-stream]
    (let [elen (async-wait (.read-exactly next-stream 18))
          rlen (int-unpack (-> (AESGCM (cut (vmess-kdf self.rkey VMESS-RESP-LEN-KEY) 16))
                               (.decrypt (cut (vmess-kdf self.riv VMESS-RESP-LEN-IV) 12) elen None)))
          eresp (async-wait (.read-exactly next-stream (+ 16 rlen)))
          resp (-> (AESGCM (cut (vmess-kdf self.rkey VMESS-RESP-KEY) 16))
                   (.decrypt (cut (vmess-kdf self.riv VMESS-RESP-IV) 12) eresp None))
          #(v _ _ _) (.unpack VMessResp resp)]
      (unless (= v self.v)
        (raise StructValidationError))
      ((async-name VMessStream)
        :write-encryptor self.write-encryptor
        :read-decryptor self.read-decryptor
        :next-layer next-stream))))

(export
  :objects [VMessID VMessConnector AsyncVMessConnector])
