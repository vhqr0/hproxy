(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  random [randbytes]
  cryptography.hazmat.primitives.hashes [Hash SHA256]
  cryptography.hazmat.primitives.hmac [HMAC]
  cryptography.hazmat.primitives.kdf.hkdf [HKDFExpand]
  cryptography.hazmat.primitives.ciphers.aead [AESGCM]
  cryptography.hazmat.primitives.asymmetric.x25519 [X25519PrivateKey X25519PublicKey]
  hiolib.struct *
  hproxy.proto.tls13.struct *)

(defstruct HkdfLabel
  [[int length :len 2]
   [varlen label
    :len 1
    :from (+ b"tls13 " it)
    :to (.removeprefix b"tls13 " it)]
   [varlen context :len 1]])

(defclass Cryptor []
  (defn #-- init [self crypt-ctx secret]
    (setv self.crypt-ctx crypt-ctx)
    (let [key (.hkdf-expand-label self.crypt-ctx secret b"key" b"" self.crypt-ctx.aead-key-size)
          iv (.hkdf-expand-label self.crypt-ctx secret b"iv" b"" self.crypt-ctx.aead-iv-size)]
      (setv self.aead (self.crypt-ctx.aead-algorithm key)
            self.iv iv
            self.sequence 0)))

  (defn next-iv [self]
    (let [iv (bytes (gfor #(c1 c2) (zip self.iv (int-pack self.sequence self.crypt-ctx.aead-iv-size)) (^ c1 c2)))]
      (+= self.sequence 1)
      iv))

  (defn encrypt [self plaintext aad]
    (.encrypt self.aead (.next-iv self) plaintext aad))

  (defn decrypt [self ciphertext aad]
    (.decrypt self.aead (.next-iv self) ciphertext aad))

  (defn encrypt-record [self type content]
    (let [inner-plaintext (.pack TLSInnerPlaintext content type 0)
          header (.pack TLSCiphertextHeader ContentType.application-data ProtocolVersion.TLS12 (+ (len inner-plaintext) self.crypt-ctx.aead-tag-size))
          encrypted-record (.encrypt self inner-plaintext header)]
      (+ header encrypted-record)))

  (defn decrypt-record [self encrypted-record]
    (let [header (.pack TLSCiphertextHeader ContentType.application-data ProtocolVersion.TLS12 (len encrypted-record))
          inner-plaintext (.decrypt self encrypted-record header)
          #(content type zeros) (.unpack TLSInnerPlaintext inner-plaintext)]
      #(type content))))

(defclass DefaultCryptCtx []
  (setv cipher-suite CipherSuite.TLS-AES-128-GCM-SHA256
        named-group NamedGroup.x25519)

  (setv hash-algorithm (SHA256)
        hash-block-size 64
        hash-digest-size 32)

  (setv aead-algorithm AESGCM
        aead-key-size 16
        aead-iv-size 12
        aead-tag-size 16)

  (setv dhe-private-key X25519PrivateKey
        dhe-public-key X25519PublicKey)

  (defn #-- init [self]
    (setv self.client-random (randbytes 32)
          self.client-private-key (.generate self.dhe-private-key)))

  (defn [property] client-share [self]
    (-> self.client-private-key
        (.public-key)
        (.public-bytes-raw)))

  (defn exchange [self server-share]
    (.exchange self.client-private-key (.from-public-bytes self.dhe-public-key server-share)))

  ;; handshake messages: client hello ... server hello
  (defn recv-server-hello [self server-random server-share handshake-messages]
    (setv self.server-random server-random
          self.shared-secret (.exchange self server-share)
          self.early-secret (.hkdf-extract self (bytes self.hash-digest-size) (bytes self.hash-digest-size))
          self.handshake-secret (.hkdf-extract self (.hkdf-derive-secret self self.early-secret b"derived" b"") self.shared-secret)
          self.client-handshake-secret (.hkdf-derive-secret self self.handshake-secret b"c hs traffic" handshake-messages)
          self.server-handshake-secret (.hkdf-derive-secret self self.handshake-secret b"s hs traffic" handshake-messages)
          self.client-handshake-encryptor (Cryptor self self.client-handshake-secret)
          self.server-handshake-decryptor (Cryptor self self.server-handshake-secret)
          self.master-secret (.hkdf-extract self (.hkdf-derive-secret self self.handshake-secret b"derived" b"") (bytes self.hash-digest-size))))

  ;; handshake messages: client hello ... server finished
  (defn client-verify-data [self handshake-messages]
    (let [key (.hkdf-expand-label self self.client-handshake-secret b"finished" b"" self.hash-digest-size)]
      (.hmac self key (.hash self handshake-messages))))

  ;; handshake messages: client hello ... server certificate verify
  (defn server-verify-data [self handshake-messages]
    (let [key (.hkdf-expand-label self self.server-handshake-secret b"finished" b"" self.hash-digest-size)]
      (.hmac self key (.hash self handshake-messages))))

  ;; handshake messages: client hello ... server finished
  (defn recv-server-finished [self handshake-messages]
    (setv self.client-application-secret (.hkdf-derive-secret self self.master-secret b"c ap traffic" handshake-messages)
          self.server-application-secret (.hkdf-derive-secret self self.master-secret b"s ap traffic" handshake-messages)
          self.client-application-encryptor (Cryptor self self.client-application-secret)
          self.server-application-decryptor (Cryptor self self.server-application-secret)))

  (defn hash [self data]
    (let [h (Hash self.hash-algorithm)]
      (.update h data)
      (.finalize h)))

  (defn hmac [self key data]
    (let [h (HMAC key self.hash-algorithm)]
      (.update h data)
      (.finalize h)))

  (defn hkdf-extract [self salt ikm]
    (.hmac self salt ikm))

  (defn hkdf-expand [self prk info length]
    (-> (HKDFExpand self.hash-algorithm length info)
        (.derive prk)))

  (defn hkdf-expand-label [self secret label context length]
    (.hkdf-expand self secret (.pack HkdfLabel length label context) length))

  (defn hkdf-derive-secret [self secret label messages]
    (.hkdf-expand-label self secret label (.hash self messages) self.hash-digest-size)))

(export
  :objects [DefaultCryptCtx])

(defmain []
  (let [ctx (DefaultCryptCtx)]
    (defn hkdf [salt ikm info length]
      (let [prk (ctx.hkdf-extract salt ikm)]
        (ctx.hkdf-expand prk info length)))
    (assert (= (hkdf :salt   (bytes.fromhex "000102030405060708090a0b0c")
                     :ikm    (bytes.fromhex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
                     :info   (bytes.fromhex "f0f1f2f3f4f5f6f7f8f9")
                     :length 42)
               (bytes.fromhex "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")))))
