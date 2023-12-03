(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  random [randbytes]
  cryptography.hazmat.primitives.hashes [Hash SHA256 SHA384]
  cryptography.hazmat.primitives.hmac [HMAC]
  cryptography.hazmat.primitives.kdf.hkdf [HKDFExpand]
  cryptography.hazmat.primitives.ciphers.aead [ChaCha20Poly1305 AESGCM AESCCM]
  cryptography.hazmat.primitives.asymmetric [ec]
  cryptography.hazmat.primitives.asymmetric.x25519 [X25519PrivateKey X25519PublicKey]
  cryptography.hazmat.primitives.asymmetric.x448 [X448PrivateKey X448PublicKey]
  cryptography.hazmat.primitives.serialization [Encoding PublicFormat]
  hiolib.struct *
  hproxy.proto.tls13.struct *)



(defn AESCCM8 [key]
  (AESCCM key :tag-length 8))

;;; [hash-algorithm hash-block-size hash-digest-size aead-algorithm aead-key-size aead-iv-size aead-tag-size]
(setv cipher-suite-dict
      {CipherSuite.TLS-AES-128-GCM-SHA256       [(SHA256)  64 32 AESGCM           16 12 16]
       CipherSuite.TLS-AES-256-GCM-SHA384       [(SHA384) 128 48 AESGCM           32 12 16]
       CipherSuite.TLS-CHACHA20-POLY1305-SHA256 [(SHA256)  64 32 ChaCha20Poly1305 32 12 16]
       CipherSuite.TLS-AES-128-CCM-SHA256       [(SHA256)  64 32 AESCCM           16 12 16]
       CipherSuite.TLS-AES-128-CCM-8-SHA256     [(SHA256)  64 32 AESCCM8          16 12  8]})

(defclass KeyExchanger []
  (defn generate [self]
    (raise NotImplementedError))

  (defn exchange [self pk]
    (raise NotImplementedError)))

(defclass ECKeyExchanger [KeyExchanger]
  (setv curve None algorithm (ec.ECDH))

  (defn generate [self]
    (setv self.private-key (ec.generate-private-key self.curve))
    (.public-bytes (.public-key self.private-key)
                   :encoding Encoding.X962
                   :format PublicFormat.UncompressedPoint))

  (defn exchange [self pk]
    (.exchange self.private-key self.algorithm (ec.EllipticCurvePublicKey.from-encoded-point self.curve pk))))

(defclass SECP256R1KeyExchanger [ECKeyExchanger] (setv curve (ec.SECP256R1)))
(defclass SECP384R1KeyExchanger [ECKeyExchanger] (setv curve (ec.SECP384R1)))
(defclass SECP521R1KeyExchanger [ECKeyExchanger] (setv curve (ec.SECP521R1)))

(defclass XKeyExchanger [KeyExchanger]
  (setv #(PrivateKey PublicKey) #(None None))

  (defn generate [self]
    (setv self.private-key (.generate self.PrivateKey))
    (.public-bytes-raw (.public-key self.private-key)))

  (defn exchange [self pk]
    (.exchange self.private-key (.from-public-bytes self.PublicKey pk))))

(defclass X25519KeyExchanger [XKeyExchanger] (setv #(PrivateKey PublicKey) #(X25519PrivateKey X25519PublicKey)))
(defclass X448KeyExchanger   [XKeyExchanger] (setv #(PrivateKey PublicKey) #(X448PrivateKey   X448PublicKey)))

(setv named-group-dict
      {NamedGroup.secp256r1 SECP256R1KeyExchanger
       NamedGroup.secp384r1 SECP384R1KeyExchanger
       NamedGroup.secp521r1 SECP521R1KeyExchanger
       NamedGroup.x25519    X25519KeyExchanger
       NamedGroup.x448      X448KeyExchanger})



(defstruct HkdfLabel
  [[int length :len 2]
   [varlen label
    :len 1
    :from (+ b"tls13 " it)
    :to (.removeprefix b"tls13 " it)]
   [varlen context :len 1]])

(defclass CryptCtx []
  (defn #-- init [self
                  [cipher-suites (list cipher-suite-dict)]
                  [named-groups (list named-group-dict)]]
    (setv self.client-random (randbytes 32)
          self.cipher-suites cipher-suites
          self.named-groups (dfor group named-groups group ((get named-group-dict group)))))

  (defn [property] extensions [self]
    [#(ExtensionType.supported-groups (.pack NamedGroupList (list self.named-groups)))
     #(ExtensionType.key-share (.pack KeyShareEntryList (lfor #(group ex) (.items self.named-groups) #(group (.generate ex)))))])

  ;; handshake messages: client hello ... server hello
  (defn recv-server-hello [self server-random cipher-suite extensions handshake-messages]
    (setv #(selected-group server-share) (.unpack KeyShareServerhello (get extensions ExtensionType.key-share)))

    (unless (and (in cipher-suite self.cipher-suites) (in selected-group self.named-groups))
      (raise RuntimeError))

    (setv server-random server-random)

    (let [#(hash-algorithm hash-block-size hash-digest-size aead-algorithm aead-key-size aead-iv-size aead-tag-size)
          (get cipher-suite-dict cipher-suite)]
      (setv self.hash-algorithm   hash-algorithm
            self.hash-block-size  hash-block-size
            self.hash-digest-size hash-digest-size
            self.aead-algorithm   aead-algorithm
            self.aead-key-size    aead-key-size
            self.aead-iv-size     aead-iv-size
            self.aead-tag-size    aead-tag-size))

    (setv self.shared-secret (.exchange (get self.named-groups selected-group) server-share))

    (setv self.early-secret (.hkdf-extract self (bytes self.hash-digest-size) (bytes self.hash-digest-size))
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

  (defn recv-new-session-ticket [self new-session-ticket]
    (setv self.new-session-ticket new-session-ticket))

  (defn recv-key-update [self key-update]
    ;; TODO: process KeyUpdateRequest
    (.key-update self.server-application-decryptor))

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



(defclass Cryptor []
  (defn #-- init [self crypt-ctx secret]
    (setv self.crypt-ctx crypt-ctx
          self.secret secret
          self.sequence 0)
    (.expand-key-iv self))

  (defn key-update [self]
    (let [secret (.hkdf-expand-label self.crypt-ctx self.secret b"traffic upd" b"" self.crypt-ctx.hash-digest-size)]
      (setv self.secret secret))
    (.expand-key-iv self))

  (defn expand-key-iv [self]
    (let [key (.hkdf-expand-label self.crypt-ctx self.secret b"key" b"" self.crypt-ctx.aead-key-size)
          iv (.hkdf-expand-label self.crypt-ctx self.secret b"iv" b"" self.crypt-ctx.aead-iv-size)]
      (setv self.aead (self.crypt-ctx.aead-algorithm key)
            self.iv iv)))

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

(export
  :objects [CryptCtx])
