(require
  hiolib.rule :readers * *)

(import
  hiolib.stream *
  hproxy.proto.tls13.struct *
  hproxy.proto.tls13.crypt *
  hproxy.proto.tls13.cert *)

(setv CHANGE-CIPHER-SPEC (.pack TLSPlainText ContentType.change-cipher-spec ProtocolVersion.TLS12 b"\x01"))

(async-defclass TLS13Stream [(async-name Stream)]
  (defn #-- init [self crypt-ctx #** kwargs]
    (#super-- init #** kwargs)
    (setv self.crypt-ctx crypt-ctx))

  (async-defn write1 [self buf]
    (async-wait (.write self.next-layer (.encrypt-record self.crypt-ctx.client-application-encryptor ContentType.application-data buf))))

  (async-defn read1 [self]
    (while True
      (let [#(opaque-type legacy-record-version encrypted-record) (async-wait (.unpack-from-stream (async-name TLSCiphertext) self.next-layer))
            #(type content) (.decrypt-record self.crypt-ctx.server-application-decryptor encrypted-record)]
        (ecase type
               ContentType.application-data (return content)
               ContentType.alert (let [#(level description) (.unpack Alert content)]
                                   (when (and (= level AlertLevel.warning) (= description AlertDescription.close-notify))
                                     (return b""))
                                   (raise (RuntimeError description.name)))
               ContentType.handshake (let [#(msg-type msg-data) (.unpack Handshake content)]
                                       (ecase msg-type
                                              HandshakeType.new-session-ticket (.recv-new-session-ticket self.crypt-ctx msg-data)
                                              HandshakeType.key-update         (.recv-key-update         self.crypt-ctx msg-data))))))))

(async-defclass TLS13Connector [(async-name Connector)]
  (defn #-- init [self host [crypt-ctx None] [cert-ctx None] #** kwargs]
    (#super-- init #** kwargs)
    (setv self.host host
          self.crypt-ctx (or crypt-ctx (CryptCtx))
          self.cert-ctx (or cert-ctx (CertCtx))))

  (defn get-next-head [self head]
    ;; save head and send it after handshake
    (setv self.head head)
    (let [extensions [#(ExtensionType.supported-versions (.pack ProtocolVersionList [ProtocolVersion.TLS13]))
                      #* self.crypt-ctx.extensions
                      #* self.cert-ctx.extensions
                      #(ExtensionType.server-name (.pack ServerNameHostList  [#(NameType.host-name self.host)]))]
          client-hello (.pack Handshake
                              HandshakeType.client-hello
                              (.pack ClientHello
                                     :legacy-version ProtocolVersion.TLS12
                                     :random self.crypt-ctx.client-random
                                     :legacy-session-id b""
                                     :cipher-suites self.crypt-ctx.cipher-suites
                                     :legacy-compression-methods [CompressionMethod.null]
                                     :extensions extensions))]

      ;; start recording handshake messages
      (setv self.handshake-messages client-hello)
      (.pack TLSPlainText
             :type ContentType.handshake
             :legacy-record-version ProtocolVersion.TLS12
             :fragment client-hello)))

  (async-defn read-handshake-ciphertext [self next-stream]
    (let [#(opaque-type legacy-version encrypted-record) (async-wait (.unpack-from-stream (async-name TLSCiphertext) next-stream))
          #(type content) (.decrypt-record self.crypt-ctx.server-handshake-decryptor encrypted-record)]
      (unless (= type ContentType.handshake)
        (raise StructValidationError))
      (BIOStream content)))

  (async-defn connect1 [self next-stream]
    ;; read server hello
    (let [#(type legacy-version server-hello) (async-wait (.unpack-from-stream (async-name TLSPlainText) next-stream))]
      (unless (= type ContentType.handshake)
        (raise StructValidationError))
      (let [#(msg-type msg-data) (.unpack Handshake server-hello)]
        (unless (= msg-type HandshakeType.server-hello)
          (raise StructValidationError))
        (let [#(legacy-version server-random legacy-session-id-echo cipher-suite legacy-compression-method extensions) (.unpack ServerHello msg-data)
              extensions (dict extensions)
              #(selected-version) (.unpack SupportedVersionsServerHello (get extensions ExtensionType.supported-versions))
              #(selected-group server-share) (.unpack KeyShareServerhello (get extensions ExtensionType.key-share))]
          (unless (and (= legacy-session-id-echo b"")
                       (= selected-version ProtocolVersion.TLS13))
            (raise StructValidationError))
          ;; client hello ... server hello
          (+= self.handshake-messages server-hello)
          ;; initial handshake secrets
          ;; handshake messages: client hello ... server hello
          (.recv-server-hello self.crypt-ctx server-random cipher-suite extensions self.handshake-messages))))

    ;; strip change cipher spec
    (let [buf (async-wait (.peek-atleast next-stream (len CHANGE-CIPHER-SPEC)))]
      (when (.startswith buf CHANGE-CIPHER-SPEC)
        (setv next-stream.read-buf (cut buf (len CHANGE-CIPHER-SPEC) None))))

    ;; stream that contains one or more handshake messages
    (setv handshake-stream (async-wait (.read-handshake-ciphertext self next-stream)))

    ;; read encrypted extensions
    (let [#(msg-type msg-data) (.unpack-from-stream Handshake handshake-stream)]
      (unless (= msg-type HandshakeType.encrypted-extensions)
        (raise StructValidationError))
      ;; client hello ... encrypted extensions
      (+= self.handshake-messages (.pack Handshake msg-type msg-data)))

    ;; refresh handshake-stream
    (unless (.peek handshake-stream)
      (setv handshake-stream (async-wait (.read-handshake-ciphertext self next-stream))))

    ;; read certificate
    (let [#(msg-type msg-data) (.unpack-from-stream Handshake handshake-stream)]
      (unless (= msg-type HandshakeType.certificate)
        (raise StructValidationError))
      ;; client hello ... server certificate
      (+= self.handshake-messages (.pack Handshake msg-type msg-data))
      ;; certificate verify data: client hello ... server certificate
      (.recv-server-certificate self.cert-ctx msg-data self.handshake-messages))

    ;; refresh handshake-stream
    (unless (.peek handshake-stream)
      (setv handshake-stream (async-wait (.read-handshake-ciphertext self next-stream))))

    ;; read certificate verify
    (let [#(msg-type msg-data) (.unpack-from-stream Handshake handshake-stream)]
      (unless (= msg-type HandshakeType.certificate-verify)
        (raise StructValidationError))
      ;; client hello ... server certificate verify
      (+= self.handshake-messages (.pack Handshake msg-type msg-data))
      (.recv-server-certificate-verify self.cert-ctx msg-data))

    ;; verify certificate and certificate verify
    (unless (.verify self.cert-ctx)
      (raise RuntimeError))

    ;; refresh handshake-stream
    (unless (.peek handshake-stream)
      (setv handshake-stream (async-wait (.read-handshake-ciphertext self next-stream))))

    ;; read finished
    (let [#(msg-type msg-data) (.unpack-from-stream Handshake handshake-stream)]
      (unless (and (= msg-type HandshakeType.finished)
                   (= msg-data (.server-verify-data self.crypt-ctx self.handshake-messages)))
        (raise StructValidationError))
      ;; client hello ... server finished
      (+= self.handshake-messages (.pack Handshake msg-type msg-data)))

    ;; initial application secrets
    (.recv-server-finished self.crypt-ctx self.handshake-messages)

    ;; check handshake-stream is empty
    (when (.peek handshake-stream)
      (raise RuntimeError))

    ;; write finished and first frame
    (let [client-finished (.pack Handshake HandshakeType.finished (.client-verify-data self.crypt-ctx self.handshake-messages))
          ciphertext (.encrypt-record self.crypt-ctx.client-handshake-encryptor ContentType.handshake client-finished)]
      (+= self.handshake-messages client-finished)
      (when self.head
        (+= ciphertext (.encrypt-record self.crypt-ctx.client-application-encryptor ContentType.application-data self.head)))
      (async-wait (.write next-stream ciphertext)))

    ((async-name TLS13Stream) :crypt-ctx self.crypt-ctx :next-layer next-stream)))

(export
  :objects [TLS13Connector AsyncTLS13Connector])
