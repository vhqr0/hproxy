;;; RFC 8446 TLS 1.3
;;; RFC 6066 TLS Extensions

(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  enum [IntEnum]
  hiolib.struct *)

(defclass U8Enum [IntEnum]
  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (setv cls.len 1)))

(defclass U16Enum [IntEnum]
  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (setv cls.len 2)))

(defmacro define-varlen [struct-name field-name len-form struct-form]
  `(defstruct ~struct-name
     [[varlen [~field-name]
       :len ~len-form
       :struct ~struct-form]]))

(defmacro define-int-list-varlen [enum-name field-name len-form]
  (let [list-struct-name (hy.gensym)
        varlen-struct-name (hy.models.Symbol (+ (str enum-name) "List"))]
    `(do
       (define-int-list-struct ~list-struct-name
         ~field-name (. ~enum-name len) :to (normalize it ~enum-name))
       (define-varlen ~varlen-struct-name
         ~field-name ~len-form (async-name ~list-struct-name)))))

(defmacro define-atom-list-varlen [struct-name field-name len-form]
  (let [list-struct-name (hy.gensym)
        varlen-struct-name (hy.models.Symbol (+ (str struct-name) "List"))]
    `(do
       (define-atom-list-struct ~list-struct-name
         ~field-name (async-name ~struct-name))
       (define-varlen ~varlen-struct-name
         ~field-name ~len-form (async-name ~list-struct-name)))))

(defmacro define-list-varlen [struct-name field-name len-form]
  (let [list-struct-name (hy.gensym)
        varlen-struct-name (hy.models.Symbol (+ (str struct-name) "List"))]
    `(do
       (define-list-struct ~list-struct-name
         ~field-name (async-name ~struct-name))
       (define-varlen ~varlen-struct-name
         ~field-name ~len-form (async-name ~list-struct-name)))))


;;; B.1 record layer

(defclass ProtocolVersion [U16Enum]
  (setv SSL30 0x0300
        TLS10 0x0301
        TLS11 0x0302
        TLS12 0x0303
        TLS13 0x0304))

(define-int-list-varlen ProtocolVersion versions 1)

(defclass ContentType [U8Enum]
  (setv invalid             0
        change-cipher-spec 20
        alert              21
        handshake          22
        application-data   23
        heartbeat          24))

(defstruct TLSPlainText
  [[int type :len 1 :to (normalize it ContentType)]
   [int legacy-record-version
    :len 2
    :to (normalize it ProtocolVersion)
    :to-validate (= it ProtocolVersion.TLS12)]
   [varlen fragment :len 2]])

(async-defclass TLSInnerPlaintext [(async-name Struct)]
  (setv names #("content" "type" "zeros"))

  (async-defn [classmethod] pack-to-stream [cls writer data type zeros]
    (async-wait (.write writer data))
    (async-wait (.write writer (int-pack type 1)))
    (async-wait (.write writer (bytes zeros))))

  (async-defn [classmethod] unpack-from-stream [cls reader]
    (let [buf (async-wait (.read-all reader))]
      (for [i (range (- (len buf) 1) -1 -1)]
        (unless (= (get buf i) 0)
          (break))
        (else
          (raise ValueError)))
      #((cut buf i) (normalize (get buf i) ContentType) (- (len buf) i 1)))))

(setv TLSInnerPlaintext.sync-struct TLSInnerPlaintext
      AsyncTLSInnerPlaintext.sync-struct TLSInnerPlaintext)

(defstruct TLSCiphertextHeader
  [[int opaque-type
    :len 1
    :to (normalize it ContentType)
    :to-validate (= it ContentType.application-data)]
   [int legacy-record-version
    :len 2
    :to (normalize it ProtocolVersion)
    :to-validate (= it ProtocolVersion.TLS12)]
   [int length :len 2]])

(defstruct TLSCiphertext
  [[int opaque-type
    :len 1
    :to (normalize it ContentType)
    :to-validate (= it ContentType.application-data)]
   [int legacy-record-version
    :len 2
    :to (normalize it ProtocolVersion)
    :to-validate (= it ProtocolVersion.TLS12)]
   [varlen encrypted-record :len 2]])


;;; B.2 alert messages

(defclass AlertLevel [U8Enum]
  (setv warning 1 fatal 2))

(defclass AlertDescription [U8Enum]
  (setv
    close-notify                          0
    unexpected-message                   10
    bad-record-mac                       20
    decryption-failed-RESERVED           21
    record-overflow                      22
    decompression-failure-RESERVED       30
    handshake-failure                    40
    no-certificate-RESERVED              41
    bad-certificate                      42
    unsupported-certificate              43
    certificate-revoked                  44
    certificate-expired                  45
    certificate-unknown                  46
    illegal-parameter                    47
    unknown-ca                           48
    access-denied                        49
    decode-error                         50
    decrypt-error                        51
    export-restriction-RESERVED          60
    protocol-version                     70
    insufficient-security                71
    internal-error                       80
    inappropriate-fallback               86
    user-canceled                        90
    no-renegotiation-RESERVED           100
    missing-extension                   109
    unsupported-extension               110
    certificate-unobtainable-RESERVED   111
    unrecognized-name                   112
    bad-certificate-status-response     113
    bad-certificate-hash-value-RESERVED 114
    unknown-psk-identity                115
    certificate-required                116
    no-application-protocol             120))

(defstruct Alert
  [[int level :len 1 :to (normalize it AlertLevel)]
   [int description :len 1 :to (normalize it AlertDescription)]])


;;; B.3 handshake protocol

(defclass HandshakeType [U8Enum]
  (setv
    hello-request-RESERVED          0
    client-hello                    1
    server-hello                    2
    hello-verify-request-RESERVED   3
    new-session-ticket              4
    end-of-early-data               5
    hello-retry-request-RESERVED    6
    encrypted-extensions            8
    certificate                    11
    server-key-exchange-RESERVED   12
    certificate-request            13
    server-hello-done-RESERVED     14
    certificate-verify             15
    client-key-exchange-RESERVED   16
    finished                       20
    certificate-url-RESERVED       21
    certificate-status-RESERVED    22
    supplemental-data-RESERVED     23
    key-update                     24
    message-hash                  254))

(defstruct Handshake
  [[int msg-type :len 1 :to (normalize it HandshakeType)]
   [varlen msg-data :len 3]])

(define-list-struct HandshakeList msgs (async-name Handshake))


;;; B.3.1. key exchange messages

(defclass CompressionMethod [U8Enum]
  (setv null 0))

(define-int-list-varlen CompressionMethod methods 1)

(defstruct ClientHello
  [[int legacy-version :len 2 :to (normalize it ProtocolVersion)]
   [bytes random :len 32]
   [varlen legacy-session-id :len 1]
   [struct [cipher-suites] :struct (async-name CipherSuiteList)]
   [struct [legacy-compression-methods] :struct (async-name CompressionMethodList)]
   [struct [extensions] :struct (async-name ExtensionList)]])

(defstruct ServerHello
  [[int legacy-version
    :len 2
    :to (normalize it ProtocolVersion)
    :to-validate (= it ProtocolVersion.TLS12)]
   [bytes random :len 32]
   [varlen legacy-session-id-echo :len 1]
   [int cipher-suite :len 2 :to (normalize it CipherSuite)]
   [int legacy-compression-method
    :len 1
    :to (normalize it CompressionMethod)
    :to-validate (= it CompressionMethod.null)]
   [struct [extensions] :struct (async-name ExtensionList)]])

(defstruct Extension
  [[int extension-type :len 2 :to (normalize it ExtensionType)]
   [varlen extension-data :len 2]])

(define-list-varlen Extension extensions 2)

(defclass ExtensionType [U8Enum]
  (setv server-name                             0
        max-fragment-length                     1
        status-request                          5
        supported-groups                       10
        signature-algorithms                   13
        use-srtp                               14
        heartbeat                              15
        application-layer-protocol-negotiation 16
        signed-certificate-timestamp           18
        client-certificate-type                19
        server-certificate-type                20
        padding                                21
        pre-shared-key                         41
        early-data                             42
        supported-versions                     43
        cookie                                 44
        psk-key-exchange-modes                 45
        certificate-authorities                47
        oid-filters                            48
        post-handshake-auth                    49
        signature-algorithms-cert              50
        key-share                              51))

(defstruct KeyShareEntry
  [[int group :len 2 :to (normalize it NamedGroup)]
   [varlen key-exchange :len 2]])

(define-list-varlen KeyShareEntry shares 2)

(defstruct KeyShareClientHello
  [[struct [client-shares] :struct (async-name KeyShareEntryList)]])

(defstruct KeyShareHelloRetryRequest
  [[int selected-group :len 2 :to (normalize it NamedGroup)]])

(defstruct KeyShareServerhello
  [[struct [selected-group server-share] :struct (async-name KeyShareEntry)]])

(defstruct UncompressedPointRepresentationP256
  [[int legacy-form :len 1 :to-validate (= it 4)]
   [bytes X :len 32]
   [bytes Y :len 32]])

(defstruct UncompressedPointRepresentationP384
  [[int legacy-form :len 1 :to-validate (= it 4)]
   [bytes X :len 48]
   [bytes Y :len 48]])

(defstruct UncompressedPointRepresentationP521
  [[int legacy-form :len 1 :to-validate (= it 4)]
   [bytes X :len 66]
   [bytes Y :len 66]])

(defclass PskKeyExchangeMode [U8Enum]
  (setv psk-ke 0 psk-dhe-ke 1))

(define-int-list-varlen PskKeyExchangeMode modes 1)

(defstruct PskKeyExchangeModes
  [[struct [ke-modes] :struct (async-name PskKeyExchangeModeList)]])

(defstruct EarlyDataIndicationNewSessionTicket
  [[int max-early-data-size :len 4]])

;; (defstruct EarlyDataIndicationClientHello [])
;; (defstruct EarlyDataIndicationEncryptedExtensions [])

(defstruct PskIdentity
  [[varlen identity :len 2]
   [int obfuscated-ticket-age :len 4]])

(define-list-varlen PskIdentity identities 2)

(defstruct PskBinderEntry
  [[varlen binder :len 1]])

(define-atom-list-varlen PskBinderEntry binders 2)

(defstruct OfferedPsks
  [[struct [identities] :struct (async-name PskIdentityList)]
   [struct [binders] :struct (async-name PskBinderEntryList)]])

(defstruct PreSharedKeyExtensionClientHello
  [[struct psks :struct (async-name OfferedPsks)]])

(defstruct PreSharedKeyExtensionServerHello
  [[int selected-identity :len 2]])


;;; B.3.1.1. version extension

(defstruct SupportedVersionsClientHello
  [[struct [versions] :struct (async-name ProtocolVersionList)]])

(defstruct SupportedVersionsServerHello
  [[int selected-version :len 2 :to (normalize it ProtocolVersion)]])


;;; B.3.1.2. cookie extension

(defstruct Cookie
  [[varlen cookie :len 2]])


;;; B.3.1.3. signature algorithm extension

(defclass SignatureScheme [U16Enum]
  (setv rsa-pkcs1-sha256       0x0401
        rsa-pkcs1-sha384       0x0501
        rsa-pkcs1-sha512       0x0601
        ecdsa-secp256r1-sha256 0x0403
        ecdsa-secp384r1-sha384 0x0503
        ecdsa-secp521r1-sha512 0x0603
        rsa-pss-rsae-sha256    0x0804
        rsa-pss-rsae-sha384    0x0805
        rsa-pss-rsae-sha512    0x0806
        ed25519                0x0807
        ed448                  0x0808
        rsa-pss-pss-sha256     0x0809
        rsa-pss-pss-sha384     0x080a
        rsa-pss-pss-sha512     0x080b
        rsa-pkcs1-sha1         0x0201
        ecdsa-sha1             0x0203))

(define-int-list-varlen SignatureScheme schemes 2)


;;;  B.3.1.4. supported groups extension

(defclass NamedGroup [U16Enum]
  (setv secp256r1 0x0017
        secp384r1 0x0018
        secp521r1 0x0019
        x25519    0x001d
        x448      0x001e
        ffdhe2048 0x0100
        ffdhe3072 0x0101
        ffdhe4096 0x0102
        ffdhe6144 0x0103
        ffdhe8192 0x0104))

(define-int-list-varlen NamedGroup groups 2)


;;; B.3.2. server parameters messages

(defstruct DistinguishedName
  [[varlen name :len 2]])

(define-atom-list-varlen DistinguishedName names 2)

(defstruct CertificateAuthoritiesExtension
  [[struct [authorities] :struct (async-name DistinguishedNameList)]])

(defstruct OIDFilter
  [[varlen certificate-extension-oid :len 1]
   [varlen certificate-extension-values :len 2]])

(define-list-varlen OIDFilter filters 2)

;; (defstruct PostHandshakeAuth [])

(defstruct OIDFilerExtension
  [[struct [filters] :struct (async-name OIDFilterList)]])

(defstruct EncryptedExtensions
  [[struct [extensions] :struct (async-name ExtensionList)]])

(defstruct CertificateRequest
  [[varlen certificate-request-context :len 1]
   [struct [extensions] :struct (async-name ExtensionList)]])


;;; B.3.3. authentication messages

(defclass CertificateType [U8Enum]
  (setv X509             0
        OpenPGP-RESERVED 1
        RawPublicKey     2))

;; raw public key is not support
(defstruct CertificateEntryX509
  [[varlen cert-data :len 3]
   [struct [extensions] :struct (async-name ExtensionList)]])

(define-list-struct CertificateEntryX509 certificates 3)

(defstruct CertificateX509
  [[varlen certificate-request-context :len 1]
   [struct [certificate-list] :struct (async-name CertificateEntryX509List)]])

(defstruct CertificateVerify
  [[int algorithm :len 2 :to (normalize it SignatureScheme)]
   [varlen signature :len 2]])

(defstruct FinishedSHA256
  [[bytes verify-data :len 32]])

(defstruct FinishedSHA384
  [[bytes verify-data :len 48]])

(defstruct FinishedSHA512
  [[bytes verify-data :len 64]])


;;; B.3.4. ticket establishment

(defstruct NewSessionTicket
  [[int ticket-lifetime :len 4]
   [int ticket-age-add :len 4]
   [varlen ticket-nonce :len 1]
   [varlen ticket :len 2]
   [struct [extensions] :struct (async-name ExtensionList)]])


;;; updating keys

;; (defstruct EndOfEarlyData [])

(defclass KeyUpdateRequest [U8Enum]
  (setv update-not-request 0 update-requested 1))

(defstruct KeyUpdate
  [[int request-update :len 1 :to (normalize it KeyUpdateRequest)]])


;;; B.4. cipher suites

(defclass CipherSuite [U16Enum]
  (setv TLS-AES-128-GCM-SHA256       0x1301
        TLS-AES-256-GCM-SHA384       0x1302
        TLS-CHACHA20-POLY1305-SHA256 0x1303
        TLS-AES-128-CCM-SHA256       0x1304
        TLS-AES-128-CCM-8-SHA256     0x1305))

(define-int-list-varlen CipherSuite suites 2)


;;; 6066.3. server name indication

(defstruct ServerNameHost
  [[int name-type
    :len 1
    :to (normalize it NameType)
    :to-validate (= it NameType.host-name)]
   [struct [name] :struct (async-name HostName)]])

(defclass NameType [U8Enum]
  (setv host-name 0))

(defstruct HostName
  [[varlen name
    :len 2
    :from (.encode it)
    :to (.decode it)]])

(define-list-varlen ServerNameHost names 2)
