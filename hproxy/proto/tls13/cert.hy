(require
  hiolib.rule :readers * *)

(import
  hproxy.proto.tls13.struct *)

(setv signature-algorithms
      [SignatureScheme.ed25519
       SignatureScheme.ed448
       SignatureScheme.ecdsa-secp256r1-sha256
       SignatureScheme.ecdsa-secp384r1-sha384
       SignatureScheme.ecdsa-secp521r1-sha512
       SignatureScheme.rsa-pss-rsae-sha256
       SignatureScheme.rsa-pss-rsae-sha384
       SignatureScheme.rsa-pss-rsae-sha512
       SignatureScheme.rsa-pkcs1-sha256
       SignatureScheme.rsa-pkcs1-sha384
       SignatureScheme.rsa-pkcs1-sha512])

(defclass CertCtx []
  (defn #-- init [self [signature-algorithms signature-algorithms]]
    (setv self.signature-algorithms signature-algorithms))

  (defn [property] extensions [self]
    [#(ExtensionType.signature-algorithms (.pack SignatureSchemeList self.signature-algorithms))])

  (defn recv-server-certificate [self certificate handshake-messages]
    (setv self.certificate certificate
          self.handshake-messages handshake-messages))

  (defn recv-server-certificate-verify [self certificate-verify]
    (setv self.certificate-verify certificate-verify))

  ;; TODO: impl verfiy via cryptography.x509.verification, but these
  ;; API are not useable yet.
  ;;
  ;; url: https://cryptography.io/en/latest/x509/verification/

  (defn verify [self]
    True))

(export
  :objects [CertCtx])
