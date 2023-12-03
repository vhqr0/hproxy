(require
  hiolib.rule :readers * *)

(import
  dns.resolver
  dns.message
  dns.rdatatype
  dns.rdataclass
  hiolib.struct *
  hproxy.proto.base *)

(defn get-default-nameservers []
  (. (dns.resolver.get-default-resolver) nameservers))

(async-defclass DNSRequester [(async-name Requester)]
  (defn #-- init [self name [rdtype dns.rdatatype.A] [rdclass dns.rdataclass.IN]]
    (setv self.name name
          self.rdtype rdtype
          self.rdclass rdclass))

  (defn [property] head [self]
    (let [query (-> (dns.message.make-query self.name :rdtype self.rdtype :rdclass self.rdclass)
                    (.to-wire))]
      (+ (int-pack (len query) 2) query)))

  (async-defn request [self stream]
    (let [rlen (int-unpack (async-wait (.read-exactly stream 2)))]
      (dns.message.from-wire (async-wait (.read-exactly stream rlen)))))

  (defn [classmethod] resp-to-str [cls resp]
    (.to-text resp))

  (defn [classmethod] resp-to-bytes [cls resp]
    (.to-wire resp)))

(export
  :objects [get-default-nameservers DNSRequester AsyncDNSRequester])
