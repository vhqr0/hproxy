(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  hiolib.struct *)

(defclass HTTPStatusError [StructValidationError])

(defn http-pack-addr [host port]
  ;; example:
  ;;   www.google.com,80 => www.google.com:80
  ;;   240c::6666,53 => [240c::6666]:53
  (.format (if (> (.find host ":") 0) "[{}]:{}" "{}:{}")
           host port))

(defn http-unpack-addr [addr]
  ;; example:
  ;;   www.google.com:80 => www.google.com,80
  ;;   [240c::6666]:53 => 240c::6666,53
  (if (= (get addr 0) "[")
      (let [idx (.find addr "]")]
        (unless (> idx 0)
          (raise ValueError))
        (cond (= (+ idx 1) (len addr))
              #((cut addr 1 idx) 80)
              (= (get addr (+ idx 1)) ":")
              #((cut addr 1 idx) (int (cut addr (+ idx 2) None)))
              True
              (raise ValueError)))
      (let [sp (.split addr ":" 1)]
        (ecase (len sp)
               2 #((get sp 0) (int (get sp 1)))
               1 #((get sp 0) 80)))))

(defn http-pack-headers [headers]
  ;; dict[str,str] => list[str]
  ;;
  ;; example:
  ;;   {"Host": "www.google.com", "Connection": "close"} =>
  ;;   ["Host: www.google.com", "Connection: close", ""]
  (doto (lfor #(k v) (headers.items) (.format "{}: {}" k v))
        (.append "")))

(defn http-unpack-headers [headers]
  ;; list[str] => dict[str,str]
  ;;
  ;; example:
  ;;   ["Host: www.google.com", "Connection: close", ""] =>
  ;;   {"Host": "www.google.com", "Connection": "close"}
  (.pop headers)
  (dfor header headers
        :setv #(k v) (.split header ":" 1)
        (.strip k) (.strip v)))

(defstruct HTTPHeaders
  [[line headers
    :sep b"\r\n"
    :repeat-until (not it)
    :from (http-pack-headers it)
    :to (http-unpack-headers it)]])

(defstruct HTTPFirstLine
  ;; for request, it is (meth,path,ver)
  ;; for response, it is (ver,status,reason)
  [[line firstline
    :sep b"\r\n"
    :from (.join " " it)
    :to (.split it :maxsplit 2)]])

(defstruct HTTPReq
  [[struct [[meth path ver]] :struct (async-name HTTPFirstLine)]
   [struct [headers] :struct (async-name HTTPHeaders)]])

(defstruct HTTPResp
  [[struct [[ver status reason]] :struct (async-name HTTPFirstLine)]
   [struct [headers] :struct (async-name HTTPHeaders)]])

(export
  :objects [HTTPStatusError
            http-pack-addr http-unpack-addr
            http-pack-headers http-unpack-headers
            HTTPReq AsyncHTTPReq HTTPResp AsyncHTTPResp])
