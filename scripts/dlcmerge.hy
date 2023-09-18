#!/usr/bin/env hy
;; https://github.com/v2fly/domain-list-community

(require
  hyrule :readers * *)

(import
  hyrule *
  os.path
  re
  json)

(setv tags-dict {"ads" "block" "cn" "direct" "!cn" "forward"})

(setv line-re (re.compile r"^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?"))

(defn load [data-path file default-tag tags]
  (for [line (open (os.path.join data-path file) :encoding "utf-8")]
    (let [line-match (.match line-re (.strip line))]
      (when line-match
        (let [command (or (get line-match 2) "domain")
              arg (get line-match 3)
              tag (get tags-dict (or (get line-match 5) default-tag))]
          (cond (in command #("domain" "full"))
                (.append tags [arg tag])
                (= command "include")
                (load data-path arg default-tag tags)))))))

(defmain []
  (let [args (parse-args [["-d" "--data-path"
                           :default (os.path.join "domain-list-community" "data")]
                          ["-o" "--output-path" :default "tags.json"]])
        tags (list)]
    (load args.data-path "cn" "cn" tags)
    (load args.data-path "geolocation-!cn" "!cn" tags)
    (with [f (open args.output-path "w")]
      (json.dump tags f))))
