(setv
  version "0.1.0"
  requires ["hy~=0.27.0" "hyrule~=0.4.0" "hiolib~=0.1.0" "pydantic~=2.2.1"])

(require
  hyrule :readers * *)

(#/ setuptools.setup
  :name "hproxy"
  :version version
  :install-requires requires
  :author "vhqr"
  :description "a simple porxy based on hiolib"
  :packages (#/ setuptools.find-packages))