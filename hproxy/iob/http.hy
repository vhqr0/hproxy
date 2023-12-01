(require
  hiolib.rule :readers * *)

(import
  hproxy.proto.http *
  hproxy.iob.iob *)

(async-defclass HTTPOUB [(async-name OUB)] (setv scheme "http" connector-class (async-name HTTPConnector)))
(async-defclass HTTPINB [(async-name INB)] (setv scheme "http" acceptor-class  (async-name HTTPAcceptor)))

(export
  :objects [])
