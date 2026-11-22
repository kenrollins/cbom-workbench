# C4: Postgres 18 (Debian 13, OpenSSL 3.5) with TLS through its SSLRequest upgrade.
FROM postgres:18@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722
RUN mkdir -p /etc/pg-tls && cd /etc/pg-tls \
 && openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 -subj "/O=S2/CN=postgres.s2.test" \
      -keyout server.key -out server.crt \
 && chown postgres:postgres server.key server.crt && chmod 600 server.key
CMD ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/etc/pg-tls/server.crt", \
     "-c", "ssl_key_file=/etc/pg-tls/server.key", "-c", "ssl_groups=X25519MLKEM768:X25519"]
