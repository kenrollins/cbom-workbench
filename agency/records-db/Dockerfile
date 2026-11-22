# records-db — the benefits records database. PostgreSQL 18 with TLS through its
# SSLRequest upgrade: an RSA-2048 certificate issued by the internal CA, the
# hybrid group offered first with X25519 still accepted, and — because
# ssl_ciphers is left at its default — TLS 1.2 RSA key transport accepted as
# well: key establishment with no group at all, which no list of groups shows.
FROM postgres:18@sha256:3a4264520e121176619f54ff867d12774bc81e95e7b84db58d63bccdb6144b81
# This server makes no outbound TLS; the base image's trust store is removed so
# the image holds only the material the service itself uses.
RUN rm -rf /etc/ssl/certs /usr/share/ca-certificates && mkdir -p /etc/pg /etc/pg-tls
COPY --from=pki --chown=postgres:postgres /pki/records-db/server.crt /pki/records-db/server.key /etc/pg-tls/
COPY --from=pki --chown=postgres:postgres /pki/ca/ca.crt /etc/pg-tls/ca.crt
RUN chmod 600 /etc/pg-tls/server.key
COPY postgresql.conf pg_hba.conf /etc/pg/
EXPOSE 5432
CMD ["postgres", "-c", "config_file=/etc/pg/postgresql.conf", "-c", "hba_file=/etc/pg/pg_hba.conf"]
