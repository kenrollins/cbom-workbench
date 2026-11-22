# pq-gateway — the inter-agency exchange gateway, migrated first. TLS 1.3 only,
# the hybrid ML-KEM group only, and an ML-DSA-65 certificate: post-quantum key
# establishment and post-quantum authentication. The certificate is self-signed;
# the internal CA cannot issue it yet (the signature track, M3).
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS pki
RUN apk add --no-cache openssl
WORKDIR /pki
RUN openssl req -x509 -newkey mldsa65 -nodes -days 825 \
      -subj "/O=Mini Agency/CN=pq-gateway.agency.test" \
      -addext "subjectAltName=DNS:pq-gateway.agency.test" \
      -keyout pq-gateway.key -out pq-gateway.crt

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache nginx \
 && rm -f /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/ssl1.1/cert.pem
COPY --from=pki /pki/pq-gateway.crt /pki/pq-gateway.key /etc/nginx/tls/
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 443
CMD ["nginx", "-g", "daemon off;"]
