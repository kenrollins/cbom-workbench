# portal — the public benefits portal. Classical TLS: RSA-2048 certificate,
# X25519 and P-256 key exchange.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS pki
RUN apk add --no-cache openssl
WORKDIR /pki
RUN openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 \
      -subj "/O=Mini Agency/CN=portal.agency.test" \
      -addext "subjectAltName=DNS:portal.agency.test" \
      -keyout portal.key -out portal.crt \
 && openssl req -x509 -newkey rsa:1024 -sha1 -nodes -days 365 \
      -subj "/O=Mini Agency/CN=portal.agency.test" \
      -keyout /dev/null -out portal-2019.crt

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache nginx \
 # These servers make no outbound TLS; the trust store is removed so the
 # image holds only the material the service itself uses.
 && rm -f /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/ssl1.1/cert.pem
COPY --from=pki /pki/portal.crt /pki/portal.key /etc/nginx/tls/
COPY --from=pki /pki/portal-2019.crt /etc/ssl/legacy/
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 443
CMD ["nginx", "-g", "daemon off;"]
