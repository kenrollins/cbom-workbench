# C3: TLS 1.3 with an ML-DSA-65 leaf certificate, hybrid and classical groups.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS pki
RUN apk add --no-cache openssl
WORKDIR /pki
RUN openssl req -x509 -newkey mldsa65 -nodes -days 825 -subj "/O=S2/CN=mldsa.s2.test" \
      -addext "subjectAltName=DNS:mldsa.s2.test" -keyout k.pem -out c.pem
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache nginx && rm -f /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/ssl1.1/cert.pem
COPY --from=pki /pki/c.pem /pki/k.pem /etc/nginx/tls/
COPY nginx.conf /etc/nginx/nginx.conf
CMD ["nginx", "-g", "daemon off;"]
