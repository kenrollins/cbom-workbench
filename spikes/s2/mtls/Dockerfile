# C7: a listener that requires a client certificate.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS pki
RUN apk add --no-cache openssl
WORKDIR /pki
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 -subj "/O=S2/CN=mtls.s2.test" \
      -addext "subjectAltName=DNS:mtls.s2.test" -keyout k.pem -out c.pem \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 -subj "/O=S2/CN=client-ca" \
      -keyout /dev/null -out ca.pem
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache nginx && rm -f /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/ssl1.1/cert.pem
COPY --from=pki /pki/c.pem /pki/k.pem /pki/ca.pem /etc/nginx/tls/
COPY nginx.conf /etc/nginx/nginx.conf
CMD ["nginx", "-g", "daemon off;"]
