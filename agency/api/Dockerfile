# api — the partner API gateway. Hybrid ML-KEM key exchange (X25519MLKEM768)
# with classical X25519 still accepted, and a classical ECDSA P-256 certificate.
# Two listeners: 443 for the public API, 8443 for partners, who must present a
# certificate issued by the partner CA.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS pki
RUN apk add --no-cache openssl
WORKDIR /pki
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -days 825 \
      -subj "/O=Mini Agency/CN=api.agency.test" \
      -addext "subjectAltName=DNS:api.agency.test" \
      -keyout api.key -out api.crt \
 # The partner CA whose client certificates the 8443 listener requires. Only its
 # certificate ships; the key stays with the partner programme.
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -days 1825 \
      -subj "/O=Mini Agency/CN=Mini Agency Partner CA" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
      -keyout /dev/null -out partner-ca.crt

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache nginx \
 && rm -f /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/ssl1.1/cert.pem
COPY --from=pki /pki/api.crt /pki/api.key /pki/partner-ca.crt /etc/nginx/tls/
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 443 8443
CMD ["nginx", "-g", "daemon off;"]
