# pki — the mini-agency's internal certificate authority, as a build-time image.
# It is never run: the service images copy their issued certificates out of it
# (compose `additional_contexts: {pki: docker-image://pqch-agency/pki:m1}`),
# so build it first:
#   docker build -t pqch-agency/pki:m1 agency/pki
# The CA is ECDSA P-384 and signs with SHA-384. Leaf keys are generated here
# with the certificates, so every build has new material; the answer key names
# it by path and algorithm, never by fingerprint.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache openssl
WORKDIR /pki
RUN mkdir ca records-db queue legacy-app retired \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -nodes -days 3650 \
      -subj "/O=Mini Agency/CN=Mini Agency Internal CA" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -keyout ca/ca.key -out ca/ca.crt \
 # records-db: RSA-2048 leaf
 && openssl req -new -newkey rsa:2048 -sha256 -nodes -subj "/O=Mini Agency/CN=records-db.agency.test" \
      -addext "subjectAltName=DNS:records-db.agency.test" -keyout records-db/server.key -out records-db/server.csr \
 && openssl x509 -req -in records-db/server.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 825 -sha384 \
      -copy_extensions copy -out records-db/server.crt \
 # queue: ECDSA P-256 leaf
 && openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -subj "/O=Mini Agency/CN=queue.agency.test" \
      -addext "subjectAltName=DNS:queue.agency.test" -keyout queue/queue.key -out queue/queue.csr \
 && openssl x509 -req -in queue/queue.csr -CA ca/ca.crt -CAkey ca/ca.key -days 825 -sha384 \
      -copy_extensions copy -out queue/queue.crt \
 # legacy-app: RSA-2048 leaf, delivered as a PKCS#12 keystore with the chain
 && openssl req -new -newkey rsa:2048 -sha256 -nodes -subj "/O=Mini Agency/CN=legacy-app.agency.test" \
      -addext "subjectAltName=DNS:legacy-app.agency.test" -keyout legacy-app/legacy-app.key -out legacy-app/legacy-app.csr \
 && openssl x509 -req -in legacy-app/legacy-app.csr -CA ca/ca.crt -CAkey ca/ca.key -days 825 -sha384 \
      -copy_extensions copy -out legacy-app/legacy-app.crt \
 && openssl pkcs12 -export -name tomcat -passout pass:changeit \
      -in legacy-app/legacy-app.crt -inkey legacy-app/legacy-app.key -certfile ca/ca.crt -out legacy-app/keystore.p12 \
 # a retired certificate (RSA-1024, SHA-1), self-signed in 2020 and never removed from the queue's image
 && openssl req -x509 -newkey rsa:1024 -sha1 -nodes -days 365 -subj "/O=Mini Agency/CN=queue.agency.test" \
      -keyout /dev/null -out retired/queue-2020.crt \
 && rm -f */*.csr ca/ca.srl
