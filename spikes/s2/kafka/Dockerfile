# C6: Kafka 4.1 (KRaft, one node) with an SSL listener on 9093, PEM key store.
# Started from a properties file; the image's wrapper wants its own credential files.
FROM apache/kafka:4.1.0
USER root
RUN mkdir -p /etc/kafka-tls && cd /etc/kafka-tls \
 && openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 -subj "/O=S2/CN=kafka.s2.test" \
      -keyout server.key -out server.crt 2>/dev/null \
 && cat server.key server.crt > keystore.pem && cp server.crt truststore.pem \
 && chown -R appuser /etc/kafka-tls
COPY server.properties /etc/kafka-tls/server.properties
USER appuser
CMD ["sh", "-c", "/opt/kafka/bin/kafka-storage.sh format --standalone -t s2s2s2s2s2s2s2s2s2s2sw -c /etc/kafka-tls/server.properties >/dev/null && exec /opt/kafka/bin/kafka-server-start.sh /etc/kafka-tls/server.properties"]
