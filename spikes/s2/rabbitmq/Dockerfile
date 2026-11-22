# C5: RabbitMQ 4 (Erlang/OTP 27) with AMQP over TLS on 5671.
FROM rabbitmq:4@sha256:1da79932eb36450a9a93bb7c6b44d04ee542b73e2819833403e364a0bc095709
RUN mkdir -p /etc/rmq-tls && cd /etc/rmq-tls \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 -subj "/O=S2/CN=rabbitmq.s2.test" \
      -keyout server.key -out server.crt \
 && cp server.crt ca.crt && chown -R rabbitmq:rabbitmq /etc/rmq-tls && chmod 600 server.key
COPY rabbitmq.conf /etc/rabbitmq/conf.d/90-tls.conf
