# queue — the case-processing message broker. RabbitMQ 4 with AMQP over TLS on
# 5671 only: TLS 1.2, an ECDSA P-256 certificate issued by the internal CA, and
# the P-256 and P-384 curves named in advanced.config. Plain AMQP is off.
FROM rabbitmq:4@sha256:1da79932eb36450a9a93bb7c6b44d04ee542b73e2819833403e364a0bc095709
# No outbound TLS: the base image's trust store is removed.
RUN rm -rf /etc/ssl/certs /usr/share/ca-certificates && mkdir -p /etc/rmq-tls/retired
COPY --from=pki --chown=rabbitmq:rabbitmq /pki/queue/queue.crt /pki/queue/queue.key /etc/rmq-tls/
COPY --from=pki --chown=rabbitmq:rabbitmq /pki/ca/ca.crt /etc/rmq-tls/ca.crt
# Left behind: the certificate the queue served before the internal CA existed.
COPY --from=pki /pki/retired/queue-2020.crt /etc/rmq-tls/retired/
RUN chmod 600 /etc/rmq-tls/queue.key
COPY rabbitmq.conf /etc/rabbitmq/conf.d/90-tls.conf
COPY advanced.config /etc/rabbitmq/advanced.config
# The management listener's settings, kept beside the live ones; RabbitMQ reads
# only *.conf from conf.d, so nothing in this file is in force.
COPY 91-management.conf.disabled /etc/rabbitmq/conf.d/91-management.conf.disabled
EXPOSE 5671
