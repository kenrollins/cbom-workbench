"""R5, trace to cause: configurations and the wire finding each produces.

A line ending in `  <<CAUSE` is the line that sets the behaviour; the marker is stripped before the
file is used. `mutate` is a list of (old, new) replacements that change that line's value: the
builder starts the service both ways and keeps the scenario only if the finding is there before and
gone after. `cause: default` means no line sets it: the builder removes every uncommented line
naming `directive` and the finding must still be there.
"""

NG_HEAD = "worker_processes 1;\nerror_log /dev/stderr warn;\npid /run/nginx.pid;\nevents { worker_connections 64; }\n"
RSA = "        ssl_certificate     /etc/nginx/tls/rsa2048.crt;\n        ssl_certificate_key /etc/nginx/tls/rsa2048.key;\n"
LOC = "        location / { return 200 \"lab\\n\"; }\n"


def ng(server_body: str, http_extra: str = "", more: str = "") -> str:
    return (NG_HEAD + "http {\n    access_log off;\n    server_tokens off;\n" + http_extra +
            "    server {\n        listen 443 ssl;\n        server_name lab.s3.test;\n" + server_body + LOC + "    }\n" + more + "}\n")


SSH_BASE = ("Port 22\nHostKey /etc/ssh/ssh_host_ed25519_key\nHostKey /etc/ssh/ssh_host_rsa_key\n{}"
            "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nSubsystem sftp internal-sftp\n")
PG_BASE = ("# S3 lab\nlisten_addresses = '*'\nmax_connections = 20\nssl = on\n"
           "ssl_cert_file = '/etc/pg/tls/rsa2048.crt'\nssl_key_file = '/etc/pg/tls/rsa2048.key'\n")
RMQ_BASE = ("listeners.ssl.default = 5671\nssl_options.cacertfile = /etc/rmq-tls/ca.crt\n"
            "ssl_options.certfile   = /etc/rmq-tls/server.crt\nssl_options.keyfile    = /etc/rmq-tls/server.key\n"
            "ssl_options.verify     = verify_none\nssl_options.fail_if_no_peer_cert = false\n")
KAFKA_BASE = ("process.roles=broker,controller\nnode.id=1\ncontroller.quorum.voters=1@localhost:9094\n"
              "listeners=SSL://:9093,CONTROLLER://:9094\nadvertised.listeners=SSL://172.16.106.60:9093\n"
              "listener.security.protocol.map=SSL:SSL,CONTROLLER:PLAINTEXT\ninter.broker.listener.name=SSL\n"
              "controller.listener.names=CONTROLLER\nlog.dirs=/tmp/kraft-logs\noffsets.topic.replication.factor=1\n"
              "ssl.keystore.type=PEM\nssl.keystore.location=/etc/kafka-tls/keystore.pem\nssl.truststore.type=PEM\n"
              "ssl.truststore.location=/etc/kafka-tls/truststore.pem\nssl.endpoint.identification.algorithm=\nssl.client.auth=none\n")
LEGACY = ("Port 22\nProtocol 2\nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\n"
          "HostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n{}"
          "UsePrivilegeSeparation yes\nPermitRootLogin no\nPasswordAuthentication no\nSubsystem sftp internal-sftp\n")
N, S, P = "/etc/nginx/nginx.conf", "/etc/ssh/sshd_config", "/etc/pg/postgresql.conf"
R, K = "/etc/rabbitmq/conf.d/90-tls.conf", "/etc/kafka-tls/server.properties"
SNI = "lab.s3.test"

SCENARIOS = [
    # ------------------------------------------------------------------ nginx 1.28, OpenSSL 3.5
    {"id": "n01", "service": "nginx", "sni": SNI, "finding": ("tls13_group", "secp384r1"),
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519:secp384r1;  <<CAUSE\n")},
     "mutate": [("ssl_ecdh_curve X25519:secp384r1;", "ssl_ecdh_curve X25519;")]},
    {"id": "n02", "service": "nginx", "sni": SNI, "finding": ("tls13_group", "X448"),
     "files": {N: ng(RSA + "        include /etc/nginx/snippets/tls.conf;\n"),
               "/etc/nginx/snippets/tls.conf": "# TLS settings shared by every server block.\nssl_protocols TLSv1.3;\nssl_ecdh_curve X448:X25519;  <<CAUSE\n"},
     "mutate": [("ssl_ecdh_curve X448:X25519;", "ssl_ecdh_curve X25519;")]},
    {"id": "n03", "service": "nginx", "sni": SNI, "finding": ("tls13_group", "secp521r1"),
     "files": {N: ng(RSA + "        ssl_ecdh_curve secp521r1;  <<CAUSE\n", http_extra="    ssl_ecdh_curve X25519;\n")},
     "mutate": [("ssl_ecdh_curve secp521r1;", "ssl_ecdh_curve secp384r1;")]},
    {"id": "n04", "service": "nginx", "sni": SNI, "finding": ("tls13_group", "secp384r1"),
     "files": {N: NG_HEAD + "http {\n    access_log off;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ecdh_curve secp384r1:X25519;  <<CAUSE\n    include /etc/nginx/conf.d/*.conf;\n}\n",
               "/etc/nginx/conf.d/site.conf": "server {\n    listen 443 ssl;\n    server_name lab.s3.test;\n    ssl_certificate     /etc/nginx/tls/rsa2048.crt;\n    ssl_certificate_key /etc/nginx/tls/rsa2048.key;\n    location / { return 200 \"lab\\n\"; }\n}\n"},
     "mutate": [("ssl_ecdh_curve secp384r1:X25519;", "ssl_ecdh_curve X25519;")]},
    {"id": "n05", "service": "nginx", "sni": SNI, "finding": ("tls13_group", "X25519MLKEM768"), "cause": "default",
     "directive": "ssl_ecdh_curve", "files": {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n")}},
    {"id": "n06", "service": "nginx", "sni": SNI, "finding": ("tls12",), "cause": "default", "directive": "ssl_protocols",
     "files": {N: ng(RSA + "        # ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519:prime256v1;\n")}},
    {"id": "n07", "service": "nginx", "sni": SNI, "finding": ("tls12",),
     "files": {N: ng(RSA + "        include /etc/nginx/snippets/tls.conf;\n        ssl_ecdh_curve X25519:prime256v1;\n"),
               "/etc/nginx/snippets/tls.conf": "ssl_protocols TLSv1.2 TLSv1.3;  <<CAUSE\nssl_prefer_server_ciphers on;\n"},
     "mutate": [("ssl_protocols TLSv1.2 TLSv1.3;", "ssl_protocols TLSv1.3;")]},
    {"id": "n08", "service": "nginx", "sni": SNI, "finding": ("rsa_kx",),
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519MLKEM768:X25519;\n        ssl_ciphers AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;  <<CAUSE\n")},
     "mutate": [("ssl_ciphers AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;", "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;")]},
    {"id": "n09", "service": "nginx", "sni": SNI, "finding": ("rsa_kx",), "cause": "default", "directive": "ssl_ciphers",
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519MLKEM768:X25519;\n")}},
    {"id": "n10", "service": "nginx", "sni": SNI, "finding": ("cert", "id-ecPublicKey", 256),
     "files": {N: ng("        ssl_certificate     /etc/nginx/tls/ec256.crt;  <<CAUSE\n        ssl_certificate_key /etc/nginx/tls/ec256.key;\n        ssl_protocols TLSv1.3;\n")},
     "mutate": [("ec256.crt", "rsa2048.crt"), ("ec256.key", "rsa2048.key")]},
    {"id": "n11", "service": "nginx", "sni": "other.s3.test", "finding": ("cert", "id-ecPublicKey", 384),
     "files": {N: ng(RSA, more="    server {\n        listen 443 ssl;\n        server_name other.s3.test;\n        ssl_certificate     /etc/nginx/tls/ec384.crt;  <<CAUSE\n        ssl_certificate_key /etc/nginx/tls/ec384.key;\n" + LOC + "    }\n")},
     "mutate": [("ec384.crt", "ec256.crt"), ("ec384.key", "ec256.key")]},
    {"id": "n12", "service": "nginx", "sni": SNI, "finding": ("tls13_group", "secp256r1"),
     "files": {N: NG_HEAD + "http {\n    access_log off;\n    include /etc/nginx/conf.d/*.conf;\n}\n",
               "/etc/nginx/conf.d/old.conf.disabled": "# Superseded 2024-11; kept for reference.\nssl_ecdh_curve X448;\n",
               "/etc/nginx/conf.d/site.conf": "server {\n    listen 443 ssl;\n    server_name lab.s3.test;\n    ssl_certificate     /etc/nginx/tls/rsa2048.crt;\n    ssl_certificate_key /etc/nginx/tls/rsa2048.key;\n    ssl_ecdh_curve prime256v1;  <<CAUSE\n    location / { return 200 \"lab\\n\"; }\n}\n"},
     "mutate": [("ssl_ecdh_curve prime256v1;", "ssl_ecdh_curve secp384r1;")]},
    {"id": "n13", "service": "nginx", "sni": SNI, "finding": ("tls13_group", "X25519MLKEM768"),
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.3;\n        # ssl_ecdh_curve X25519MLKEM768:X25519;\n        ssl_ecdh_curve X25519MLKEM768;  <<CAUSE\n")},
     "mutate": [("        ssl_ecdh_curve X25519MLKEM768;", "        ssl_ecdh_curve X25519;")]},
    {"id": "n14", "service": "nginx", "sni": SNI, "finding": ("dhe", 2048),
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_dhparam /etc/nginx/tls/dh2048.pem;  <<CAUSE\n")},
     "mutate": [("        ssl_dhparam /etc/nginx/tls/dh2048.pem;\n", "")]},
    # ------------------------------------------------------------------ OpenSSH 10.0 (first value wins)
    {"id": "s01", "service": "sshd", "finding": ("kex", "curve25519-sha256"),
     "files": {S: SSH_BASE.format("KexAlgorithms mlkem768x25519-sha256,curve25519-sha256  <<CAUSE\n")},
     "mutate": [("KexAlgorithms mlkem768x25519-sha256,curve25519-sha256", "KexAlgorithms mlkem768x25519-sha256")]},
    {"id": "s02", "service": "sshd", "finding": ("kex", "ecdh-sha2-nistp256"),
     "files": {S: SSH_BASE.format("KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256  <<CAUSE\n") + "# hardening pass, 2025\nKexAlgorithms diffie-hellman-group14-sha256\n"},
     "mutate": [("KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256", "KexAlgorithms curve25519-sha256")]},
    {"id": "s03", "service": "sshd", "finding": ("kex", "ecdh-sha2-nistp384"),
     "files": {S: "Include /etc/ssh/sshd_config.d/*.conf\n" + SSH_BASE.format("KexAlgorithms curve25519-sha256\n"),
               "/etc/ssh/sshd_config.d/10-kex.conf": "# site policy\nKexAlgorithms ecdh-sha2-nistp384  <<CAUSE\n"},
     "mutate": [("KexAlgorithms ecdh-sha2-nistp384", "KexAlgorithms ecdh-sha2-nistp521")]},
    {"id": "s04", "service": "sshd", "finding": ("kex", "mlkem768x25519-sha256"), "cause": "default", "directive": "KexAlgorithms",
     "files": {S: SSH_BASE.format("")}},
    {"id": "s05", "service": "sshd", "finding": ("kex", "curve25519-sha256"),
     "files": {S: SSH_BASE.format("KexAlgorithms curve25519-sha256  <<CAUSE\n") + "Include /etc/ssh/sshd_config.d/*.conf\n",
               "/etc/ssh/sshd_config.d/10-kex.conf": "KexAlgorithms diffie-hellman-group14-sha256\n"},
     "mutate": [("KexAlgorithms curve25519-sha256", "KexAlgorithms ecdh-sha2-nistp256")]},
    {"id": "s06", "service": "sshd", "finding": ("hostkey", "ssh-ed25519"),
     "files": {S: "Port 22\nHostKey /etc/ssh/ssh_host_ed25519_key  <<CAUSE\nHostKey /etc/ssh/ssh_host_rsa_key\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"},
     "mutate": [("HostKey /etc/ssh/ssh_host_ed25519_key\n", "")]},
    {"id": "s07", "service": "sshd", "finding": ("kex", "diffie-hellman-group14-sha1"),
     "files": {S: SSH_BASE.format("KexAlgorithms +diffie-hellman-group14-sha1  <<CAUSE\n")},
     "mutate": [("KexAlgorithms +diffie-hellman-group14-sha1\n", "")]},
    {"id": "s08", "service": "sshd", "finding": ("kex", "sntrup761x25519-sha512"), "cause": "default", "directive": "KexAlgorithms",
     "files": {S: SSH_BASE.format("KexAlgorithms -mlkem768x25519-sha256\n")}},
    {"id": "s09", "service": "sshd", "finding": ("kex", "sntrup761x25519-sha512"),
     "files": {S: "Include /etc/ssh/sshd_config.d/*.conf\n" + SSH_BASE.format("#KexAlgorithms curve25519-sha256\n"),
               "/etc/ssh/sshd_config.d/50-pq.conf": "KexAlgorithms sntrup761x25519-sha512,curve25519-sha256  <<CAUSE\n"},
     "mutate": [("KexAlgorithms sntrup761x25519-sha512,curve25519-sha256", "KexAlgorithms curve25519-sha256")]},
    {"id": "s10", "service": "sshd-legacy", "finding": ("kex", "diffie-hellman-group1-sha1"),
     "files": {S: LEGACY.format("KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1  <<CAUSE\n")},
     "mutate": [(",diffie-hellman-group1-sha1", "")]},
    # ------------------------------------------------------------------ Postgres 18 (last value wins)
    {"id": "p01", "service": "postgres", "finding": ("tls13_group", "X25519MLKEM768"),
     "files": {P: PG_BASE + "ssl_groups = 'X25519MLKEM768:X25519'  <<CAUSE\n"},
     "mutate": [("ssl_groups = 'X25519MLKEM768:X25519'", "ssl_groups = 'X25519'")]},
    {"id": "p02", "service": "postgres", "finding": ("tls13_group", "secp384r1"),
     "files": {P: PG_BASE + "ssl_groups = 'X25519'\nshared_buffers = 64MB\n# override for the reporting clients\nssl_groups = 'secp384r1'  <<CAUSE\n"},
     "mutate": [("ssl_groups = 'secp384r1'", "ssl_groups = 'secp521r1'")]},
    {"id": "p03", "service": "postgres", "finding": ("tls13_group", "X448"),
     "files": {P: PG_BASE + "ssl_groups = 'X25519'\ninclude 'tls.conf'\n", "/etc/pg/tls.conf": "# TLS policy, managed separately\nssl_groups = 'X448:X25519'  <<CAUSE\n"},
     "mutate": [("ssl_groups = 'X448:X25519'", "ssl_groups = 'X25519'")]},
    {"id": "p04", "service": "postgres", "finding": ("tls13_group", "secp256r1"), "cause": "default", "directive": "ssl_groups",
     "files": {P: PG_BASE + "ssl_min_protocol_version = 'TLSv1.2'\n"}},
    {"id": "p05", "service": "postgres", "finding": ("rsa_kx",), "cause": "default", "directive": "ssl_ciphers",
     "files": {P: PG_BASE + "ssl_groups = 'X25519MLKEM768:X25519'\n"}},
    {"id": "p06", "service": "postgres", "finding": ("cert", "id-ecPublicKey", 256),
     "files": {P: "listen_addresses = '*'\nssl = on\nssl_cert_file = '/etc/pg/tls/ec256.crt'  <<CAUSE\nssl_key_file = '/etc/pg/tls/ec256.key'\n"},
     "mutate": [("ec256.crt", "rsa2048.crt"), ("ec256.key", "rsa2048.key")]},
    # ------------------------------------------------------------------ RabbitMQ 4 (Erlang/OTP 27)
    {"id": "r01", "service": "rabbitmq", "finding": ("tls12",),
     "files": {R: RMQ_BASE + "ssl_options.versions.1 = tlsv1.3\nssl_options.versions.2 = tlsv1.2  <<CAUSE\n"},
     "mutate": [("ssl_options.versions.2 = tlsv1.2\n", "")]},
    {"id": "r02", "service": "rabbitmq", "finding": ("tls13_group", "X448"), "cause": "default", "directive": "ssl_options.(supported_groups|eccs)",
     "files": {R: RMQ_BASE + "ssl_options.versions.1 = tlsv1.3\nssl_options.versions.2 = tlsv1.2\n"}},
    {"id": "r03", "service": "rabbitmq", "finding": ("tls13",),
     "files": {R: RMQ_BASE + "ssl_options.versions.1 = tlsv1.3  <<CAUSE\nssl_options.versions.2 = tlsv1.2\n"},
     "mutate": [("ssl_options.versions.1 = tlsv1.3\n", "")]},
    # ------------------------------------------------------------------ Kafka 4.1 (JVM TLS)
    {"id": "k01", "service": "kafka", "finding": ("tls12",),
     "files": {K: KAFKA_BASE + "ssl.enabled.protocols=TLSv1.2,TLSv1.3  <<CAUSE\n"},
     "mutate": [("ssl.enabled.protocols=TLSv1.2,TLSv1.3", "ssl.enabled.protocols=TLSv1.3")]},
    {"id": "k02", "service": "kafka", "finding": ("tls13_group", "secp384r1"), "cause": "default", "directive": "named.?groups",
     "files": {K: KAFKA_BASE + "ssl.enabled.protocols=TLSv1.2,TLSv1.3\n"}},
    {"id": "k03", "service": "kafka", "finding": ("tls13_group", "X25519"), "cause": "default", "directive": "named.?groups",
     "files": {K: KAFKA_BASE}},
]
