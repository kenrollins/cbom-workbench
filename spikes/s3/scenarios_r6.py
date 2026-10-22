"""R6, change plan: starting configurations, each asked for `enable` and for `require`.

`solve` is one set of replacements per intent that the builder applies and verifies, to show the item
can be done. It is not a label and is never shown or compared: a reply is scored by running it.
"""

from scenarios_r5 import KAFKA_BASE, LOC, NG_HEAD, PG_BASE, RMQ_BASE, RSA, SNI, K, N, P, R, ng

SITE = ("server {\n    listen 443 ssl;\n    server_name lab.s3.test;\n    ssl_certificate     /etc/nginx/tls/rsa2048.crt;\n"
        "    ssl_certificate_key /etc/nginx/tls/rsa2048.key;\n%s    location / { return 200 \"lab\\n\"; }\n}\n")
H13 = "ssl_protocols TLSv1.3;"

LAYOUTS = [
    {"id": "a", "service": "nginx", "sni": SNI, "what": "curve and protocol lines in the server block",
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519:prime256v1;\n")},
     "solve": {"enable": [("ssl_ecdh_curve X25519:prime256v1;", "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;")],
               "require": [("ssl_ecdh_curve X25519:prime256v1;", "ssl_ecdh_curve X25519MLKEM768;"), ("ssl_protocols TLSv1.2 TLSv1.3;", H13)]}},
    {"id": "b", "service": "nginx", "sni": SNI, "what": "TLS settings in an included snippet",
     "files": {N: ng(RSA + "        include /etc/nginx/snippets/tls.conf;\n"),
               "/etc/nginx/snippets/tls.conf": "# TLS settings shared by every server block.\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519:secp384r1;\n"},
     "solve": {"enable": [("ssl_ecdh_curve X25519:secp384r1;", "ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;")],
               "require": [("ssl_ecdh_curve X25519:secp384r1;", "ssl_ecdh_curve X25519MLKEM768;"), ("ssl_protocols TLSv1.2 TLSv1.3;", H13)]}},
    {"id": "c", "service": "nginx", "sni": SNI, "what": "a curve line at http level, overridden in the server block",
     "files": {N: ng(RSA + "        ssl_ecdh_curve secp521r1;\n", http_extra="    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ecdh_curve X25519;\n")},
     "solve": {"enable": [("        ssl_ecdh_curve secp521r1;", "        ssl_ecdh_curve X25519MLKEM768:secp521r1;")],
               "require": [("        ssl_ecdh_curve secp521r1;", "        ssl_ecdh_curve X25519MLKEM768;"), ("ssl_protocols TLSv1.2 TLSv1.3;", H13)]}},
    {"id": "d", "service": "nginx", "sni": SNI, "what": "settings at http level, the server block in conf.d",
     "files": {N: NG_HEAD + "http {\n    access_log off;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ecdh_curve secp384r1:X25519;\n    include /etc/nginx/conf.d/*.conf;\n}\n",
               "/etc/nginx/conf.d/site.conf": SITE % ""},
     "solve": {"enable": [("ssl_ecdh_curve secp384r1:X25519;", "ssl_ecdh_curve X25519MLKEM768:secp384r1:X25519;")],
               "require": [("ssl_ecdh_curve secp384r1:X25519;", "ssl_ecdh_curve X25519MLKEM768;"), ("ssl_protocols TLSv1.2 TLSv1.3;", H13)]}},
    {"id": "e", "service": "nginx", "sni": SNI, "what": "no curve or protocol line at all: the defaults apply",
     "files": {N: ng(RSA)},
     "solve": {"enable": [],
               "require": [(RSA, RSA + "        ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519MLKEM768;\n")]}},
    {"id": "f", "service": "nginx", "sni": SNI, "what": "a cipher line that allows RSA key transport",
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519:prime256v1;\n        ssl_ciphers AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n")},
     "solve": {"enable": [("ssl_ecdh_curve X25519:prime256v1;", "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;")],
               "require": [("ssl_ecdh_curve X25519:prime256v1;", "ssl_ecdh_curve X25519MLKEM768;"), ("ssl_protocols TLSv1.2 TLSv1.3;", H13)]}},
    {"id": "g", "service": "nginx", "sni": SNI, "what": "a commented-out curve line beside the live one",
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.3;\n        # ssl_ecdh_curve X25519MLKEM768:X25519;\n        ssl_ecdh_curve X25519:secp384r1;\n")},
     "solve": {"enable": [("        ssl_ecdh_curve X25519:secp384r1;", "        ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;")],
               "require": [("        ssl_ecdh_curve X25519:secp384r1;", "        ssl_ecdh_curve X25519MLKEM768;")]}},
    {"id": "h", "service": "nginx", "sni": SNI, "what": "a disabled file in conf.d beside the live one",
     "files": {N: NG_HEAD + "http {\n    access_log off;\n    include /etc/nginx/conf.d/*.conf;\n}\n",
               "/etc/nginx/conf.d/old.conf.disabled": "# Superseded 2024-11; kept for reference.\nssl_ecdh_curve X25519MLKEM768;\n",
               "/etc/nginx/conf.d/site.conf": SITE % "    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ecdh_curve prime256v1;\n"},
     "solve": {"enable": [("ssl_ecdh_curve prime256v1;", "ssl_ecdh_curve X25519MLKEM768:prime256v1;")],
               "require": [("ssl_ecdh_curve prime256v1;", "ssl_ecdh_curve X25519MLKEM768;"), ("ssl_protocols TLSv1.2 TLSv1.3;", H13)]}},
    {"id": "i", "service": "nginx", "sni": SNI, "what": "an ECDSA certificate, TLS 1.3 only, two classical curves",
     "files": {N: ng("        ssl_certificate     /etc/nginx/tls/ec256.crt;\n        ssl_certificate_key /etc/nginx/tls/ec256.key;\n        ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519:secp384r1;\n")},
     "solve": {"enable": [("ssl_ecdh_curve X25519:secp384r1;", "ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;")],
               "require": [("ssl_ecdh_curve X25519:secp384r1;", "ssl_ecdh_curve X25519MLKEM768;")]}},
    {"id": "j", "service": "nginx", "sni": SNI, "what": "a policy file rendered by another tool, included by exact name",
     "files": {N: ng(RSA + "        # Protocol versions and key-exchange groups come from the central crypto\n        # policy, rendered into this file.\n        include /etc/nginx/policy/tls.conf;\n        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;\n"),
               "/etc/nginx/policy/tls.conf": "# Rendered from policy/crypto-policy.yaml, intent none.\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519:prime256v1;\n"},
     "solve": {"enable": [("ssl_ecdh_curve X25519:prime256v1;", "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;")],
               "require": [("ssl_ecdh_curve X25519:prime256v1;", "ssl_ecdh_curve X25519MLKEM768;"), ("ssl_protocols TLSv1.2 TLSv1.3;", H13)]}},
    {"id": "k", "service": "nginx", "sni": SNI, "what": "finite-field DHE parameters loaded for TLS 1.2",
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_dhparam /etc/nginx/tls/dh2048.pem;\n        ssl_ecdh_curve X25519;\n")},
     "solve": {"enable": [("ssl_ecdh_curve X25519;", "ssl_ecdh_curve X25519MLKEM768:X25519;")],
               "require": [("ssl_ecdh_curve X25519;", "ssl_ecdh_curve X25519MLKEM768;"), ("ssl_protocols TLSv1.2 TLSv1.3;", H13),
                           ("        ssl_dhparam /etc/nginx/tls/dh2048.pem;\n", "")]}},
    {"id": "l", "service": "nginx", "sni": SNI, "what": "TLS 1.2 only",
     "files": {N: ng(RSA + "        ssl_protocols TLSv1.2;\n        ssl_ecdh_curve X25519:prime256v1;\n")},
     "solve": {"enable": [("ssl_protocols TLSv1.2;", "ssl_protocols TLSv1.2 TLSv1.3;"), ("ssl_ecdh_curve X25519:prime256v1;", "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;")],
               "require": [("ssl_protocols TLSv1.2;", H13), ("ssl_ecdh_curve X25519:prime256v1;", "ssl_ecdh_curve X25519MLKEM768;")]}},
    {"id": "m", "service": "postgres", "what": "an explicit classical ssl_groups line",
     "files": {P: PG_BASE + "ssl_groups = 'X25519:prime256v1'\n"},
     "solve": {"enable": [("ssl_groups = 'X25519:prime256v1'", "ssl_groups = 'X25519MLKEM768:X25519:prime256v1'")],
               "require": [("ssl_groups = 'X25519:prime256v1'", "ssl_groups = 'X25519MLKEM768'\nssl_min_protocol_version = 'TLSv1.3'")]}},
    {"id": "n", "service": "postgres", "what": "no ssl_groups line: the default applies",
     "files": {P: PG_BASE},
     "solve": {"enable": [("ssl = on\n", "ssl = on\nssl_groups = 'X25519MLKEM768:X25519'\n")],
               "require": [("ssl = on\n", "ssl = on\nssl_groups = 'X25519MLKEM768'\nssl_min_protocol_version = 'TLSv1.3'\n")]}},
    {"id": "o", "service": "postgres", "what": "ssl_groups set in the main file and again in an included one",
     "files": {P: PG_BASE + "ssl_groups = 'X25519'\ninclude 'tls.conf'\n", "/etc/pg/tls.conf": "# TLS policy, managed separately\nssl_groups = 'X448:X25519'\n"},
     "solve": {"enable": [("ssl_groups = 'X448:X25519'", "ssl_groups = 'X25519MLKEM768:X448:X25519'")],
               "require": [("ssl_groups = 'X448:X25519'", "ssl_groups = 'X25519MLKEM768'\nssl_min_protocol_version = 'TLSv1.3'")]}},
]

# Not possible with the image as built: the runtime offers no ML-KEM group (spike S2). The right reply
# is `blocked: supplier` with no edits. The builder records what the runtime itself lists.
BLOCKED = [
    {"id": "p", "service": "rabbitmq", "what": "RabbitMQ 4 on Erlang/OTP 27, TLS 1.3 and 1.2",
     "files": {R: RMQ_BASE + "ssl_options.versions.1 = tlsv1.3\nssl_options.versions.2 = tlsv1.2\n"}},
    {"id": "q", "service": "rabbitmq", "what": "RabbitMQ 4 on Erlang/OTP 27, TLS 1.3 only",
     "files": {R: RMQ_BASE + "ssl_options.versions.1 = tlsv1.3\n"}},
    {"id": "r", "service": "kafka", "what": "Kafka 4.1 on the JVM's TLS",
     "files": {K: KAFKA_BASE + "ssl.enabled.protocols=TLSv1.2,TLSv1.3\n"}},
]
_ = LOC
