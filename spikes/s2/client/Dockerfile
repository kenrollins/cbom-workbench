# C8 and C1: a client that connects every 3 s, offering X25519MLKEM768 then X25519, to the
# slice's hybrid listener (api) and then to its classical one (portal). A Zeek sidecar shares
# its network namespace, so C1 can be judged on both sides: the hybrid group negotiated with
# api and not with portal.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache openssl
CMD ["sh", "-c", "while true; do openssl s_client -connect 172.16.106.11:443 -servername api.agency.test -groups X25519MLKEM768:X25519 </dev/null >/dev/null 2>&1; openssl s_client -connect 172.16.106.10:443 -servername portal.agency.test -groups X25519MLKEM768:X25519 </dev/null >/dev/null 2>&1; sleep 3; done"]
