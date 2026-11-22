# bastion — the administrators' jump host. OpenSSH 10.0 with post-quantum
# hybrid key exchange first, classical X25519 still accepted, and classical
# Ed25519 and RSA-3072 host keys.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache openssh-server \
 && rm -f /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/ssl1.1/cert.pem \
 && rm -f /etc/ssh/ssh_host_* \
 && ssh-keygen -q -N '' -t ed25519 -f /etc/ssh/ssh_host_ed25519_key \
 && ssh-keygen -q -N '' -t rsa -b 3072 -f /etc/ssh/ssh_host_rsa_key
COPY sshd_config /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
