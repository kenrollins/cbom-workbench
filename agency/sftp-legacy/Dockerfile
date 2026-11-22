# sftp-legacy — a records drop on an old base. OpenSSH 6.6 with its era's
# defaults written out: finite-field and elliptic-curve key exchange, RSA, DSA,
# ECDSA and Ed25519 host keys. The base image's trust store is removed: this
# server makes no outbound TLS.
FROM ubuntu:14.04@sha256:64483f3496c1373bfd55348e88694d1c4d0c9b660dee6bfef5e12f43b9933b30
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && apt-get purge -y ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/ssl/certs /usr/share/ca-certificates \
 && rm -f /etc/ssh/ssh_host_* \
 && ssh-keygen -q -N '' -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key \
 && ssh-keygen -q -N '' -t dsa -f /etc/ssh/ssh_host_dsa_key \
 && ssh-keygen -q -N '' -t ecdsa -b 256 -f /etc/ssh/ssh_host_ecdsa_key \
 && ssh-keygen -q -N '' -t ed25519 -f /etc/ssh/ssh_host_ed25519_key \
 && mkdir -p /var/run/sshd
COPY sshd_config /etc/ssh/sshd_config
COPY ssh_config /etc/ssh/ssh_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
