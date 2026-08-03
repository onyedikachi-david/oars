# Development sshd for Oars integration tests (spec 02 §11, spec 03 §11).
#
# Fixed, well-known test credentials — NEVER use this image anywhere near
# real workloads:
#   root / oars-test-password                 (password auth leg)
#   /root/.ssh/id_ed25519 + oars-test-passphrase  (key auth leg)
#
# The config is written in full (not sed-patched) so the container is
# deterministic across openssh package revisions. Busybox tools (df, ps)
# also serve as the busybox variant for the spec 03 probe parsers.

FROM alpine:3.20

RUN apk add --no-cache openssh bash zip unzip \
    && ssh-keygen -A \
    && echo 'root:oars-test-password' | chpasswd \
    && mkdir -p /root/.ssh \
    && chmod 700 /root/.ssh \
    && ssh-keygen -t ed25519 -N 'oars-test-passphrase' -f /root/.ssh/id_ed25519 -q \
    && cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys \
    && chmod 600 /root/.ssh/authorized_keys \
    && printf 'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nSubsystem sftp internal-sftp\n' > /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
