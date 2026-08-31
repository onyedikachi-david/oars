# Development sshd for Oars integration tests (spec 02 §11, spec 03 §11,
# spec 07 §11). Fixed, well-known test credentials — NEVER use this image
# anywhere near real workloads:
#   root / oars-test-password                 (password auth leg)
#   /root/.ssh/id_ed25519 + oars-test-passphrase  (key auth leg)
#
# The config is written in full (not sed-patched) so the container is
# deterministic across openssh package revisions. Busybox tools (df, ps)
# also serve as the busybox variant for the spec 03 probe parsers.
#
# Spec 07 adds the deploy stack: git, node/npm, PM2, nginx (with the
# Debian-style sites-available → sites-enabled include), and a fixture git
# repo (/srv/fixture.git) whose app serves fixture.txt on port 3000. The
# fixture has no dependencies, so `npm install` runs offline.
#
# Spec 10 adds rclone (community repo) for the backups integration leg;
# the bucket side lives in a separate minio/minio container on the shared
# oars-dev-net network (see scripts/dev-sshd.sh).
#
# Spec 12 adds x11vnc/Xvfb, XFCE, and its test tools. The VNC integration test
# proves a real desktop, framebuffer, pointer, and keyboard path.

FROM alpine:3.20

RUN apk add --no-cache openssh bash zip unzip git nodejs npm nginx curl shadow sudo rclone \
        x11vnc xvfb xterm xdotool xfce4 dbus xprop \
    && ssh-keygen -A \
    && echo 'root:oars-test-password' | chpasswd \
    && mkdir -p /root/.ssh \
    && chmod 700 /root/.ssh \
    && ssh-keygen -t ed25519 -N 'oars-test-passphrase' -f /root/.ssh/id_ed25519 -q \
    && cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys \
    && chmod 600 /root/.ssh/authorized_keys \
    && mkdir -p /etc/sudoers.d \
    && printf 'root ALL=(ALL) ALL\ncarol ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/oars-test \
    && chmod 440 /etc/sudoers.d/oars-test \
    && printf 'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nSubsystem sftp internal-sftp\n' > /etc/ssh/sshd_config \
    && npm install -g pm2 --silent \
    && mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled \
    && printf 'user nginx;\nworker_processes 1;\nerror_log /var/log/nginx/error.log;\npid /run/nginx.pid;\nevents { worker_connections 1024; }\nhttp {\n    include /etc/nginx/mime.types;\n    default_type application/octet-stream;\n    access_log /var/log/nginx/access.log;\n    sendfile on;\n    include /etc/nginx/sites-enabled/*;\n}\n' > /etc/nginx/nginx.conf \
    && mkdir -p /srv/fixture \
    && printf '{"name":"oars-fixture","version":"1.0.0","scripts":{"start":"node server.js"},"dependencies":{}}\n' > /srv/fixture/package.json \
    && printf 'const http = require("http");\nconst fs = require("fs");\nconst path = require("path");\nconst port = process.env.PORT || 3000;\nconst text = fs.readFileSync(path.join(__dirname, "fixture.txt"), "utf8").trim();\nhttp.createServer(function (req, res) {\n  res.writeHead(200, { "Content-Type": "text/plain" });\n  res.end(text);\n}).listen(port, "127.0.0.1");\n' > /srv/fixture/server.js \
    && printf 'hello v1\n' > /srv/fixture/fixture.txt \
    && git -C /srv/fixture init -q -b main \
    && git -C /srv/fixture add -A \
    && git -C /srv/fixture -c user.email=test@oars.dev -c user.name=oars commit -q -m init \
    && git clone -q --bare /srv/fixture /srv/fixture.git

# Keep backup scheduler additions in their own layer so changes here do not
# invalidate the much larger desktop/deploy fixture layer above.
RUN apk add --no-cache dcron util-linux

EXPOSE 22
CMD ["/bin/sh", "-c", "/usr/sbin/crond && exec /usr/sbin/sshd -D"]
