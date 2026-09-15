ARG BASE=ubuntu@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 iproute2 iptables ocserv gnutls-bin dnsmasq openssl curl procps dbus-x11 gnome-keyring libsecret-tools libglib2.0-bin xvfb xauth x11-apps xdotool openbox fonts-dejavu-core zenity xdg-desktop-portal xdg-desktop-portal-gtk make xz-utils ca-certificates libwebkit2gtk-4.1-0 libayatana-appindicator3-1 libsecret-1-0 libgnutls30t64 libxml2-16 libstoken1 libpcsclite1 libpskc0 libp11-kit0 libproxy1v5 libgmp10 libnettle8t64 libhogweed6t64 && dpkg-query -W > /lab-packages.txt && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:901d83a15520b80e117aeca8cb6f5b70ceb205ba050a638d45cebcf304df729b https://github.com/NetworkConfiguration/openresolv/releases/download/v3.17.4/openresolv-3.17.4.tar.xz /tmp/openresolv.tar.xz
RUN tar -xJf /tmp/openresolv.tar.xz -C /tmp && cd /tmp/openresolv-3.17.4 && ./configure --prefix=/usr --sysconfdir=/etc --sbindir=/usr/sbin --libexecdir=/usr/libexec/resolvconf --rundir=/run && make install && install -Dm644 LICENSE /usr/share/doc/openresolv/LICENSE && rm -rf /tmp/openresolv-3.17.4 /tmp/openresolv.tar.xz
RUN if getent passwd 1000; then usermod -l lab -d /home/lab -m "$(getent passwd 1000 | cut -d: -f1)"; else useradd --create-home --uid 1000 lab; fi
RUN mkdir -p /opt/lab /evidence /run/openconnect-gui /usr/libexec/openconnect-gui && chmod 755 /run/openconnect-gui
COPY runtime.py verify_keyring.py /opt/lab/
ENTRYPOINT ["python3", "/opt/lab/runtime.py", "supervise"]
