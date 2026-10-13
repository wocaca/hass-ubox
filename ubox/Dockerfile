ARG BUILD_FROM=python:3.12-slim-bookworm
FROM ${BUILD_FROM}

ENV LANG=C.UTF-8 \
    APP=/app \
    LD_LIBRARY_PATH=/app/bin

# ffmpeg for H.265 -> MJPEG; qemu-user-static for the ARM64 rehost engine;
# iptables for the relay/direct transport switch (needs NET_ADMIN).
# Only qemu-aarch64-static is kept (rest of the package is purged).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg ca-certificates qemu-user-static iptables \
 && mkdir -p /tmp/qemusave \
 && cp /usr/bin/qemu-aarch64-static /tmp/qemusave/ \
 && apt-get purge -y qemu-user-static \
 && apt-get autoremove -y --purge \
 && mv /tmp/qemusave/qemu-aarch64-static /usr/bin/qemu-aarch64-static \
 && rm -rf /tmp/qemusave /var/lib/apt/lists/*

WORKDIR /app
COPY rootfs /app/rootfs
COPY bin /app/bin
COPY run.py /app/run.py
RUN chmod +x /app/bin/rehost \
 && cp /usr/bin/qemu-aarch64-static /app/bin/qemu-aarch64-static \
 && /app/bin/qemu-aarch64-static --version

EXPOSE 8089
CMD ["python3", "/app/run.py"]
