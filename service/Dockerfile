FROM debian:bookworm-slim AS build

WORKDIR /service

# Install build dependencies
RUN apt-get update && apt-get install -y build-essential cmake pkg-config libcap2-bin libuv1-dev libssl-dev libsqlite3-dev libwebsockets-dev libb64-dev && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY CMakeLists.txt .
COPY src src
COPY lib lib

# Compile using cmake
RUN cmake -S . -B build && cmake --build build
RUN setcap CAP_NET_BIND_SERVICE+ep build/bin/syncryn1z3


# Suitable base image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y tini gosu adduser python3 openssl libuv1 libsqlite3-0 libwebsockets17 libwebsockets-evlib-uv libb64-0d && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN addgroup --system service
RUN adduser --system --ingroup service --uid 1001 service

RUN mkdir /data/

# Setup entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

WORKDIR /service/

# Setup binaries
COPY --from=build /service/build/bin/syncryn1z3 .
COPY lib/libjson.so /usr/local/lib/json/
RUN echo "/usr/local/lib/json" > /etc/ld.so.conf.d/json.conf && ldconfig

# Copy cleanup script
COPY cleanup.py cleanup.py

WORKDIR /service/

EXPOSE 319/udp
EXPOSE 320/udp

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
