FROM microdebian/bookworm AS build

WORKDIR /service

# Install build dependencies
RUN apt-get update && apt-get install -y build-essential cmake pkg-config libcap2-bin libuv1-dev libssl-dev libsqlite3-dev libwebsockets-dev libcjson-dev && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy sources
COPY CMakeLists.txt .
COPY src src

# Compile using cmake
RUN cmake -S . -B build && cmake --build build
RUN setcap CAP_NET_BIND_SERVICE+ep build/bin/syncryn1z3


# Use a suitable base-image
FROM microdebian/bookworm

# Add runtime dependencies 
RUN apt-get update && apt-get install -y tini gosu adduser python3 openssl libuv1 libsqlite3-0 libwebsockets17 libwebsockets-evlib-uv libcjson1 gdbserver && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create a seperate user and chown new directories if necessary
RUN addgroup --system service
RUN adduser --system --ingroup service --uid 1001 service

# Create our mapped data volume endpoint
RUN mkdir /data/

# Copy our entrypoint.sh and make it executable
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Change the working directory.
WORKDIR /service/

# Copy the compiled binary from build stage
COPY --from=build /service/build/bin/syncryn1z3 .

# Copy cleanup script
COPY cleanup.py cleanup.py

WORKDIR /service/

EXPOSE 319/udp
EXPOSE 320/udp

# Run the service
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
