FROM debian:bookworm-slim AS build

WORKDIR /service

# Install build dependencies
RUN apt-get update && apt-get install -y build-essential cmake libcap2-bin libsqlite3-dev && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy sources
COPY CMakeLists.txt .
COPY src src

# Compile using cmake
RUN cmake -S . -B build && cmake --build build
RUN setcap CAP_NET_BIND_SERVICE+ep build/bin/ptp-master


# Use a suitable base-image
FROM debian:bookworm-slim

# Add runtime dependencies 
RUN apt-get update && apt-get install -y tini gosu adduser libsqlite3-0 && apt-get clean && rm -rf /var/lib/apt/lists/*

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
COPY --from=build /service/build/bin/ptp-master .

WORKDIR /service/

EXPOSE 319/udp
EXPOSE 320/udp

# Run the service
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
