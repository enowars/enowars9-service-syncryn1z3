FROM debian:bookworm-slim AS build

WORKDIR /service_hidden

# Install build dependencies
RUN apt-get update && apt-get install -y build-essential cmake

# Copy sources
COPY CMakeLists.txt .
COPY src src

# Compile using cmake
RUN cmake -S . -B build && cmake --build build
RUN mkdir -p /fakeroot/lib/$(gcc -dumpmachine)
RUN mv build/src/libtiming.so /fakeroot/lib/$(gcc -dumpmachine)

# Use a suitable base-image
FROM debian:bookworm-slim

COPY --from=build /fakeroot/lib /lib
