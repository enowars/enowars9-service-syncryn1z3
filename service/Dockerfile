FROM gcc:13 AS build

WORKDIR /service

# Copy source files into the build container
COPY src .

# Compile using make
RUN make


# Use a suitable base-image.
FROM alpine

# Add glibc
RUN apk add gcompat

# Create a seperate user and chown new directories if necessary
RUN addgroup --system service
RUN adduser --system --ingroup service --uid 1000 service

# Create our mapped data volume endpoint
RUN mkdir /data/

# Copy our entrypoint.sh and make it executable
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Change the working directory.
WORKDIR /service/

# Copy the compiled binary from build stage
COPY --from=build /service/build/ptp-master .

WORKDIR /service/
# Expose the service's port
EXPOSE 319

# Run the service
ENTRYPOINT ["/entrypoint.sh"]
