# Use a suitable base-image
FROM ubuntu:noble

# Add runtime dependencies 
RUN apt-get update && apt-get install -y tini adduser iproute2 linuxptp && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create our mapped data volume endpoint
RUN mkdir /data/

COPY src /checker

# Copy our entrypoint.sh and make it executable
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Change the working directory.
WORKDIR /checker/

#EXPOSE 319

# Run the service
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
