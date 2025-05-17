FROM python:3.9-bookworm AS BUILD

WORKDIR /checker

# Install build dependencies
RUN apt-get update && apt-get install -y gcc && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install cffi

# Copy sources
COPY checker/src src
COPY service/src ../service/src
RUN cd src && python3 build.py


# Use a suitable base-image
FROM python:3.9-bookworm

WORKDIR /checker

# Install runtime dependencies
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Add checker user
RUN useradd -ms /bin/bash -u 1000 checker

COPY checker/requirements.txt .

USER checker
RUN python3 -m pip install -r requirements.txt

COPY checker/src .
COPY --from=build checker/src/*.so .

ENTRYPOINT [ "/home/checker/.local/bin/gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]
