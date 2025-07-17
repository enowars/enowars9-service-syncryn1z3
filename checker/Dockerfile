FROM pypy:3.11-bookworm AS BUILD

WORKDIR /checker

# Install build dependencies
RUN apt-get update && apt-get install -y gcc && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pypy3 -m pip install cffi setuptools

# Copy sources
COPY src src
RUN cd src && pypy3 build.py


# Use a suitable base-image
FROM pypy:3.11-bookworm

WORKDIR /checker

# Install runtime dependencies
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Add checker user
RUN useradd -ms /bin/bash -u 1000 checker

COPY requirements.txt .

USER checker
RUN pypy3 -m pip install -r requirements.txt

COPY src .
COPY --from=build checker/src/*.so .

ENTRYPOINT [ "/home/checker/.local/bin/gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]
