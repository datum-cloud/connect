# Build context must be the repo root (connect/), not this directory —
# needed so this can COPY both connect-lib/ (Cargo workspace) and
# connect-plugin/ (Go module). See README.md in this directory.
#
#   docker build -f deploy/containerlab/vpc/Dockerfile -t connect-vpc-lab:latest .
#
# Runs as root inside the container (the default for `docker build`/`FROM`
# here) so it can create TUN devices and manage routes — that's ordinary
# container root, granted by containerlab's `cap-add: [NET_ADMIN]` on the
# node, not anything this image elevates itself to. Nothing in this image
# or the scripts it runs invokes `sudo`.

FROM rust:1-bookworm AS rust-build
WORKDIR /src
COPY connect-lib/ connect-lib/
WORKDIR /src/connect-lib
RUN cargo build --release -p datum-connect -p mock-galactic-router

FROM golang:1.25-bookworm AS go-build
WORKDIR /src
COPY connect-plugin/ connect-plugin/
WORKDIR /src/connect-plugin
RUN go build -o /out/datumctl-connect .

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping ca-certificates coreutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-build /src/connect-lib/target/release/datum-connect /usr/local/bin/datum-connect
COPY --from=rust-build /src/connect-lib/target/release/mock-galactic-router /usr/local/bin/mock-galactic-router
COPY --from=go-build /out/datumctl-connect /usr/local/bin/datumctl-connect
COPY deploy/containerlab/vpc/fake-credentials-helper.sh /usr/local/bin/fake-credentials-helper.sh
RUN chmod +x /usr/local/bin/fake-credentials-helper.sh

# datum-connect's shared startup path always builds a token source from
# these, even for the vpc subcommand, which doesn't call the Datum Cloud
# API for anything yet — see fake-credentials-helper.sh.
ENV DATUM_CONNECT_DIR=/var/lib/datum-connect
ENV DATUM_SESSION=lab-session
ENV DATUM_CREDENTIALS_HELPER=/usr/local/bin/fake-credentials-helper.sh
ENV DATUM_API_HOST=https://api.lab.invalid

CMD ["sleep", "infinity"]
