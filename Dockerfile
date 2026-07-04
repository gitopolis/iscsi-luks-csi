FROM clux/muslrust:stable AS builder
ARG TARGET
ARG VERSION

WORKDIR /usr/src/app

COPY src src
COPY proto proto
COPY build.rs build.rs
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

RUN cargo install cargo-edit --locked
RUN cargo set-version "${VERSION}"
RUN cargo build --target=${TARGET} --release --locked --bins

FROM debian:bookworm-slim
ARG TARGET

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cryptsetup \
        e2fsprogs \
        mount \
        open-iscsi \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/${TARGET}/release/iscsi-luks-csi /

ENTRYPOINT ["/iscsi-luks-csi"]
