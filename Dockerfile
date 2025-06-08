FROM rust@sha256:25038aa450210c53cf05dbf7b256e1df1ee650a58bb46cbc7d6fa79c1d98d083 AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y musl musl-dev
RUN rustup target add x86_64-unknown-linux-musl
COPY . /build
RUN cargo build --release --target x86_64-unknown-linux-musl && \
    cp /build/target/x86_64-unknown-linux-musl/release/nephelite /build/nephelite

FROM scratch
COPY --from=builder /build/nephelite /nephelite
USER 1000
ENTRYPOINT [ "/nephelite" ]