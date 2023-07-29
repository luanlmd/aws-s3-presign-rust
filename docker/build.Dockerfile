FROM rust:1.70.0-alpine3.18

RUN apk add --no-cache musl-dev

ADD signer /app/
WORKDIR /app

RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build