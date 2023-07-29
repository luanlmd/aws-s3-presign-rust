FROM rust:1.70.0-alpine3.18

RUN apk add --no-cache musl-dev
RUN cargo install cargo-watch

WORKDIR /src

CMD ["cargo", "watch", "-x", "test -- --show-output"]