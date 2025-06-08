FROM rust:1.85 AS builder
WORKDIR /usr/src/upstream-test-server
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/upstream-test-server/target/release/upstream-test-server /usr/local/bin/upstream-test-server
EXPOSE 8080
CMD ["upstream-test-server"]
