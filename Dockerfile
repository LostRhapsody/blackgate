FROM rust:1.85 AS builder
WORKDIR /usr/src/blackgate
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libsqlite3-0 libssl3 curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/blackgate/target/release/blackgate /usr/local/bin/blackgate
COPY --from=builder /usr/src/blackgate/blackgate.db /blackgate.db
COPY setup-routes.sh /setup-routes.sh
RUN chmod +x /setup-routes.sh
CMD ["/setup-routes.sh"]