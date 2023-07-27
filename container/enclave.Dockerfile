FROM --platform=linux/amd64 rust:1.67.0 AS builder
RUN apt-get update && apt-get install -y cmake pkg-config libssl-dev git clang

WORKDIR app
COPY . .
RUN cargo build --release --locked

FROM --platform=linux/amd64 debian:bullseye-slim as runtime
RUN apt-get update && apt-get install -y openssl chrony
WORKDIR app
COPY --from=builder /app/target/release/enclave-issue /usr/local/bin
COPY --from=builder /app/run.sh /app

ENTRYPOINT ["/app/run.sh"]
