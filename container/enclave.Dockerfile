FROM --platform=linux/amd64 rust:1.67.0 AS chef
RUN apt-get update && apt-get install -y cmake pkg-config libssl-dev git clang lib32z1
RUN cargo install cargo-chef --locked

WORKDIR app

FROM chef as planner
COPY . .

# https://github.com/rust-lang/cargo/issues/3381#issuecomment-308460530
RUN eval `ssh-agent -s` && ssh-add && \
    cargo chef prepare --recipe-path recipe.json

FROM chef as builder
COPY --from=planner /app/recipe.json recipe.json

RUN eval `ssh-agent -s` && ssh-add && \
  cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release --locked

FROM --platform=linux/amd64 debian:bullseye-slim as runtime
RUN apt-get update && apt-get install -y openssl
WORKDIR app
COPY --from=builder /app/target/release/enclave-issue /usr/local/bin

ENTRYPOINT ["/usr/local/bin/enclave-issue"]
