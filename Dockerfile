# Build Stage
FROM rust:1.79-bookworm as builder

WORKDIR /app

# Copy dependency files first to cache dependencies
COPY Cargo.toml Cargo.lock Justfile ./
# We need to copy crates to build properly
COPY crates ./crates
COPY bins ./bins

# Build Indexer
RUN cargo build --release -p umbra-indexer

# Build Relayer
RUN cargo build --release -p umbra-relayer

# Indexer Runtime Image
FROM debian:bookworm-slim as indexer
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/local/bin
COPY --from=builder /app/target/release/umbra-indexer .
CMD ["./umbra-indexer"]

# Relayer Runtime Image
FROM debian:bookworm-slim as relayer
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/local/bin
COPY --from=builder /app/target/release/umbra-relayer .
CMD ["./umbra-relayer"]
