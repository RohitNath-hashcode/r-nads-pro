# Stage 1: Build stage
FROM rust:1.78-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libsqlite3-dev \
    pkg-config \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/r-nads
COPY . .

# Build release binary
RUN cargo build --release

# Stage 2: Runtime stage
FROM debian:bookworm-slim

# Install minimal runtime shared libraries
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libsqlite3-0 \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy release binary and configuration from builder
COPY --from=builder /usr/src/r-nads/target/release/r-nads .
COPY --from=builder /usr/src/r-nads/config.toml .

# Expose the SOC dashboard port
EXPOSE 8080

ENTRYPOINT ["./r-nads"]
