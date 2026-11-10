# Build the React UI first, then the Rust binary with the UI embedded.
FROM node:22-bookworm-slim AS web
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY --from=web /app/web/dist ./web/dist
RUN cargo build --release -p quark-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /data quark \
    && mkdir -p /downloads \
    && chown quark:quark /downloads

COPY --from=build /src/target/release/quark-server /usr/local/bin/quark-server

USER quark
WORKDIR /data
EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/quark-server"]
CMD ["--listen", "0.0.0.0:8787", "--data-dir", "/data", "--download-root", "/downloads"]
