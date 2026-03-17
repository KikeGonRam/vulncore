# ── Stage 1: Rust scanner ────────────────────────────
FROM rust:1.75-slim AS rust-builder
WORKDIR /build

RUN apt-get update -q && apt-get install -y -q pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY scanner/ ./scanner/
WORKDIR /build/scanner
RUN cargo build --release

# ── Stage 2: Go API ──────────────────────────────────
FROM golang:1.22-bookworm AS go-builder
WORKDIR /build

COPY api/go.mod api/go.sum ./
RUN go mod download

COPY api/ ./
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o vulncore-api .

# ── Stage 3: Final image ─────────────────────────────
FROM debian:bookworm-slim AS final

RUN apt-get update -q && apt-get install -y -q ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=rust-builder /build/scanner/target/release/vulncore-scanner ./
COPY --from=go-builder   /build/vulncore-api                             ./
COPY web/                ./web/
COPY configs/            ./configs/

RUN mkdir -p /data && useradd -r -s /bin/false vulncore && chown -R vulncore:vulncore /app /data

USER vulncore

ENV VULNCORE_SCANNER_PATH=/app/vulncore-scanner
ENV VULNCORE_DB_PATH=/data/vulncore.db
ENV VULNCORE_PORT=8080
ENV VULNCORE_ENV=production

EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -sf http://localhost:8080/api/health || exit 1

CMD ["./vulncore-api"]