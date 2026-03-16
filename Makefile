# VulnCore Makefile
# Builds both Rust scanner and Go API

BINARY_SCANNER = vulncore-scanner
BINARY_API     = vulncore-api
DIST_DIR       = dist
DATA_DIR       = data

.PHONY: all build build-scanner build-api clean run dev install deps check test zip

all: build

## ── Dependencies ────────────────────────────────────────────
deps:
	@echo "→ Installing Go dependencies..."
	cd api && go mod tidy
	@echo "→ Checking Rust toolchain..."
	rustup update stable
	@echo "✓ Dependencies ready"

## ── Build ───────────────────────────────────────────────────
build: build-scanner build-api
	@echo ""
	@echo "✓ VulnCore built successfully"
	@echo "  Scanner : $(DIST_DIR)/$(BINARY_SCANNER)"
	@echo "  API     : $(DIST_DIR)/$(BINARY_API)"

build-scanner:
	@echo "→ Building Rust scanner..."
	cd scanner && cargo build --release
	mkdir -p $(DIST_DIR)
	cp scanner/target/release/$(BINARY_SCANNER) $(DIST_DIR)/

build-api:
	@echo "→ Building Go API..."
	cd api && go build -ldflags="-s -w" -o ../$(DIST_DIR)/$(BINARY_API) .

## ── Run ─────────────────────────────────────────────────────
run: build
	@mkdir -p $(DATA_DIR)
	@echo "→ Starting VulnCore on http://localhost:8080"
	VULNCORE_SCANNER_PATH=./$(DIST_DIR)/$(BINARY_SCANNER) \
	  ./$(DIST_DIR)/$(BINARY_API)

dev:
	@mkdir -p $(DATA_DIR)
	@echo "→ Dev mode: starting API (scanner must be pre-built)"
	VULNCORE_SCANNER_PATH=./$(DIST_DIR)/$(BINARY_SCANNER) \
	GIN_MODE=debug \
	  cd api && go run .

## ── Test ────────────────────────────────────────────────────
test:
	@echo "→ Running Rust tests..."
	cd scanner && cargo test
	@echo "→ Running Go tests..."
	cd api && go test ./...

## ── Static analysis ─────────────────────────────────────────
check:
	cd scanner && cargo clippy -- -D warnings
	cd api     && go vet ./...

## ── Install (system-wide) ───────────────────────────────────
install: build
	@echo "→ Installing to /usr/local/bin/"
	install -m 755 $(DIST_DIR)/$(BINARY_SCANNER) /usr/local/bin/
	install -m 755 $(DIST_DIR)/$(BINARY_API)     /usr/local/bin/
	@echo "✓ Installed"

## ── Package ─────────────────────────────────────────────────
zip: build
	@echo "→ Packaging release..."
	mkdir -p release
	cp -r $(DIST_DIR) web configs release/
	cp README.md release/ 2>/dev/null || true
	cd release && zip -r ../vulncore-release.zip .
	rm -rf release
	@echo "✓ vulncore-release.zip created"

## ── Cleanup ─────────────────────────────────────────────────
clean:
	cd scanner && cargo clean
	rm -rf $(DIST_DIR) $(DATA_DIR)/vulncore.db
	@echo "✓ Clean"
