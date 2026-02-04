DIST_DIR ?= dist
BUILD_TESTS ?=

.PHONY: serve
serve: build
	unset NO_COLOR && trunk serve --dist $(DIST_DIR)

.PHONY: build
build: circuits-build wasm-witness install
	@echo "Building frontend with trunk..."
	unset NO_COLOR && trunk build  --dist $(DIST_DIR)

.PHONY: wasm-witness
wasm-witness:
	@echo "Building witness WASM module..."
	@mkdir -p target/wasm-witness
	wasm-pack build app/crates/witness \
		--target web \
		--out-name witness \
		--out-dir ../../../target/wasm-witness \
		--release
	@rm -f target/wasm-witness/.gitignore target/wasm-witness/package.json 2>/dev/null || true

.PHONY: circuits-build
circuits-build:
	@echo "Building circuits (this may take a while)..."
	$(if $(BUILD_TESTS),BUILD_TESTS=$(BUILD_TESTS)) OUT_DIR=$(DIST_DIR) cargo build -p circuits

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	@npm install --prefix app
	@command -v trunk >/dev/null 2>&1 || cargo install trunk --locked
	@command -v wasm-pack >/dev/null 2>&1 || cargo install wasm-pack --locked

.PHONY: clean
clean:
	trunk clean --dist $(DIST_DIR)
	cargo clean
