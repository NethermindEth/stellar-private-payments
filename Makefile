# Output directory for trunk build artifacts; override with DIST_DIR=<path> to
# change where serve, build, and clean write/read compiled assets.
DIST_DIR ?= dist
BUILD_TESTS ?=
RELEASE ?=

.PHONY: release
release: RELEASE := 1
release: build

.PHONY: serve
serve: build
	# --dist $(DIST_DIR) overrides the dist_dir set in the trunk.toml
	# it's useful for generating a different serving path
	unset NO_COLOR && trunk serve --dist $(DIST_DIR)

.PHONY: build
build: install circuits-build wasm-witness wasm-state
	@echo "Building frontend with trunk..."
	unset NO_COLOR && trunk build --dist $(DIST_DIR) $(if $(RELEASE),--release)

.PHONY: wasm-state
wasm-state: install
	@echo "Building state WASM module..."
	@mkdir -p target/wasm-state
	wasm-pack build app/crates/state \
		--target web \
		--out-name state \
		--out-dir ../../../target/wasm-state \
		--release
	@rm -f target/wasm-state/.gitignore target/wasm-state/package.json 2>/dev/null || true

.PHONY: wasm-witness
wasm-witness: install
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
	$(if $(BUILD_TESTS),BUILD_TESTS=$(BUILD_TESTS)) cargo build -p circuits $(if $(RELEASE),--release)

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	@npm install --prefix app
	@rustup target add wasm32v1-none
	@command -v trunk >/dev/null 2>&1 || cargo install trunk --locked
	@command -v wasm-pack >/dev/null 2>&1 || cargo install wasm-pack --locked

.PHONY: clean
clean:
	trunk clean --dist $(DIST_DIR)
	cargo clean

.PHONY: doc
doc:
	cp -r assets docs/src/assets && mdbook build docs/ && rm -rf docs/src/assets && cargo doc --no-deps --workspace && cp -r target/doc docs/book/api && open docs/book/index.html
