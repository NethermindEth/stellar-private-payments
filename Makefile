# Output directory for trunk build artifacts; override with DIST_DIR=<path> to
# change where serve, build, and clean write/read compiled assets.
DIST_DIR ?= dist
PUBLIC_URL ?= /
BUILD_TESTS ?=
RELEASE ?=
# LOGS=1 builds the WASM SDK with verbose diagnostic logging enabled
# (WASM_PROFILE=release-with-logs) instead of the quiet, privacy-first default.
# e.g. `make serve LOGS=1`, `make build LOGS=1`.
LOGS ?=

.PHONY: release
release: RELEASE := 1
release: build

.PHONY: serve
serve: install $(if $(LOGS),sdk-web-build-debug,sdk-web-build)
	@echo "Serving frontend with trunk$(if $(LOGS), (debug logs enabled),)..."
	# --dist $(DIST_DIR) overrides the dist_dir set in the trunk.toml
	# it's useful for generating a different serving path
	unset NO_COLOR && export PUBLIC_URL=$(PUBLIC_URL) && \
	trunk serve --dist $(DIST_DIR) --public-url $(PUBLIC_URL)

# Alias: `make serve-debug` == `make serve LOGS=1`.
.PHONY: serve-debug
serve-debug:
	@$(MAKE) serve LOGS=1

.PHONY: build
build: install $(if $(LOGS),sdk-web-build-debug,sdk-web-build)
	@echo "Building frontend with trunk$(if $(LOGS), (debug logs enabled),)..."
	unset NO_COLOR && export PUBLIC_URL=$(PUBLIC_URL) && \
	trunk build --dist $(DIST_DIR) $(if $(RELEASE),--release) --public-url $(PUBLIC_URL)

# Alias: `make build-debug` == `make build LOGS=1`.
.PHONY: build-debug
build-debug:
	@$(MAKE) build LOGS=1

.PHONY: circuits-build
circuits-build:
	@echo "Building circuits (this may take a while)..."
	$(if $(BUILD_TESTS),BUILD_TESTS=$(BUILD_TESTS)) cargo build -p circuits $(if $(RELEASE),--release)

# Production stems for circom-witness-rs graph regen (keep in sync with SDK).
WITNESS_GRAPH_STEMS := \
	policy_tx_2_2.circom \
	policy_tx_2_2_A.circom \
	policy_tx_2_2_B.circom \
	policy_tx_2_2_AB.circom \
	selectiveDisclosure_1.circom \
	selectiveDisclosure_2.circom \
	selectiveDisclosure_3.circom \
	selectiveDisclosure_4.circom

# Regenerates committed circom-witness-rs graphs under
# deployments/testnet/circuit_keys/*.graph.bin. Requires Circom CLI matching
# circuits/circom.lock and a C++ toolchain. One stem per cargo build (single-
# circuit circom-witness-rs); clean between stems so WITNESS_CPP is re-read.
.PHONY: witness-graphs
witness-graphs:
	@echo "Regenerating witness graphs (Circom $$(tr -d '[:space:]' < circuits/circom.lock))..."
	@for entry in $(WITNESS_GRAPH_STEMS); do \
		stem=$${entry%.circom}; \
		echo "===== $$stem ====="; \
		cargo clean -p circom-witness-rs >/dev/null; \
		CIRCOM_LIBRARY_PATH="$(CURDIR)/circuits/src" \
		WITNESS_CPP="$(CURDIR)/circuits/src/$$entry" \
		cargo build -p circuits --features regen-graph || exit 1; \
	done
	@echo "Done. Graphs in deployments/testnet/circuit_keys/"

# Both targets record the built profile in sdk/web/.trunk-wasm-profile so a
# subsequent `trunk serve`/`trunk build` (which `serve`/`build` invoke) sees a
# matching marker and skips its own redundant rebuild.
.PHONY: sdk-web-build
sdk-web-build:
	@echo "Building browser SDK (npm: stellar-private-payments → sdk/web/dist)..."
	@npm run build --prefix sdk/web
	@echo "release" > sdk/web/.trunk-wasm-profile

.PHONY: sdk-web-build-debug
sdk-web-build-debug:
	@echo "Building stellar-private-payments-sdk-web with debug logs (release-with-logs)..."
	@WASM_PROFILE=release-with-logs npm run build --prefix sdk/web
	@echo "release-with-logs" > sdk/web/.trunk-wasm-profile

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	@npm install --prefix app
	@npm install --prefix sdk/web
	@rustup target add wasm32v1-none
	@command -v trunk >/dev/null 2>&1 || cargo install trunk --locked

.PHONY: clean
clean:
	trunk clean --dist $(DIST_DIR)
	rm -rf sdk/web/dist sdk/web/.trunk-wasm-profile
	cargo clean

.PHONY: doc
doc:
	mdbook build docs/ && cargo doc --no-deps --workspace && cp -r target/doc docs/book/api && open docs/book/index.html
