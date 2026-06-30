# Output directory for trunk build artifacts; override with DIST_DIR=<path> to
# change where serve, build, and clean write/read compiled assets.
DIST_DIR ?= dist
PUBLIC_URL ?= /
BUILD_TESTS ?=
RELEASE ?=

.PHONY: release
release: RELEASE := 1
release: build

.PHONY: serve
serve: install circuits-build
	# --dist $(DIST_DIR) overrides the dist_dir set in the trunk.toml
	# it's useful for generating a different serving path
	unset NO_COLOR && export PUBLIC_URL=$(PUBLIC_URL) && \
	trunk serve --dist $(DIST_DIR) --public-url $(PUBLIC_URL)

.PHONY: build
build: install circuits-build
	@echo "Building frontend with trunk..."
	unset NO_COLOR && export PUBLIC_URL=$(PUBLIC_URL) && \
	trunk build --dist $(DIST_DIR) $(if $(RELEASE),--release) --public-url $(PUBLIC_URL)

.PHONY: circuits-build
circuits-build:
	@echo "Building circuits (this may take a while)..."
	$(if $(BUILD_TESTS),BUILD_TESTS=$(BUILD_TESTS)) cargo build -p circuits $(if $(RELEASE),--release)

# Regenerate the committed circom-witness-rs graphs. Requires circom 2.2.3 and a C++ toolchain on PATH.
#
# The first build injects the bbf_* black-box hints into the in-tree circomlib;
# `cargo clean -p circom-witness-rs` then forces the witness generator to be
# recompiled from that hinted circomlib before REGEN_GRAPHS runs build_witness().
.PHONY: witness-graphs
witness-graphs:
	@echo "Regenerating witness graphs (requires circom and a C++ toolchain)..."
	cargo build -p circuits
	cargo clean -p circom-witness-rs
	REGEN_GRAPHS=1 cargo build -p circuits

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	@npm install --prefix app
	@rustup target add wasm32v1-none
	@command -v trunk >/dev/null 2>&1 || cargo install trunk --locked

.PHONY: clean
clean:
	trunk clean --dist $(DIST_DIR)
	cargo clean

.PHONY: doc
doc:
	mdbook build docs/ && cargo doc --no-deps --workspace && cp -r target/doc docs/book/api && open docs/book/index.html
