# Output directory for trunk build artifacts; override with DIST_DIR=<path> to
# change where serve, build, and clean write/read compiled assets.
DIST_DIR ?= dist
PUBLIC_URL ?= /
PORT ?=
TESTS ?=
REGEN_KEYS ?=
GRAPHS ?=
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
	trunk serve --dist $(DIST_DIR) --public-url $(PUBLIC_URL) $(if $(PORT),--port $(PORT),)

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

.PHONY: circuits
circuits:
	@echo "Building circuits (this may take a while)..."
	cargo run -p circuit-compiler --bin circuit-compiler --release -- compile \
		--circuits $(CURDIR)/circuits \
		--out $(CURDIR)/target/circuits-artifacts $(if $(TESTS),--tests) $(if $(REGEN_KEYS),--regen-keys) $(if $(GRAPHS),--graphs)

.PHONY: circuits-lock
circuits-lock: circuits
	sh $(CURDIR)/deployments/scripts/circuit-artifacts.sh lock $(VERSION)

.PHONY: circuits-verify
circuits-verify: circuits
	sh $(CURDIR)/deployments/scripts/circuit-artifacts.sh verify

# Runs the integration-tests
.PHONY: integration-tests
integration-tests:
	bash $(CURDIR)/integration-tests/run.sh

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
	@echo "Building stellar-private-payments-web with debug logs (release-with-logs)..."
	@WASM_PROFILE=release-with-logs npm run build --prefix sdk/web
	@echo "release-with-logs" > sdk/web/.trunk-wasm-profile

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	@npm install --prefix app
	@npm install --prefix sdk/web
	@rustup target add wasm32v1-none
	@command -v trunk >/dev/null 2>&1 || cargo install trunk --locked

# App browser e2e suite (drives a real Freighter extension). Starts a local
# network + `make serve`, provisions the Freighter profile if needed
# (E2E_SKIP_SETUP=1 skips that), runs the tests, and tears down.
#
# integration-tests-app-setup just provisions the profile, running no tests.
.PHONY: integration-tests-app-setup
integration-tests-app-setup:
	bash integration-tests-app/scripts/serve-and-run.sh -- true

.PHONY: integration-tests-app-e2e
integration-tests-app-e2e:
	bash integration-tests-app/scripts/serve-and-run.sh

# Smoke subset: connect, signature rejection, and a deposit+transfer round
# trip — the same three the CI smoke job runs.
.PHONY: integration-tests-app-smoke
integration-tests-app-smoke:
	bash integration-tests-app/scripts/serve-and-run.sh \
		integration-tests-app/tests/01-connect.mjs \
		integration-tests-app/tests/03-rejection.mjs \
		integration-tests-app/tests/05-deposit-transfer.mjs

.PHONY: clean
clean:
	trunk clean --dist $(DIST_DIR)
	rm -rf sdk/web/dist sdk/web/.trunk-wasm-profile
	cargo clean

.PHONY: doc
doc:
	mdbook build docs/ && cargo doc --no-deps --workspace && cp -r target/doc docs/book/api && open docs/book/index.html
