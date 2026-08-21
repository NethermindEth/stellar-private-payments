# Output directory for trunk build artifacts; override with DIST_DIR=<path> to
# change where serve, build, and clean write/read compiled assets.
DIST_DIR ?= dist
PUBLIC_URL ?= /
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

.PHONY: circuits
circuits:
	@echo "Building circuits (this may take a while)..."
	cargo run -p circuit-compiler --bin circuit-compiler --release -- compile \
		--circuits $(CURDIR)/circuits \
		--out $(CURDIR)/target/circuits-artifacts $(if $(TESTS),--tests) $(if $(REGEN_KEYS),--regen-keys) $(if $(GRAPHS),--graphs)

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

# Freighter browser e2e suite. Both targets start `make serve`, wait for it,
# and stop it again when the tests finish — pass or fail, and on Ctrl-C.
# A server already listening on the port is reused and left running.
#
# Anything missing is set up first (testnet accounts, the pinned extension,
# node_modules, the Freighter profile snapshot). Already-set-up checkouts pay
# only a few stat calls. First-time setup provisions the profile HEADED and
# needs a display. E2E_SKIP_SETUP=1 skips the check.
#
# These run against live testnet and spend real testnet XLM.
#
# An APP_URL already exported in the shell is replaced with the served one:
# these targets own the server, so a stale export cannot silently point the
# suite at a dead port. Pass --url to target something else on purpose, e.g.
#   bash e2e-freighter/scripts/serve-and-run.sh --url https://example.com
#
# APPROVE=human HEADFUL=1 approves each Freighter prompt by hand.
.PHONY: freighter-setup
freighter-setup:
	bash scripts/e2e-ensure-setup.sh

.PHONY: freighter-e2e
freighter-e2e: freighter-setup
	bash e2e-freighter/scripts/serve-and-run.sh

# Smoke subset: connect, signature rejection, and a deposit+transfer round
# trip — the same three the CI smoke job runs.
.PHONY: freighter-smoke
freighter-smoke: freighter-setup
	bash e2e-freighter/scripts/serve-and-run.sh \
		e2e-freighter/tests/01-connect.mjs \
		e2e-freighter/tests/03-rejection.mjs \
		e2e-freighter/tests/05-deposit-transfer.mjs

# Salvage an e2e setup broken by a redeploy: stale contracts in the CLI's
# compiled-in config, accounts registered in a registry nothing points at,
# wallet-DB state for pools that no longer exist. Rebuilds spp, re-registers
# the EXISTING accounts (keypairs and funding kept), prunes dead generations,
# then re-runs the preflight to confirm.
#
# PROFILE=1 also rebuilds the Freighter profile snapshot (headed, ~2 min).
# DRY_RUN=1 prints the steps without running them.
.PHONY: freighter-repair
freighter-repair:
	bash scripts/e2e-repair.sh $(if $(PROFILE),--profile) $(if $(DRY_RUN),--dry-run)

.PHONY: clean
clean:
	trunk clean --dist $(DIST_DIR)
	rm -rf sdk/web/dist sdk/web/.trunk-wasm-profile
	cargo clean

.PHONY: doc
doc:
	mdbook build docs/ && cargo doc --no-deps --workspace && cp -r target/doc docs/book/api && open docs/book/index.html
