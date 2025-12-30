APP_DIR = ./app
DIST_DIR = ./dist
INPUT_CSS = $(APP_DIR)/css/src.css
OUTPUT_CSS = $(DIST_DIR)/css/app.css
SERVED_OUTPUT_CSS = $(APP_DIR)/css/app.css
CONFIG = $(APP_DIR)/tailwind.config.js
ESBUILD = ./app/node_modules/.bin/esbuild

.PHONY: all
all: dist

# Build the app distribution for static hosting
.PHONY: dist
dist: createdist bundle

# install required frontend deps
.PHONY: bundle
bundle: html css js assets wasm circuits-artifacts witness-module proving-keys

.PHONY: css
css:
	@echo "Packing CSS"
	npx --prefix $(APP_DIR) tailwindcss -i $(INPUT_CSS) -o $(OUTPUT_CSS) --minify

.PHONY: js
js:	wasm witness-module
	@echo "Packing JS"
	mkdir -p $(DIST_DIR)/js
	# Bundle main app (excludes witness module and prover for separate loading)
	$(ESBUILD) $(APP_DIR)/js/app.js --bundle --outfile=$(DIST_DIR)/js/app.js --format=esm \
		--external:./witness/* --external:../../dist/js/prover/*
	# Copy bridge and worker (they import witness/prover dynamically)
	cp $(APP_DIR)/js/bridge.js $(DIST_DIR)/js/
	cp $(APP_DIR)/js/worker.js $(DIST_DIR)/js/

.PHONY: assets
assets:
	cp -r app/assets $(DIST_DIR)/assets

.PHONY: html
html:
	@echo "Packing HTML"
	cp -r app/*.html $(DIST_DIR)/

.PHONY: createdist
createdist:
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)

.PHONY: serve
serve: $(DIST_DIR)
	@echo "Starting static server"
	python3 $(APP_DIR)/devserver.py

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	npm install --prefix app
	cargo install wasm-pack

.PHONY: wasm
wasm:
	@echo "Building prover WASM (Apache-2.0)"
	wasm-pack build app/crates/prover-wasm --out-name prover --no-opt --target web --no-pack --no-typescript --out-dir ../../../$(DIST_DIR)/js/prover
	rm -rf $(DIST_DIR)/js/prover/.gitignore

.PHONY: circuits-artifacts
circuits-artifacts:
	@echo "Copying circuit artifacts for witness generation"
	mkdir -p $(DIST_DIR)/circuits
	@if [ -d "circuits/src/tmp" ]; then \
		for dir in circuits/src/tmp/*_js; do \
			if [ -d "$$dir" ]; then \
				circuit_name=$$(basename $$dir _js); \
				cp "$$dir/$$circuit_name.wasm" "$(DIST_DIR)/circuits/" 2>/dev/null || true; \
			fi \
		done; \
		cp circuits/src/tmp/*.r1cs "$(DIST_DIR)/circuits/" 2>/dev/null || true; \
	fi
	@echo "Circuit artifacts copied"

.PHONY: proving-keys
proving-keys:
	@echo "Copying proving/verifying keys for frontend"
	mkdir -p $(DIST_DIR)/keys
	cp scripts/testdata/*_proving_key.bin $(DIST_DIR)/keys/ 2>/dev/null || true
	cp scripts/testdata/*_vk.json $(DIST_DIR)/keys/ 2>/dev/null || true
	@echo "Keys copied to $(DIST_DIR)/keys/"

.PHONY: witness-module
witness-module:
	@echo "Copying witness module (GPL-3.0)"
	mkdir -p $(DIST_DIR)/js/witness
	cp $(APP_DIR)/js/witness/index.js $(DIST_DIR)/js/witness/
	cp $(APP_DIR)/js/witness/witness_calculator.js $(DIST_DIR)/js/witness/
	cp $(APP_DIR)/js/witness/README.md $(DIST_DIR)/js/witness/ 2>/dev/null || true