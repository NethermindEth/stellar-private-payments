.PHONY: serve
serve: $(DIST_DIR)
	trunk serve

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	npm install --prefix app
	cargo install trunk --locked

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