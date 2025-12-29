.PHONY: serve
serve: $(DIST_DIR)
	trunk serve

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	npm install --prefix app
	cargo install trunk --locked
