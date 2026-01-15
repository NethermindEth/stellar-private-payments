.PHONY: serve
serve: install
	trunk serve

.PHONY: build
build: install
	@echo "Building frontend with trunk..."
	trunk build

.PHONY: circuits-build
circuits-build:
	@echo "Building circuits (this may take a while)..."
	BUILD_TESTS=1 cargo build -p circuits

.PHONY: install
install:
	@echo "Installing frontend dependencies..."
	npm install --prefix app
	cargo install trunk --locked

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf dist
