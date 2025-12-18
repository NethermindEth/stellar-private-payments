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
bundle: html css js assets wasm

.PHONY: css
css:
	@echo "Packing CSS"
	npx --prefix $(APP_DIR) tailwindcss -i $(INPUT_CSS) -o $(OUTPUT_CSS) --minify

.PHONY: js
js:	wasm
	@echo "Packing JS"
	mkdir -p $(DIST_DIR)/js
	$(ESBUILD) $(APP_DIR)/js/app.js --bundle --outfile=$(DIST_DIR)/js/app.js --format=esm
	$(ESBUILD) $(APP_DIR)/js/worker.js --bundle --outfile=$(DIST_DIR)/js/worker.js --format=esm

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
	wasm-pack build app --out-name prover --no-opt --target web --no-pack --no-typescript --out-dir ../$(DIST_DIR)/js
	rm -rf $(DIST_DIR)/js/.gitignore