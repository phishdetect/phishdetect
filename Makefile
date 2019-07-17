.DEFAULT_GOAL   = linux
BUILD_FOLDER    = $(shell pwd)/build
FLAGS_LINUX     = GOOS=linux GOARCH=amd64 CGO_ENABLED=1

lint:
	@echo "[lint] Running linter on codebase"
	@golint ./...

deps:
	@echo "[deps] Downloading modules..."
	go mod download

	@echo "[deps] Done!"

linux:
	@mkdir -p $(BUILD_FOLDER)/linux

	@echo "[builder] Building Linux CLI executable"
	@cd cli; $(FLAGS_LINUX) go build -o $(BUILD_FOLDER)/linux/phishdetect-cli

	@echo "[builder] Done!"

clean:
	rm -rf $(BUILD_FOLDER)
