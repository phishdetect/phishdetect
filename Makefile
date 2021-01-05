.DEFAULT_GOAL = linux
BUILD_FOLDER  = $(shell pwd)/build
FLAGS_LINUX   = GOOS=linux GOARCH=amd64 CGO_ENABLED=1

lint:
	@echo "[lint] Running linter on codebase"
	@golint ./...

deps:
	@echo "[deps] Downloading modules..."
	go mod download

	@echo "[deps] Done!"

linux: deps
	@mkdir -p $(BUILD_FOLDER)

	@echo "[builder] Building Linux command-line executable"
	@cd cmd/phishdetect; $(FLAGS_LINUX) go build -o $(BUILD_FOLDER)/phishdetect

	@echo "[builder] Done!"

clean:
	rm -rf $(BUILD_FOLDER)
