BUILD_FOLDER  = $(shell pwd)/build

FLAGS_LINUX   = GOOS=linux
# FLAGS_FREEBSD = GOOS=freebsd
FLAGS_DARWIN  = GOOS=darwin
FLAGS_WINDOWS = GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc CGO_ENABLED=1

lint:
	@echo "[lint] Running linter on codebase"
	@golint ./...

deps:
	@echo "[deps] Downloading modules..."
	go mod download
	go get -u github.com/gobuffalo/packr/...

	@echo "[deps] Need to fix an issue with Docker client vendoring..."
	rm -rf $(GOPATH)/src/github.com/docker/docker/vendor/github.com/docker/go-connections

	@echo "[deps] Done!"

linux:
	@mkdir -p $(BUILD_FOLDER)/linux

	@echo "[builder] Building Linux CLI executable"
	@cd cli; $(FLAGS_LINUX) go build --ldflags '-s -w' -o $(BUILD_FOLDER)/linux/phishdetect-cli

	@echo "[builder] Building Linux Web executable"
	@cd web; $(FLAGS_LINUX) packr build --ldflags '-s -w' -o $(BUILD_FOLDER)/linux/phishdetect-web

	@echo "[builder] Done!"

# freebsd:
# 	@mkdir -p $(BUILD_FOLDER)/freebsd

# 	@echo "[builder] Building FreeBSD CLI executable"
# 	@cd cli; $(FLAGS_FREEBSD) go build --ldflags '-s -w' -o $(BUILD_FOLDER)/freebsd/phishdetect-cli

# 	@echo "[builder] Building FreeBSD Web executable"
# 	@cd web; $(FLAGS_FREEBSD) packr build --ldflags '-s -w' -o $(BUILD_FOLDER)/freebsd/phishdetect-web

# 	@echo "[builder] Done!"

darwin:
	@mkdir -p $(BUILD_FOLDER)/darwin

	@echo "[builder] Building Darwin CLI executable"
	@cd cli; $(FLAGS_DARWIN) go build --ldflags '-s -w' -o $(BUILD_FOLDER)/darwin/phishdetect-cli

	@echo "[builder] Building Linux Web executable"
	@cd web; $(FLAGS_DARWIN) packr build --ldflags '-s -w' -o $(BUILD_FOLDER)/darwin/phishdetect-web

	@echo "[builder] Done!"

windows:
	@mkdir -p $(BUILD_FOLDER)/windows

	@echo "[builder] Building Windows CLI executable"
	@cd cli; $(FLAGS_WINDOWS) go build --ldflags '-s -w -extldflags "-static"' -o $(BUILD_FOLDER)/windows/phishdetect-cli.exe

	@echo "[builder] Building Windows Web executable"
	@cd web; $(FLAGS_WINDOWS) packr build --ldflags '-s -w -extldflags "-static"' -o $(BUILD_FOLDER)/windows/phishdetect-web.exe

	@echo "[builder] Done!"

clean:
	rm -rf $(BUILD_FOLDER)
