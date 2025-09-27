.PHONY: all build-darwin-arm64 build-linux-amd64 build-windows-amd64 test clean run install-deps

all: build-darwin-arm64 build-linux-amd64 build-windows-amd64 test

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -o iqfetch-darwin-arm64 ./cmd/iqfetch

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o iqfetch-linux-amd64 ./cmd/iqfetch

build-windows-amd64:
	GOOS=windows GOARCH=amd64 go build -o iqfetch-windows-amd64.exe ./cmd/iqfetch

test:
	go test ./... -v

clean:
	rm -f iqfetch* *.exe

run:
	go run ./cmd/iqfetch

install-deps:
	go mod tidy
	go mod download
