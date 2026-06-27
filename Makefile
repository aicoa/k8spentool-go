.PHONY: build run clean deps test

APP_NAME = k8spen
BUILD_DIR = build

deps:
	go mod tidy
	go mod download

build:
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/k8spen/

run:
	go run ./cmd/k8spen/ -port 8080

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

dev:
	go run ./cmd/k8spen/ -port 8080

build-all:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 ./cmd/k8spen/
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 ./cmd/k8spen/
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 ./cmd/k8spen/
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/k8spen/
