#
# Generated by @zondax/cli
#
-include Makefile.settings.mk

# Get all directories under cmd
CMDS=$(shell find cmd -type d)

# Strip cmd/ from directory names and generate output binary names
BINS=$(subst cmd/,output/,$(CMDS))

default: build

build:
	@go build

mod-tidy:
	@go mod tidy

mod-clean:
	go clean -modcache

mod-update: mod-clean
	@go get -u ./...
	@go mod tidy

generate: mod-tidy
	go generate ./internal/...

version: build
	./output/$(APP_NAME) version

clean:
	go clean

gitclean:
	git clean -xfd
	git submodule foreach --recursive git clean -xfd

install_lint:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin latest

check-modtidy:
	@go mod tidy
	git diff --exit-code -- go.mod go.sum

lint:
	golangci-lint --version
	golangci-lint run

test:
	@go test common.go -mod=readonly -timeout 5m -short -race -coverprofile=coverage.txt -covermode=atomic
	@go test common.go -mod=readonly -timeout 5m
