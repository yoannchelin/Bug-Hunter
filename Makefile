BIN_DIR := $(HOME)/.local/bin
HUNTER   := $(BIN_DIR)/hunter
HUNTERMCP := $(BIN_DIR)/hunter-mcp

.PHONY: all build install test vet clean

all: build

build:
	go build -o bin/hunter     ./cmd/hunter
	go build -o bin/hunter-mcp ./cmd/hunter-mcp

install: build
	mkdir -p $(BIN_DIR)
	cp bin/hunter     $(HUNTER)
	cp bin/hunter-mcp $(HUNTERMCP)
	@echo "Installed to $(BIN_DIR)"

test:
	go test ./... -count=1

vet:
	go vet ./...

clean:
	rm -rf bin/
