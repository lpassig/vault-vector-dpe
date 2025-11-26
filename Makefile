GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.PHONY: build clean fmt test

default: build

all: fmt build test

build:
	@echo "Building vault-vector-dpe..."
	@cd plugins && go build -o bin/vault-vector-dpe .

clean:
	@rm -f plugins/bin/vault-vector-dpe
	@rm -f vector.json

fmt:
	@cd plugins && go fmt ./...

test:
	@cd plugins && go test -v ./...

# Helper to register with a local dev vault (requires vault server running)
dev-register: build
	@echo "Calculating SHA256..."
	$(eval SHASUM := $(shell shasum -a 256 plugins/bin/vault-vector-dpe | cut -d " " -f1))
	@echo "SHA256: $(SHASUM)"
	@echo "Registering plugin..."
	@vault plugin register -sha256=$(SHASUM) -command="vault-vector-dpe" secret vector-dpe || true
	@echo "Enabling secrets engine..."
	@vault secrets enable -path=vector vector-dpe || true

