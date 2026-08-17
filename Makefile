export GOFLAGS := -mod=mod
export GOPROXY := off
export GOSUMDB := off

.PHONY: all build test e2e vet clean proto

all: build test

build:
	go build ./...
	@mkdir -p bin
	go build -o bin/collector ./cmd/collector
	go build -o bin/fakesentry ./cmd/fakesentry

test:
	go test ./...

vet:
	go vet ./...

# Cluster-free end-to-end: collector + fakesentry over the real seccheck protocol.
e2e:
	./scripts/e2e.sh

# Real gVisor run (needs Docker + runsc). See the script header for prerequisites.
runsc:
	./scripts/run-with-runsc.sh

# Regenerate internal/pb from the vendored gVisor .proto files.
# Requires protoc and protoc-gen-go on PATH.
proto:
	protoc --go_out=. --go_opt=module=github.com/yashgupta/gvisor-visibility-poc \
		-I proto proto/common.proto proto/container.proto proto/sentry.proto proto/syscall.proto

clean:
	rm -rf bin
