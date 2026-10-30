GO_VERSION = 1.27.3
GORELEASER_VERSION = v2.19.0
GOLANGCI_LINT_VERSION = v2.15.0
GOVULNCHECK_VERSION = v1.9.0
GORELEASER_ARGS = --snapshot

# Packages whose tests cannot run under the race detector (see //go:build !race)
NORACE_PKGS = $(shell git grep -l '^//go:build !race' -- ./internal | xargs -n 1 dirname | sort -u | sed 's/^/.\//')

.PHONY: all
all: check dist

# check runs everything CI runs
.PHONY: check
check: fmt-check vet lint test vuln

.PHONY: build
build:
	go build ./...

.PHONY: test
test:
	go test $(NORACE_PKGS)
	go test -race ./...

.PHONY: vet
vet:
	go vet ./...
	GOOS=windows go vet ./cmd/sshi/... ./internal/util/...

.PHONY: fmt-check
fmt-check:
	@out="$$(gofmt -l cmd internal)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

GOLANGCI_LINT = go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# sshi is also built for Windows, lint those files too
.PHONY: lint
lint:
	$(GOLANGCI_LINT) run ./...
	GOOS=windows $(GOLANGCI_LINT) run ./...

.PHONY: fmt
fmt:
	$(GOLANGCI_LINT) fmt ./...

.PHONY: vuln
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

.PHONY: dist
dist:
	@rm -rf dist
	docker run --rm \
		--user "$(shell id -u):$(shell id -g)" \
		--env CI \
		--env GITHUB_TOKEN \
		--env GOCACHE=/tmp/go-build \
		--env GOMODCACHE=/tmp/go-mod \
		--env VERSION=$(GORELEASER_VERSION) \
		--volume "$$PWD:/work" \
		--workdir /work \
		--entrypoint sh \
		golang:$(GO_VERSION) \
		-c "curl -fSsL https://goreleaser.com/static/run | bash -s -- release $(GORELEASER_ARGS)"
