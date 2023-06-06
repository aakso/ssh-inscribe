GO_VERSION = 1.18.9
GORELEASER_ARGS = --snapshot

.PHONY: all
all: test dist

.PHONY: dist
dist:
	@rm -rf dist
	docker run --rm \
		--user "$(shell id -u):$(shell id -g)" \
		--env GOCACHE=/tmp/go-build \
		--volume "$$PWD:/work" \
		--workdir /work \
		--entrypoint sh \
		golang:$(GO_VERSION) \
		-c "curl -fSsL https://goreleaser.com/static/run | bash -s -- release $(GORELEASER_ARGS)"

.PHONY: test
test:
	go test $(shell git grep  -l '!race' ./pkg | xargs -n 1 dirname | uniq | sed 's/^/\.\//')
	go test -race ./pkg/...
