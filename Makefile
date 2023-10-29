GO_VERSION = 1.20.7
GORELEASER_ARGS = --snapshot

.PHONY: all
all: test dist

.PHONY: dist
dist:
	@rm -rf dist
	docker run --rm \
		--user "$(shell id -u):$(shell id -g)" \
		--env CI \
		--env GITHUB_TOKEN \
		--env GOCACHE=/tmp/go-build \
		--volume "$$PWD:/work" \
		--workdir /work \
		--entrypoint sh \
		golang:$(GO_VERSION) \
		-c "curl -fSsL https://goreleaser.com/static/run | bash -s -- release $(GORELEASER_ARGS)"

.PHONY: test
test:
	go test $(shell git grep  -l '!race' ./internal | xargs -n 1 dirname | uniq | sed 's/^/\.\//')
	go test -race ./internal/...
