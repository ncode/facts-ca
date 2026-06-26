GO ?= go
PACKAGES ?= ./...

# VERSION is the exact git tag at HEAD (release builds); dev builds with no tag
# at HEAD fall back to dev-<short-commit>. Override with `make VERSION=...`.
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || echo "dev-$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)")
LDFLAGS ?= -X github.com/ncode/facts-ca/internal/version.Version=$(VERSION)
PREFIX ?= /usr/local
DESTDIR ?=
DIST_DIR ?= dist
BINARIES ?= facts-ca-cli facts-ca-server
DIST_TARGETS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64
SHA256 := $(shell command -v sha256sum >/dev/null 2>&1 && echo "sha256sum" || echo "shasum -a 256")

.PHONY: all build test race vet fmt fmt-check tidy vuln cover e2e interop dist install clean

all: fmt-check vet test build

# build compiles both binaries with the version embedded.
build:
	$(GO) build -ldflags '$(LDFLAGS)' -o facts-ca-cli ./cmd/facts-ca-cli
	$(GO) build -ldflags '$(LDFLAGS)' -o facts-ca-server ./cmd/facts-ca-server

test:
	$(GO) test $(PACKAGES)

race:
	$(GO) test -race $(PACKAGES)

vet:
	$(GO) vet $(PACKAGES)

fmt:
	gofmt -w $$(git ls-files '*.go')

fmt-check:
	@files="$$(gofmt -l $$(git ls-files '*.go'))"; \
	if [ -n "$$files" ]; then printf 'The following Go files need gofmt:\n%s\n' "$$files"; exit 1; fi

tidy:
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

vuln:
	$(GO) tool govulncheck ./...

cover:
	$(GO) test -covermode=atomic -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -5

# e2e runs the local server<->cli proof; interop runs the real-puppetserver proof.
e2e:
	./e2e.sh

interop:
	./interop.sh

# dist builds checksummed release archives facts-ca-$(VERSION)-<os>-<arch>,
# each bundling both facts-ca-cli and facts-ca-server. The version is embedded
# (internal/version.Version) and reported by `facts-ca-cli --version`.
dist:
	@set -e; \
	mkdir -p $(DIST_DIR); \
	for target in $(DIST_TARGETS); do \
		goos=$${target%/*}; goarch=$${target#*/}; \
		name="facts-ca-$(VERSION)-$$goos-$$goarch"; \
		staging="$(DIST_DIR)/$$name"; \
		rm -rf "$$staging"; mkdir -p "$$staging"; \
		echo "building $$name"; \
		for b in $(BINARIES); do \
			out="$$b"; if [ "$$goos" = windows ]; then out="$$b.exe"; fi; \
			CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o "$$staging/$$out" ./cmd/$$b; \
		done; \
		if [ "$$goos" = windows ]; then \
			rm -f "$(DIST_DIR)/$$name.zip"; (cd $(DIST_DIR) && zip -q -r "$$name.zip" "$$name"); \
		else \
			tar -czf "$(DIST_DIR)/$$name.tar.gz" -C $(DIST_DIR) "$$name"; \
		fi; \
		rm -rf "$$staging"; \
	done; \
	(cd $(DIST_DIR) && rm -f SHA256SUMS && $(SHA256) facts-ca-$(VERSION)-*.tar.gz facts-ca-$(VERSION)-*.zip > SHA256SUMS); \
	cat $(DIST_DIR)/SHA256SUMS

# install builds the host binaries and installs them under PREFIX (default
# /usr/local), honoring DESTDIR for staged installs.
install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 facts-ca-cli "$(DESTDIR)$(PREFIX)/bin/facts-ca-cli"
	install -m 0755 facts-ca-server "$(DESTDIR)$(PREFIX)/bin/facts-ca-server"

clean:
	rm -f facts-ca-cli facts-ca-server coverage.out
	rm -rf $(DIST_DIR)/facts-ca-$(VERSION)-* $(DIST_DIR)/SHA256SUMS
