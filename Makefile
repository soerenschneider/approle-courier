BUILD_DIR = builds
MODULE = github.com/soerenschneider/approle-courier
BINARY_NAME = approle-courier
CHECKSUM_FILE = $(BUILD_DIR)/checksum.sha256
DOCKER_PREFIX = ghcr.io/soerenschneider

# -s -w strip the symbol table and DWARF data, which stack traces do not need,
# and -trimpath removes local paths from the binary.
LDFLAGS = -s -w -X '$(MODULE)/internal.BuildVersion=$(VERSION)' -X '$(MODULE)/internal.CommitHash=$(COMMIT_HASH)'
GO_BUILD = CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)"

generate:
	go generate  ./...

tests:
	go test ./... -race -covermode=atomic -coverprofile=coverage.out
	go tool cover -html=coverage.out -o=coverage.html
	go tool cover -func=coverage.out -o=coverage.out

lint:
	golangci-lint run ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Runs the machine flow against OpenBao, HAProxy and approle-courier in docker
# compose, then tears everything down again.
e2e:
	docker compose up -d --build --wait --wait-timeout 180
	docker compose run --rm e2e || { docker compose logs; docker compose down -v --remove-orphans; false; }
	docker compose down -v --remove-orphans

clean:
	git diff --quiet || { echo 'Dirty work tree' ; false; }
	rm -rf ./$(BUILD_DIR)

build: version-info generate
	$(GO_BUILD) -o $(BINARY_NAME) .

release: clean version-info cross-build checksums

# File names without the directory, so "sha256sum --check" works on the
# downloaded release assets.
checksums: version-info
	{ echo "# version: $(VERSION)"; cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)-*; } > $(CHECKSUM_FILE)

# Signs keyless and writes $(CHECKSUM_FILE).sigstore.json, tied to the CI
# workflow's identity, so this only runs in CI.
sign:
	@if [ "$$CI" != "true" ]; then \
		echo "keyless signatures are only meaningful from the release workflow"; false; \
	fi
	cosign sign-blob --yes --bundle $(CHECKSUM_FILE).sigstore.json $(CHECKSUM_FILE)

cross-build: version-info
	GOOS=linux GOARCH=amd64        $(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64    .
	GOOS=linux GOARCH=arm GOARM=6  $(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-armv6    .
	GOOS=linux GOARCH=arm GOARM=7  $(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-armv7    .
	GOOS=linux GOARCH=arm64        $(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-aarch64  .

validate-openapi-spec:
	docker run --rm -v $(shell pwd):/tmp stoplight/spectral lint --ruleset "/tmp/.spectral.yaml" "/tmp/api/openapi.yaml"

docker-build: version-info
	docker build --build-arg VERSION="$(VERSION)" --build-arg COMMIT_HASH="$(COMMIT_HASH)" -t "$(DOCKER_PREFIX)/$(BINARY_NAME)" .

version-info:
	$(eval VERSION := $(shell git describe --tags --abbrev=0 || echo "dev"))
	$(eval COMMIT_HASH := $(shell git rev-parse HEAD))

fmt:
	find . -iname "*.go" -exec go fmt {} \; 

pre-commit-init:
	pre-commit install
	pre-commit install --hook-type commit-msg

pre-commit-update:
	pre-commit autoupdate

.PHONY: generate tests lint vulncheck e2e clean build release checksums sign cross-build validate-openapi-spec docker-build version-info fmt pre-commit-init pre-commit-update
