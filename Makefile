# Make DefraDB!
# For compatibility, prerequisites are instead explicit calls to make.

ifndef VERBOSE
MAKEFLAGS+=--no-print-directory
endif

# Provide info from git to the version package using linker flags.
ifeq (, $(shell which git))
$(error "No git in $(PATH), version information won't be included")
else
VERSION_GOINFO=$(shell go version)
VERSION_GITCOMMIT=$(shell git rev-parse HEAD)
VERSION_GITCOMMITDATE=$(shell git show -s --format=%cs HEAD)
VERSION_GITBRANCH=$(shell git symbolic-ref -q --short HEAD)
ifneq ($(shell git symbolic-ref -q --short HEAD),master)
VERSION_GITTAG=dev-$(shell git symbolic-ref -q --short HEAD)
else
VERSION_GITTAG=$(shell git describe --tags)
endif
BUILD_FLAGS=-ldflags "\
-X 'github.com/sourcenetwork/defradb/version.GoInfo=$(VERSION_GOINFO)'\
-X 'github.com/sourcenetwork/defradb/version.GitTag=$(VERSION_GITTAG)'\
-X 'github.com/sourcenetwork/defradb/version.GitCommit=$(VERSION_GITCOMMIT)'\
-X 'github.com/sourcenetwork/defradb/version.GitCommitDate=$(VERSION_GITCOMMITDATE)'\
-X 'github.com/sourcenetwork/defradb/version.GitBranch=$(VERSION_GITBRANCH)'"
endif

default:
	@go run $(BUILD_FLAGS) cmd/defradb/main.go

.PHONY: install
install:
	@go install $(BUILD_FLAGS) ./cmd/defradb

.PHONY: build
build:
	@go build $(BUILD_FLAGS) -o build/defradb cmd/defradb/main.go

# Usage: make cross-build platforms="{platforms}"
# platforms is specified as a comma-separated list with no whitespace, e.g. "linux/amd64,linux/arm,linux/arm64"
# If none is specified, build for all platforms.
.PHONY: cross-build
cross-build:
	bash tools/scripts/cross-build.sh $(platforms)

.PHONY: start
start:
	@$(MAKE) build
	./build/defradb start

.PHONY: dev\:start
dev\:start:
	@$(MAKE) build
	DEFRA_ENV=dev ./build/defradb start

.PHONY: client\:dump
client\:dump:
	./build/defradb client dump

.PHONY: client\:add-schema
client\:add-schema:
	./build/defradb client schema add -f examples/schema/bookauthpub.graphql

.PHONY: deps\:lint
deps\:lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: deps\:test
deps\:test:
	go install gotest.tools/gotestsum@latest

.PHONY: deps\:coverage
deps\:coverage:
	go install github.com/ory/go-acc@latest

.PHONY: deps\:bench
deps\:bench:
	go install golang.org/x/perf/cmd/benchstat@latest

.PHONY: deps\:chglog
deps\:chglog:
	go install github.com/git-chglog/git-chglog/cmd/git-chglog@latest

.PHONY: deps\:modules
deps\:modules:
	go mod download

.PHONY: deps\:ci
deps\:ci:
	curl -fLSs https://raw.githubusercontent.com/CircleCI-Public/circleci-cli/master/install.sh | DESTDIR=${HOME}/bin bash

.PHONY: deps
deps:
	@$(MAKE) deps:lint && $(MAKE) deps:coverage && $(MAKE) deps:bench && $(MAKE) deps:chglog && \
	$(MAKE) deps:modules && $(MAKE) deps:ci && $(MAKE) deps:test

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	go clean cmd/defradb/main.go
	rm -f build/defradb

.PHONY: clean\:test
clean\:test:
	go clean -testcache

.PHONY: test
test:
	gotestsum --format pkgname -- ./... -race -shuffle=on

.PHONY: test\:go
test\:go:
	go test ./... -race -shuffle=on

.PHONY: test\:verbose
test\:verbose:
	gotestsum --format testname --junitfile /tmp/defradb-dev/test.xml -- ./... -race -shuffle=on

.PHONY: test\:watch
test\:watch:
	gotestsum --watch -- ./...

.PHONY: test\:clean
test\:clean:
	@$(MAKE) clean:test && $(MAKE) test

.PHONY: test\:bench
test\:bench:
	@$(MAKE) -C ./tests/bench/ bench

.PHONY: test\:bench-short
test\:bench-short:
	@$(MAKE) -C ./tests/bench/ bench:short

# This also takes integration tests into account.
.PHONY: test\:coverage-full
test\:coverage-full:
	@$(MAKE) deps:coverage
	go-acc ./... --output=coverage-full.txt --covermode=atomic
	go tool cover -func coverage-full.txt | grep total | awk '{print $$3}'

# Usage: make test:coverage-html path="{pathToPackage}"
# Example: make test:coverage-html path="./api/..."
# .PHONY: test\:coverage-html
test\:coverage-html:
ifeq ($(path),)
	gotestsum -- ./... -v -race -shuffle=on -coverprofile=coverage.out
else 
	gotestsum -- $(path) -v -race -shuffle=on -coverprofile=coverage.out
endif
	go tool cover -html=coverage.out
	rm ./coverage.out

# This only covers how much of the package is tested by itself (unit test).
.PHONY: test\:coverage-quick
test\:coverage-quick:
	gotestsum -- ./... -race -shuffle=on -coverprofile=coverage-quick.txt -covermode=atomic
	go tool cover -func coverage-quick.txt | grep total | awk '{print $$3}'

.PHONY: test\:changes
test\:changes:
	env DEFRA_DETECT_DATABASE_CHANGES=true gotestsum --junitfile /tmp/defradb-dev/changes.xml -- ./... -shuffle=on -p 1

.PHONY: validate\:codecov
validate\:codecov:
	curl --data-binary @.github/codecov.yml https://codecov.io/validate

.PHONY: validate\:circleci
validate\:circleci:
	circleci config validate

.PHONY: lint
lint:
	golangci-lint run --config tools/configs/golangci.yaml

.PHONY: lint\:fix
lint\:fix:
	golangci-lint run --config tools/configs/golangci.yaml --fix

.PHONY: lint\:todo
lint\:todo:
	rg "nolint" -g '!{Makefile}'

.PHONY: lint\:list
lint\:list:
	golangci-lint linters --config tools/configs/golangci.yaml

.PHONY: chglog
chglog:
	git-chglog -c "tools/configs/chglog/config.yml" --next-tag v0.x.0 -o CHANGELOG.md

.PHONY: docs
docs:
	@$(MAKE) docs\:cli
	@$(MAKE) docs\:manpages

.PHONY: docs\:cli
docs\:cli:
	go run cmd/genclidocs/genclidocs.go -o docs/cli/

.PHONY: docs\:manpages
docs\:manpages:
	go run cmd/genmanpages/main.go -o build/man/

detectedOS := $(shell uname)
.PHONY: install\:manpages
install\:manpages:
ifeq ($(detectedOS),Linux)
	cp build/man/* /usr/share/man/man1/
endif
ifneq ($(detectedOS),Linux)
	@echo "Direct installation of Defradb's man pages is not supported on your system."
endif
