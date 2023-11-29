PKG?=github.com/smallstep/sshutil

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC=$(shell find . -type f -name '*.go')
GOOS_OVERRIDE ?=
OUTPUT_ROOT=output/

# Set shell to bash for `echo -e`
SHELL := /bin/bash

all: lint test

.PHONY: all

#########################################
# Bootstrapping
#########################################

bootstra%:
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin latest
	$Q go install golang.org/x/vuln/cmd/govulncheck@latest
	$Q go install gotest.tools/gotestsum@latest

#########################################
# Test
#########################################
test:
	$Q $(GOFLAGS) gotestsum -- -coverprofile=coverage.out -short -covermode=atomic ./...

.PHONY: test

#########################################
# Linting
#########################################

fmt:
	$Q goimports -l -w $(SRC)

lint: SHELL:=/bin/bash
lint:
	$Q LOG_LEVEL=error golangci-lint run --config <(curl -s https://raw.githubusercontent.com/smallstep/workflows/master/.golangci.yml) --timeout=30m
	$Q govulncheck ./...

.PHONY: fmt lint

