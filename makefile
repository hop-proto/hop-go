help: ## List tasks with documentation
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' "$(firstword $(MAKEFILE_LIST))" | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

GOLANGCI_LINT := golangci-lint
ifeq (, $(shell command -v "$(GOLANGCI_LINT)"))
	GOLANGCI_LINT_ERR = $(error install golangci-lint with e.g. brew install golangci/tap/golangci-lint)
endif

.PHONY: lint
lint: ## lint go code
lint: ; $(GOLANGCI_LINT_ERR)
	@echo "lint-go"
	@$(GOLANGCI_LINT) run --deadline 1m

.PHONY: build
build: ## compile
build:
	go build ./...

.PHONY: install
install: ## install rpf
install:
	go install ./cmd/remotePF

.PHONY: test
test: ## test
test:
	go test ./... -timeout 120s

.PHONY: serve-dev
serve-dev: ## launch a container running the server with code mounted in
	make -C hack serve-dev
