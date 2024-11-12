help: ## List tasks with documentation
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' "$(firstword $(MAKEFILE_LIST))" | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

GOLANGCI_LINT := golangci-lint
ifeq (, $(shell command -v "$(GOLANGCI_LINT)"))
	GOLANGCI_LINT_ERR = $(error install golangci-lint with e.g. brew install golangci/tap/golangci-lint)
endif

GOLANG_CHECKLOCKS := $$HOME/go/bin/checklocks
ifeq (, $(shell command -v "GOLANG_CHECKLOCKS"))
	GOLANG_CHECKLOCKS_ERR = $(error install checklocks eith e.g. go install gvisor.dev/gvisor/tools/checklocks/cmd/checklocks@go)
endif

.PHONY: vet
vet: ## run go vet. Currently, this only checks for deadlocks
vet:
	go vet -vettool=$$HOME/go/bin/checklocks ./...

.PHONY: lint
lint: ## lint go code
lint: ; $(GOLANGCI_LINT_ERR)
	@echo "lint-go"
	@$(GOLANGCI_LINT) run --timeout 1m

.PHONY: build
build: ## compile
build:
	go build ./...

.PHONY: debug
debug: ## compile in debug mode
debug:
	go build -tags debug ./...

.PHONY: test
test: ## test. To run with trace logging, add "-tags debug" to the arguments
test:
	go test -race ./... -timeout 4m

.PHONY: cred-gen
cred-gen: ## generates credentials for container tests
	./containers/container_cred_gen.sh

.PHONY: authgrant-dev
authgrant-dev: ## launch two containers
	docker compose -f ./containers/docker-compose.yml build hopd-dev
	docker compose -f ./containers/docker-compose.yml up --detach target delegate

.PHONY: authgrant-chain-dev
authgrant-chain-dev: ## launch three containers
	docker compose -f ./containers/docker-compose.yml build hopd-dev
	docker compose -f ./containers/docker-compose.yml up --detach target delegate third

.PHONY: serve-dev
serve-dev: ## launch a container running the server with code mounted in
	docker compose -f ./containers/docker-compose.yml build hopd-dev
	docker compose -f ./containers/docker-compose.yml up --detach hop-server

stop-servers: ## stop all running docker instances
	docker compose -f ./containers/docker-compose.yml down
