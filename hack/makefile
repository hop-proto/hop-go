.PHONY: serve-dev
serve-dev:
	go run . server

# go build -o ../containers/hop ../cmd/hop
.PHONY: authgrant-dev
authgrant-dev:
	go run . target
	go run . delegate

# go build -o ../containers/hop ../cmd/hop
.PHONY: authgrant-chain-dev
authgrant-chain-dev:
	go run . target
	go run . delegate
	go run . third
