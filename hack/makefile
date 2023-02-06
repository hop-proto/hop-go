.PHONY: serve-dev
serve-dev:
	go run . server

.PHONY: authgrant-dev
authgrant-dev:
	go build -o ../containers/hop ../cmd/hop
	go run . target
	go run . delegate

.PHONY: authgrant-chain-dev
authgrant-chain-dev:
	go build -o ../containers/hop ../cmd/hop
	go run . target
	go run . delegate
	go run . third
