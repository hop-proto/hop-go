.PHONY: serve-dev
serve-dev:
	go run . server

.PHONY: authgrant-dev
authgrant-dev:
	go build -o ../containers/delegate_proxy_server/hop ../cmd/hop
	go run . target
	go run . delegate
