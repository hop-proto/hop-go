.PHONY: serve-dev
serve-dev:
	go build -o ../containers/client_delegate/hop ../cmd/hop
	go run . server_a

.PHONY: target
target:
	go run . server_b

