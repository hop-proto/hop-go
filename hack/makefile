.PHONY: serve-dev
serve-dev:
	go run . server

# the hop binary needs to be able to run on the docker container
# TODO(baumanl): figure out weirdness with cross-compilation and kravatte
.PHONY: authgrant-dev
authgrant-dev:
	go build -o ../containers/hop ../cmd/hop
	go run . target
	go run . delegate


# the hop binary needs to be able to run on the docker container
# TODO(baumanl): figure out weirdness with cross-compilation and kravatte
.PHONY: authgrant-chain-dev
authgrant-chain-dev:
	go build -o ../containers/hop ../cmd/hop
	go run . target
	go run . delegate
	go run . third

.PHONY: measurement-dev
measurement-dev:
	go run . measurement
