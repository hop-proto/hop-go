HOP_DIR="../../../"
ROOT_HOP_DIR="/root/.hop/" # MUST be in root home dir

cd "$HOP_DIR" || exit 1
mkdir "./artifact/simulation/config/CAFiles" || exit 1


# Root

go run ./cmd/hop-keygen \
  -signing \
  -name root \
  -directory ./artifact/simulation/config/CAFiles

go run ./cmd/hop-issue \
  -type root \
  -key-file ./artifact/simulation/config/CAFiles/root.pem \
  > ./artifact/simulation/config/CAFiles/root.cert


# Intermediate

go run ./cmd/hop-keygen \
  -signing \
  -name intermediate \
  -directory ./artifact/simulation/config/CAFiles/

go run ./cmd/hop-issue \
  -type intermediate \
  -key-file ./artifact/simulation/config/CAFiles/root.pem \
  -cert-file ./artifact/simulation/config/CAFiles/root.cert \
  -public-key ./artifact/simulation/config/CAFiles/intermediate.pub \
  -dns-name simulation.com \
  > ./artifact/simulation/config/CAFiles/intermediate.cert


# Client

go run ./cmd/hop-keygen \
  -name id_client \
  -directory ./artifact/simulation/config/

go run ./cmd/hop-issue \
  -type leaf \
  -key-file ./artifact/simulation/config/CAFiles/intermediate.pem \
  -cert-file ./artifact/simulation/config/CAFiles/intermediate.cert \
  -public-key ./artifact/simulation/config/id_client.pub \
  -dns-name root \
  > ./artifact/simulation/config/id_client.cert


# Server

go run ./cmd/hop-keygen \
  -name id_server \
  -directory ./artifact/simulation/config/

go run ./cmd/hop-issue \
  -type leaf \
  -key-file ./artifact/simulation/config/CAFiles/intermediate.pem \
  -cert-file ./artifact/simulation/config/CAFiles/intermediate.cert \
  -public-key ./artifact/simulation/config/id_server.pub \
  -dns-name 10.0.3.10 \
  > ./artifact/simulation/config/id_server.cert

mkdir -p "$ROOT_HOP_DIR"
cat "$HOP_DIR"/artifact/simulation/config/id_client.pub > "$ROOT_HOP_DIR"/authorized_keys
echo "Be sure that you have the id_client.pub key in $ROOT_HOP_DIR or user's Hop authorized keys home directory.)"
