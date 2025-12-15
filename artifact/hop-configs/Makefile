# Mac OS /usr/local/bin
# Linux /usr/bin
PREFIX_SERVER=/etc/hopd
PREFIX_CLIENT=/usr/bin

USER_HOP_DIR=.
SERVER_HOP_DIR=.
CA_CERTS_DIR=./CACerts
HOP_PORT=77

USERNAME?=root
SERVER_IP?=127.0.0.1
CA_CERT_DNS_NAME=example.com

build:
	@echo "Building Hop Tools..."
	go build -o hop ../../cmd/hop
	go build -o hopd ../../cmd/hopd
	go build -o hop-gen ../../cmd/hop-gen
	go build -o hop-issue ../../cmd/hop-issue

server-install:
	@echo "Installing Hop tools..."
	sudo install -m 755 hop hopd hop-gen hop-issue $(PREFIX_SERVER)/
	@echo "Installation complete!"

client-install:
	@echo "Installing Hop tools..."
	sudo install -m 755 hop hopd hop-gen hop-issue $(PREFIX_CLIENT)/
	@echo "Installation complete!"

server-remove:
	@echo "Removing Hop Tools from $(PREFIX_SERVER)..."
	sudo rm -f $(PREFIX_SERVER)/hop $(PREFIX_SERVER)/hopd $(PREFIX_SERVER)/hop-gen $(PREFIX_SERVER)/hop-issue

	@echo "Remove Hop Configuration from $(SERVER_HOP_DIR) and $(USER_HOP_DIR)..."
	sudo rm -rf $(SERVER_HOP_DIR)
	sudo rm -rf $(USER_HOP_DIR)
	@echo "HOP uninstalled."

client-remove:
	@echo "Remove Hop Tools from $(PREFIX_CLIENT)..."
	sudo rm -f $(PREFIX_CLIENT)/hop $(PREFIX_CLIENT)/hopd $(PREFIX_CLIENT)/hop-gen $(PREFIX_CLIENT)/hop-issue

	@echo "Remove Hop Configuration from $(SERVER_HOP_DIR) and $(USER_HOP_DIR)..."
	sudo rm -rf $(SERVER_HOP_DIR)
	sudo rm -rf $(USER_HOP_DIR)
	@echo "Hop uninstalled."


ca-certsgen:
	mkdir -p "$(CA_CERTS_DIR)"
	## CA private keygen (You can change the location of the binaries
	./hop-gen -signing | tee $(CA_CERTS_DIR)/root-key.pem
	./hop-gen -signing | tee $(CA_CERTS_DIR)/intermediate-key.pem
	## CA public keygen
	./hop-gen -signing -private $(CA_CERTS_DIR)/root-key.pem | tee $(CA_CERTS_DIR)/root.pub
	./hop-gen -signing -private $(CA_CERTS_DIR)/intermediate-key.pem | tee $(CA_CERTS_DIR)/intermediate.pub
	## CA cert gen
	./hop-issue -type root -key-file $(CA_CERTS_DIR)/root-key.pem -dns-name $(CA_CERT_DNS_NAME) | tee $(CA_CERTS_DIR)/root.cert
	./hop-issue -type intermediate -key-file $(CA_CERTS_DIR)/root-key.pem -cert-file $(CA_CERTS_DIR)/root.cert -public-key $(CA_CERTS_DIR)/intermediate.pub -dns-name $(CA_CERT_DNS_NAME) | tee $(CA_CERTS_DIR)/intermediate.cert
	@echo "\nRoot for $(CA_CERT_DNS_NAME) and intermediate certificates generated"



client-keygen:
	@echo "Generating user keys..."
	@if [ ! -f "$(USER_HOP_DIR)/id_hop.pem" ]; then \
		./hop-gen > $(USER_HOP_DIR)/id_hop.pem; \
		./hop-gen -private $(USER_HOP_DIR)/id_hop.pem > $(USER_HOP_DIR)/id_hop.pub; \
		@echo "Done!"
	else \
		echo "$(USER_HOP_DIR)/keys already exist"; \
		exit 0; \
	fi

client-certsgen:
	@echo "Issuing client certificate..."
	@if [ ! -f "$(USER_HOP_DIR)/id_hop.cert" ] && [ -f "$(USER_HOP_DIR)/id_hop.pub" ]; then \
		./hop-issue -type leaf \
			-key-file $(CA_CERTS_DIR)/intermediate-key.pem \
			-cert-file $(CA_CERTS_DIR)/intermediate.cert \
			-public-key $(USER_HOP_DIR)/id_hop.pub \
			-dns-name "$(USERNAME)" > $(USER_HOP_DIR)/id_hop.cert; \
		echo "Done!"; \
	else \
		echo "$(USER_HOP_DIR)/certs already exist or missing id_hop keys"; \
	fi


client-config-gen:
	@echo "Generating default config..."
	@echo '[Global]' > "$(USER_HOP_DIR)/config.toml"
	@echo 'Key = "$(USER_HOP_DIR)/id_hop.pem"' >> "$(USER_HOP_DIR)/config.toml"
	@echo 'Certificate = "$(USER_HOP_DIR)/id_hop.cert"' >> "$(USER_HOP_DIR)/config.toml"
	@echo 'CAFiles = ["$(CA_CERTS_DIR)/intermediate.cert", "$(CA_CERTS_DIR)/root.cert"]' >> "$(USER_HOP_DIR)/config.toml"
	@echo '' >> "$(USER_HOP_DIR)/config.toml"
	@echo '[[Hosts]]' >> "$(USER_HOP_DIR)/config.toml"
	@echo 'Patterns = ["$(SERVER_IP)"]' >> "$(USER_HOP_DIR)/config.toml"
	@echo 'ServerName = "$(SERVER_IP)"' >> "$(USER_HOP_DIR)/config.toml"
	@echo 'Port = $(HOP_PORT)' >> "$(USER_HOP_DIR)/config.toml"

	@echo "Installation complete! Edit $(USER_HOP_DIR)/config.toml"

server-keygen:
	@echo "Generating server keys..."
	@if [ ! -f "$(SERVER_HOP_DIR)/id_hop.pem" ]; then \
		sudo bash -c "hop-gen > $(SERVER_HOP_DIR)/id_hop.pem"; \
		sudo bash -c "hop-gen -private $(SERVER_HOP_DIR)/id_hop.pem > $(SERVER_HOP_DIR)/id_hop.pub"; \
		echo "Done!"; \
	else \
		echo "$(SERVER_HOP_DIR)/keys already exist"; \
	fi

server-certsgen:
	@echo "Issuing server certificate..."
	@if [ ! -f "$(SERVER_HOP_DIR)/id_hop.cert" ] && [ -f "$(SERVER_HOP_DIR)/id_hop.pub" ]; then \
		sudo bash -c 'hop-issue -type leaf \
			-key-file "$(CA_CERTS_DIR)/intermediate-key.pem" \
			-cert-file "$(CA_CERTS_DIR)/intermediate.cert" \
			-public-key "$(SERVER_HOP_DIR)/id_hop.pub" \
			-dns-name "$(SERVER_IP)" > "$(SERVER_HOP_DIR)/id_hop.cert"'; \
		echo "Done!"; \
	else \
		echo "$(SERVER_HOP_DIR)/certs already exist"; \
	fi


server-config-gen:
	@echo "Generating default config..."
	sudo bash -c 'echo "ListenAddress = \":$(HOP_PORT)\"" > "$(SERVER_HOP_DIR)/config.toml"'
	sudo bash -c 'echo "" >> "$(SERVER_HOP_DIR)/config.toml"'
	sudo bash -c 'echo "Key = \"$(SERVER_HOP_DIR)/id_hop.pem\"" >> "$(SERVER_HOP_DIR)/config.toml"'
	sudo bash -c 'echo "Certificate = \"$(SERVER_HOP_DIR)/id_hop.cert\"" >> "$(SERVER_HOP_DIR)/config.toml"'
	sudo bash -c 'echo "CAFiles = [\"$(CA_CERTS_DIR)/intermediate.cert\", \"$(CA_CERTS_DIR)/root.cert\"]" >> "$(SERVER_HOP_DIR)/config.toml"'
	sudo bash -c 'echo "" >> "$(SERVER_HOP_DIR)/config.toml"'
	sudo bash -c 'echo "Users = [\"$(USERNAME)\"]" >> "$(SERVER_HOP_DIR)/config.toml"'

	@echo "Creating authorized_keys file..."
	@if [ ! -f "$(USER_HOP_DIR)/authorized_keys" ]; then \
		touch "$(USER_HOP_DIR)/authorized_keys"; \
		chmod 644 "$(USER_HOP_DIR)/authorized_keys"; \
	fi

	@echo "Installation complete! Edit $(SERVER_HOP_DIR)/config.toml and add client public key in $(USER_HOP_DIR)/authorized_keys"

enable-restart:
	@echo "Copying hopd service file..."
	sudo cp hopd.service /etc/systemd/system/hopd.service

	@echo "Reloading systemd, enabling and starting hopd service..."
	sudo systemctl daemon-reload
	sudo systemctl enable hopd
	sudo systemctl start hopd

	@echo "Hopd service is now enabled and running."


