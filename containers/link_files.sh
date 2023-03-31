#! /bin/bash

mkdir -p /etc/hopd

ln -s $(pwd)/server_dev_config /etc/hopd/config
ln -s $(pwd)/id_server.pem /etc/hopd/id_hop.pem
ln -s $(pwd)/id_server.cert /etc/hopd/id_hop.cert
ln -s $(pwd)/CAFiles/intermediate.cert /etc/hopd/intermediate.cert
ln -s $(pwd)/CAFiles/root.cert /etc/hopd/root.cert

mkdir -p $HOME/.hop
ln -s $(pwd)/id_client.pub $HOME/.hop/authorized_keys
