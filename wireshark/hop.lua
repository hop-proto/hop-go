-- Hop Dissector for Wireshark

-- Define the protocol
local hop = Proto("hop", "Hop Data")

-- Hop message types
local msg_type_name = {
	[0x01] = "Client Hello",
	[0x02] = "Server Hello",
	[0x03] = "Client Acknowledgement",
	[0x04] = "Server Authentication",
	[0x05] = "Client Authentication",
	[0x10] = "Transport",
}
hop.fields.msg_type = ProtoField.uint8("hop.type", "Type", base.HEX, msg_type_name)

-- Hop versions. Right now there is only the one version
local versions = {
	[1] = "Hop 1"
}
hop.fields.version = ProtoField.uint8("hop.version", "Version", base.DEC, versions)
hop.fields.client_ephermeral = ProtoField.bytes("hop.client_ephemeral", "Client Ephemeral")
hop.fields.mac = ProtoField.bytes("hop.mac", "MAC")
hop.fields.server_ephermeral = ProtoField.bytes("hop.server_ephemeral", "Server Ephemeral")
hop.fields.cookie = ProtoField.bytes("hop.cookie", "Server Cookie")

-- This would be a string if it were not encrypted
hop.fields.hostname = ProtoField.bytes("hop.hostname", "Hostname")
hop.fields.certificates_length = ProtoField.uint16("hop.certificates_length", "Certificates Length", base.DEC)
hop.fields.session_id = ProtoField.uint32("hop.session_id", "Session ID", base.DEC)

-- TODO(hosono) there are two certificates in there. But getting them apart is tricky, and they encrypted anyway
hop.fields.certificates = ProtoField.bytes("hop.certificates", "Certificates")
hop.fields.certificates_auth_tag = ProtoField.bytes("hop.certificates_auth_tag", "Certificates Authentication Tag")
hop.fields.counter = ProtoField.uint64("hop.conter", "Counter", base.DEC)
hop.fields.encrypted_data = ProtoField.bytes("hop.encrypted_data", "Encrypted Data")

-- Function to handle client hellos
function client_hello(tree, buffer)
	tree:add(hop.fields.version, buffer(1,1))
	tree:add(buffer(2,2), "Reserved")
	tree:add(hop.fields.client_ephermeral, buffer(4,32))
	tree:add(hop.fields.mac, buffer(buffer:len()-16,16))
	-- TODO add hidden mode fields
end

-- Function to handle server hellos
function server_hello(tree, buffer)
	tree:add(buffer(1,3), "Reserved")
	tree:add(hop.fields.server_ephermeral, buffer(4,32))
	tree:add(hop.fields.cookie, buffer(36,48))
	tree:add(hop.fields.mac, buffer(buffer:len()-16,16))
end

-- Function to handle client acknowledgement
function client_acknowledgement(tree, buffer)
	tree:add(buffer(1,3), "Reserved")
	tree:add(hop.fields.client_ephermeral, buffer(4,32))
	tree:add(hop.fields.cookie, buffer(36,48))
	tree:add(hop.fields.hostname, buffer(84, 256))
end

-- Function to handle server authentication
function server_authentication(tree, buffer)
	tree:add(buffer(1,1), "Reserved")
	tree:add(hop.fields.certificates_length, buffer(2,2))
	tree:add(hop.fields.session_id, buffer(4, 4))
	local certs_len = buffer(2,2):uint()
	tree:add(hop.fields.certificates, buffer(8, certs_len))
	tree:add(hop.fields.certificates_auth_tag, buffer(8+certs_len, 16))
	tree:add(hop.fields.mac, buffer(buffer:len()-16,16))
end

-- Function to handle client authentication requests
function client_authentication(tree, buffer)
	tree:add(buffer(1,1), "Reserved")
	tree:add(hop.fields.certificates_length, buffer(2,2))
	tree:add(hop.fields.session_id, buffer(4, 4))
	local certs_len = buffer(2,2):uint()
	tree:add(hop.fields.certificates, buffer(8, certs_len))
	tree:add(hop.fields.certificates_auth_tag, buffer(8+certs_len, 16))
	tree:add(hop.fields.mac, buffer(buffer:len()-16,16))
end

-- Function to handle transport requests
function transport(tree, buffer)
	tree:add(buffer(1,3), "Reserved")
	tree:add(hop.fields.session_id, buffer(4,4))
	tree:add(hop.fields.counter, buffer(8, 8))
	tree:add(hop.fields.encrypted_data, buffer(16, buffer:len()-32))
	tree:add(hop.fields.mac, buffer(buffer:len()-16,16))
end

local msg_type_func = {
	[0x01] = client_hello,
	[0x02] = server_hello,
	[0x03] = client_acknowledgement,
	[0x04] = server_authentication,
	[0x05] = client_authentication,
	[0x10] = transport,
} 

-- Define the function that dissects it
function hop.dissector(buffer, pinfo, ptree)
	pinfo.cols.protocol = "HOP"
	local subtree = ptree:add(hop, buffer())

	local func = msg_type_func[buffer(0,1):uint()]
	subtree:add(hop.fields.msg_type, buffer(0,1))

	-- Call the function for the associated type
	if (func) then func(subtree, buffer) end
end

-- Register Hop on port 77
udp_table = DissectorTable.get("udp.port")
udp_table:add(77, hop) 
