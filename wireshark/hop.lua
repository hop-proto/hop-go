-- Hop Dissector for Wireshark
--
package.loadlib(package_loc, "luaopen_libcompat")()

-- Define the protocols
local hop = Proto("hop", "Hop Data")
local hop_tube = Proto("hop_tube", "Hop Tube Data")

hop.prefs.client_to_server_key = Pref.string("Client to Server Key", "", "The key used to encrypt traffic from the client to the server")
hop.prefs.server_to_client_key = Pref.string("Server to client Key", "", "The key used to encrypt traffic from the server to the client")

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
hop.fields.decrypted_data = ProtoField.bytes("hop.decrypted_data", "Decrypted Data")

local tube_type_name = {
	[1] = "ExecTube",
	[2] = "AuthGrantTube",
	[3] = "NetProxyTube",
	[4] = "UserAuthTube",
	[5] = "LocalPFTube",
	[6] = "RemotePFTube",
}

-- A mapping from tube ids to the type of tube
local tube_types = {}

hop_tube.fields.id = ProtoField.uint8("hop_tube.id", "Tube ID", base.DEC)
hop_tube.fields.flags = ProtoField.uint8("hop_tube.data_length", "Tube flags", base.HEX)
hop_tube.fields.data_length = ProtoField.uint8("hop_tube.data_length", "Tube Data Length", base.DEC)
hop_tube.fields.type = ProtoField.uint8("hop_tube.type", "Tube Type", base.DEC, tube_type_name)
hop_tube.fields.ack_no = ProtoField.uint16("hop_tube.ack_no", "Tube Ack No", base.DEC)
hop_tube.fields.frame_no = ProtoField.uint16("hop_tube.frame_no", "Tube Frame No", base.DEC)
hop_tube.fields.data = ProtoField.bytes("hop_tube.data", "Tube Data")


hop_tube.fields.exec_type = ProtoField.uint8("hop_tube.exec.type", "Exec Type", base.DEC, {
  [1] = "defaultShell", [2] = "specificCmd"
})
hop_tube.fields.exec_cmd_len = ProtoField.uint32("hop_tube.exec.cmd_len", "Exec Cmd Length")
hop_tube.fields.exec_cmd = ProtoField.string("hop_tube.exec_cmd", "Exec Cmd")
hop_tube.fields.exec_term_len = ProtoField.uint32("hop_tube.exec.term_len", "Exec Term Length")
hop_tube.fields.exec_term = ProtoField.string("hop_tube.exec_term", "Exec TERM")

hop_tube.fields.exec_res = ProtoField.uint8("hop_tube.exec_res", "Exec Response Code", base.DEC, {
  [1] = "execConf", [2] = "execFail"
})
hop_tube.fields.exec_err_len = ProtoField.uint32("hop_tube.exec.err_len", "Exec Err Length")
hop_tube.fields.exec_err = ProtoField.string("hop_tube.exec_err", "Exec Err")

-- TODO: debate name/severity
hop_tube.experts.data_short = ProtoExpert.new("hop_tube.data_short", "Hop tube data short", expert.group.MALFORMED, expert.severity.ERROR)

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
function transport(tree, buffer, pinfo, ptree)
	tree:add(buffer(1,3), "Reserved")
	tree:add(hop.fields.session_id, buffer(4,4))
	tree:add(hop.fields.counter, buffer(8, 8))
	tree:add(hop.fields.encrypted_data, buffer(16, buffer:len()-32))

	local pt, err = read_packet(buffer:bytes():raw(), convert_key(hop.prefs.client_to_server_key))
	if err ~= 0 then
    pt, err = read_packet(buffer:bytes():raw(), convert_key(hop.prefs.server_to_client_key))
  end
	if err == 0 then
    local decrypted = ByteArray.new(pt, true):tvb("HOP Transport Decrypted Data")
    tree:add(hop.fields.decrypted_data, decrypted(0, decrypted:len()))
    Dissector.get("hop_tube"):call(decrypted, pinfo, ptree)
  end
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
  -- Lua silently ignores extra args, but note that as of now transport is the
  -- only one that needs pinfo/ptree
	if (func) then func(subtree, buffer, pinfo, ptree) end
end

function hop_tube.dissector(buffer, pinfo, ptree)
	pinfo.cols.protocol = "HOP Tube"
	local subtree = ptree:add(hop_tube, buffer())
  local tube_id = buffer(0, 1)
  subtree:add(hop_tube.fields.id, tube_id)
  local tube_id = tube_id:uint()
  local flags = buffer(1, 1):uint()
  local flags_str = ""
  if bit.band(flags, 1) ~= 0 then flags_str = flags_str .. " REQ" end
  if bit.band(flags, 2) ~= 0 then flags_str = flags_str .. " RESP" end
  if bit.band(flags, 4) ~= 0 then flags_str = flags_str .. " REL" end
  if bit.band(flags, 8) ~= 0 then flags_str = flags_str .. " ACK" end
  if bit.band(flags, 16) ~= 0 then flags_str = flags_str .. " FIN" end
  subtree:add(hop_tube.fields.flags, buffer(1, 1)):append_text(flags_str)
  local data_length = buffer(2, 2)
  subtree:add(hop_tube.fields.data_length, data_length)
  data_length = data_length:uint()
  subtree:add(hop_tube.fields.frame_no, buffer(8, 4))
  local data_tree
  if data_length + 12 > buffer:len() then
    data_tree = subtree:add(hop_tube.fields.data, buffer(12, buffer:len() - 12))
    data_tree:add_proto_expert_info(hop_tube.experts.data_short)
  else
    data_tree = subtree:add(hop_tube.fields.data, buffer(12, data_length))
  end
  -- If this is an initiate packet (REQ/RES set)
  if bit.band(flags, 3) ~= 0 then
    subtree:add(hop_tube.fields.type, buffer(6, 1))
    tube_types[tube_id] = buffer(6, 1):uint()
  else
    subtree:add(hop_tube.fields.ack_no, buffer(4, 4))
    if tube_types[tube_id] == 1 then -- ExecTube
      local frameno = buffer(8, 4):uint()
      local ackno = buffer(4, 4):uint()
      if data_length > 0 and frameno == 1 then
        if ackno == 1 then
          -- This is the initial message from the client to the server
          local cmd_type = buffer(12, 1)
          local cmd_len = buffer(13, 4)
          local cmd = buffer(17, cmd_len:uint())
          local term_len = buffer(17 + cmd_len:uint(), 4)
          local term = buffer(21 + cmd_len:uint(), term_len:uint())
          data_tree:add(hop_tube.fields.exec_type, cmd_type)
          data_tree:add(hop_tube.fields.exec_cmd_len, cmd_len)
          data_tree:add(hop_tube.fields.exec_cmd, cmd)
          data_tree:add(hop_tube.fields.exec_term_len, term_len)
          data_tree:add(hop_tube.fields.exec_term, term)
        elseif ackno == 2 then
          -- This is the response from the server to the client
          local exec_res = buffer(12, 1)
          data_tree:add(hop_tube.fields.exec_res, exec_res)
          exec_res = exec_res:uint()
          if exec_res ~= 1 then
            local err_len = buffer(13, 4)
            local err = buffer(17, err_len:uint())
            data_tree:add(hop_tube.fields.exec_err_len, err_len)
            data_tree:add(hop_tube.fields.exec_err, err)
          end
        end
      end
    elseif tube_types[tube_id] == 2 then -- AuthgrantProxyTube
    end
  end
end

-- Register Hop on port 77
udp_table = DissectorTable.get("udp.port")
udp_table:add(77, hop) 
