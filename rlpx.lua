local python = require 'python'

-- Temporary for development
local sys = python.import 'sys'
sys.path.append('../pydevp2p/')
-- End of Temporary for development

local crypto_secp256k1 = python.import 'pydevp2p.crypto.secp256k1'
local discover_v4wire = python.import 'pydevp2p.discover.v4wire'
local pyrlpx = python.import 'pydevp2p.rlpx'
local utils = python.import 'pydevp2p.utils'

-- Setup known nodes
local boot_priv_static_k = "3028271501873c4ecf501a2d3945dcb64ea3f27d6f163af45eb23ced9e92d85b"
local node1_priv_static_k = "4622d11b274848c32caf35dded1ed8e04316b1cde6579542f0510d86eb921298"
local node2_priv_static_k = "816efc6b019e8863c382fe94cefe8e408d53697815590f03ce0a5cbfdd5f23f2"
local node3_priv_static_k = "3fadc6b2fbd8c7cf1b2292b06ebfea903813b18b287dc29970a8a3aa253d757f"
local bootnode = pyrlpx.add_new_node("192.168.2.20", utils.hex_to_bytes(boot_priv_static_k))
local node1 = pyrlpx.add_new_node("192.168.3.30", utils.hex_to_bytes(node1_priv_static_k))
local node2 = pyrlpx.add_new_node("192.168.4.40", utils.hex_to_bytes(node2_priv_static_k))
local node3 = pyrlpx.add_new_node("192.168.5.50", utils.hex_to_bytes(node3_priv_static_k))

-- create a new dissector
local NAME = "rlpx"
local PORT = 30305
local rlpx = Proto(NAME, "Ethereum RLPx Protocol")

local fields = rlpx.fields
fields.auth_size = ProtoField.uint16(NAME .. ".auth_size", "Auth Size")
fields.ack_size = ProtoField.uint16(NAME .. ".ack_size", "Ack Size")
fields.body = ProtoField.bytes(NAME .. ".body", "Data")

local known_ports = { 30303, 30304, 30305, 30306, 30307, 30308 }

local function table_has_value(tab, val)
    for index, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

-- main dissect packet function
function rlpx.dissector(tvb, pinfo, tree)
    local subtree = tree:add(rlpx, tvb())
    local offset = 0

    -- show protocol name in protocol column
    pinfo.cols.protocol = rlpx.name

    local srcaddr = tostring(pinfo.src)
    local dstaddr = tostring(pinfo.dst)
    if srcaddr == node1.ipaddr then
        print("Found node1", srcaddr)
    end

    local srcNode = pyrlpx.all_nodes.get(srcaddr)
    local dstNode = pyrlpx.all_nodes.get(dstaddr)

    local payload = tostring(tvb:bytes())

    -- dissect field one by one, and add to protocol tree
    local auth_size = tvb(offset, 2)
    if (tvb:len() - auth_size:int() == 2) then
        if (table_has_value(known_ports, pinfo.src_port)) then
            -- This is most likely a handshake AUTH-ACK packet
            offset = offset + 2
            subtree:add(fields.ack_size, auth_size)
            pinfo.cols.info:set(pinfo.src_port .. " → " .. pinfo.dst_port .. " RLPx Handshake (ACK)")
            print(payload, dstNode)
            local authack_msg = dstNode.readHandshakeMsg(payload)
            print(authack_msg)
        elseif (table_has_value(known_ports, pinfo.dst_port)) then
            -- This is most likely a handshake AUTH packet
            offset = offset + 2
            subtree:add(fields.auth_size, auth_size)
            pinfo.cols.info:set(pinfo.src_port .. " → " .. pinfo.dst_port .. " RLPx Handshake (AUTH)")
        end
        subtree:add(fields.body, tvb(offset))
    end
end

-- register this dissector
DissectorTable.get("tcp.port"):add(PORT, rlpx)
DissectorTable.get("tcp.port"):add("30303", rlpx)
DissectorTable.get("tcp.port"):add("30308", rlpx)
DissectorTable.get("tcp.port"):add("30307", rlpx)
