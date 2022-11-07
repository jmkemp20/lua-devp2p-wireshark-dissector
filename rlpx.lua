
-- create a new dissector
local NAME = "rlpx"
local PORT = 30305
local rlpx = Proto(NAME, "Ethereum RLPx Protocol")

local fields = rlpx.fields
fields.auth_size = ProtoField.uint16 (NAME .. ".auth_size", "Auth Size")
fields.ack_size = ProtoField.uint16 (NAME .. ".ack_size", "Ack Size")
fields.body = ProtoField.bytes (NAME .. ".body", "Data")

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
function rlpx.dissector (tvb, pinfo, tree)
    local subtree = tree:add(rlpx, tvb())
    local offset = 0

    -- show protocol name in protocol column
    pinfo.cols.protocol = rlpx.name

    -- dissect field one by one, and add to protocol tree
    local auth_size = tvb(offset, 2)
    if (tvb:len() - auth_size:int() == 2) then
        if (table_has_value(known_ports, pinfo.src_port)) then
            -- This is most likely a handshake AUTH-ACK packet
            offset = offset + 2
            subtree:add(fields.ack_size, auth_size)
            pinfo.cols.info:set(pinfo.src_port .. " → " .. pinfo.dst_port .. " RLPx Handshake (ACK)")
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