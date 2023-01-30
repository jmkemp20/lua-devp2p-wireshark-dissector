--
-- @brief Ethereum devp2p Protocol dissector plugin
-- @author Joshua Kemp
-- @date 2022.07
-- @version 0.1
--

local python = require 'python'

-- Temporary for development
-- local sys = python.import 'sys'
-- sys.path.append('/home/jkemp/cs700/pydevp2p/')
-- End of Temporary for development

local pydevp2p = python.import 'pydevp2p.bridge'

-- create a new dissector
local NAME = "devp2p"
local devp2p = Proto(NAME, "Ethereum devp2p Protocol")

local types = {
    [1] = "PING",
    [2] = "PONG",
    [3] = "FindNode",
    [4] = "Neighbors",
    [5] = "ENRRequest",
    [6] = "ENRResponse"
}

-- create fields of devp2p
local fields = devp2p.fields
fields.hash = ProtoField.bytes(NAME .. ".hash", "Hash")
fields.sign = ProtoField.bytes(NAME .. ".sign", "Sign")
fields.type = ProtoField.uint8(NAME .. ".type", "Type", base.DEC, types)
fields.header = ProtoField.bytes(NAME .. ".payload", "Header")
fields.payload = ProtoField.bytes(NAME .. ".payload", "Payload")

local function array_iterator(array, len)
    -- This lets us iterate over a c object (like a python array)
    local index = 0
    local count = len

    -- The closure function is returned

    return function()
        index = index + 1

        if index <= count
        then
            -- return the current element of the iterator
            return array[index]
        end

    end
end

-- dissect packet
function devp2p.dissector(tvb, pinfo, tree)
    local subtree = tree:add(devp2p, tvb())
    local offset = 0

    -- show protocol name in protocol column
    pinfo.cols.protocol = devp2p.name

    local srcaddr = tostring(pinfo.src)
    local dstaddr = tostring(pinfo.dst)

    local payload = tostring(tvb:bytes())

    -- first check for discv4 then if nil discv5
    local msg = pydevp2p.handleDiscv4Msg(srcaddr, dstaddr, payload, pinfo.visited, pinfo.number)
    if msg ~= nil then
        local header = msg[0]
        local packet = msg[1]
        local type = msg[2]
        pinfo.cols.info:set(pinfo.src_port .. " → " .. pinfo.dst_port .. " " .. type .. " Len=" .. tvb:len())
        -- hash value
        local hash = tvb(offset, 32)
        subtree:add(fields.hash, hash)
        offset = offset + 32
        -- sig value
        local sign = tvb(offset, 65)
        subtree:add(fields.sign, sign)
        offset = offset + 65
        -- type value
        subtree:add(fields.type, tvb(offset, 1))
        offset = offset + 1
        -- payload data
        local payloadtree = subtree:add(fields.payload, tvb(offset))
        for element in array_iterator(packet, packet[0]) do
            payloadtree:add(element)
        end

        -- return since there won't be another packet type
        return
    end
    msg = pydevp2p.handleDiscv5Msg(srcaddr, dstaddr, payload, pinfo.visited, pinfo.number)
    if msg ~= nil then
        local header = msg[0]
        local header_size = msg[1]
        local packet = msg[2]
        local type = msg[3]
        pinfo.cols.info:set(pinfo.src_port .. " → " .. pinfo.dst_port .. " " .. type .. " Len=" .. tvb:len())
        -- Show the header information
        if header ~= nil then
            local header_tree = subtree:add(fields.header, tvb(0, header_size))
            for element in array_iterator(header, header[0]) do
                header_tree:add(element)
            end
        end
        -- Show the packet information
        if packet ~= nil then
            local packet_tree = subtree:add(fields.payload, tvb(header_size))
            for element in array_iterator(packet, packet[0]) do
                packet_tree:add(element)
            end
        end
        return
    end
end

-- register this dissector
DissectorTable.get("udp.port"):add("30303", devp2p)
DissectorTable.get("udp.port"):add("30304", devp2p)
DissectorTable.get("udp.port"):add("30305", devp2p)
DissectorTable.get("udp.port"):add("30306", devp2p)
DissectorTable.get("udp.port"):add("30307", devp2p)
DissectorTable.get("udp.port"):add("30308", devp2p)
