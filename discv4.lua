--
-- @brief Ethereum devp2p Protocol dissector plugin
-- @author Joshua Kemp
-- @date 2022.07
-- @version 0.1
--

-- create a new dissector
local NAME = "devp2p"
local PORT = 30305
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
fields.payload = ProtoField.bytes(NAME .. ".payload", "Payload")

-- create ping fields
fields.ping_version = ProtoField.bytes(NAME .. ".payload.ping_version", "Version")
fields.ping_from = ProtoField.bytes(NAME .. ".payload.ping_from", "From")
fields.ping_from_ip = ProtoField.bytes(NAME .. ".payload.ping_from.ip", "IP")
fields.ping_from_udp = ProtoField.bytes(NAME .. ".payload.ping_from.udp", "UDP Port")
fields.ping_from_tcp = ProtoField.bytes(NAME .. ".payload.ping_from.tcp", "TCP Port")
fields.ping_to = ProtoField.bytes(NAME .. ".payload.ping_to", "To")
fields.ping_to_ip = ProtoField.bytes(NAME .. ".payload.ping_to.ip", "IP")
fields.ping_to_port = ProtoField.bytes(NAME .. ".payload.ping_to.port", "Port")
fields.ping_expiration = ProtoField.bytes(NAME .. ".payload.ping_expiration", "Expiration")
fields.ping_enrseq = ProtoField.bytes(NAME .. ".payload.ping_enrseq", "ENR Seq")

function rlp_decode(input)
  if (input == nil or input == '')
  then
    return
  end

  local output = ""
  local offset, dataLen, type = decode_length(input, #input)
  if type == 'str' then
    output = string.sub(input, offset + 1, dataLen + offset)
  elseif type == 'list' then
    output = output .. "["
    local list_buf = string.sub(input, offset + 1, offset + dataLen)
    -- message(string.tohex(list_buf))
    local offset = 1
    while offset < #list_buf do
      local buf = string.sub(list_buf, offset, #list_buf)
      -- message(string.tohex(buf))
      local _offset, _dataLen, _type = decode_length(buf, #buf)

      local vbuf = ''
      if _offset > 1 then
        vbuf = string.sub(buf, 1, _offset + _dataLen)
      else
        vbuf = string.sub(buf, _offset, _offset + _dataLen)
      end
      -- message(_offset, _dataLen, _type, string.tohex(vbuf) )
      local v = rlp_decode(vbuf)
      -- message(_offset, _dataLen, _type, string.tohex(v) )
      -- message(v)

      if #output > 1 then
        output = output .. ", "
      end
      if _type == "str" then
        output = output .. "\"" .. string.tohex(v) .. "\""
      else
        output = output .. v
      end

      offset = offset + _offset + _dataLen
    end
    output = output .. "]"
  end

  -- output + rlp_decode(substr(input, offset + dataLen))
  return output
end

function decode_length(input, length)
  if (input == nil or input == '')
  then
    return
  end
  local prefix = string.byte(input)
  if prefix <= 0x7f then
    return 0, 1, 'str'
  elseif prefix <= 0xb7 and length >= prefix - 0x80 then
    local strLen = prefix - 0x80
    return 1, strLen, 'str'
  elseif prefix <= 0xbf and length > prefix - 0xb7 and
      length > prefix - 0xb7 + string.byte(string.sub(input, 2, prefix - 0xb7 + 1)) then
    local lenOfStrLen = prefix - 0xb7
    local strLen = bytes_to_int(string.sub(input, 2, lenOfStrLen + 1))
    return 1 + lenOfStrLen, strLen, 'str'
  elseif prefix <= 0xf7 and length > prefix - 0xc0 then
    local listLen = prefix - 0xc0;
    return 1, listLen, 'list'
  elseif prefix <= 0xff and length > prefix - 0xf7 and
      length >= prefix - 0xf7 + string.byte(string.sub(input, 2, prefix - 0xf7 + 1)) then
    local lenOfListLen = prefix - 0xf7
    local listLen = bytes_to_int(string.sub(input, 2, lenOfListLen + 1))
    return 1 + lenOfListLen, listLen, 'list'
  else
    message("input don't conform RLP encoding form")
  end
end

function string.fromhex(str)
  return (str:gsub('..', function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

function string.tohex(str)
  return (str:gsub('.', function(c)
    return string.format('%02x', string.byte(c))
  end))
end

function string.toip(hexstr)
  local ipbytes = string.fromhex(hexstr)
  return string.byte(ipbytes, 1) ..
      "." .. string.byte(ipbytes, 2) .. "." .. string.byte(ipbytes, 3) .. "." .. string.byte(ipbytes, 4)
end

function string.remove_quoted(str)
  return string.sub(str, 2, -2)
end

function string.toport(hexstr)
  local portbytes = string.fromhex(hexstr)
  return string.byte(portbytes, 1) * 256 + string.byte(portbytes, 2)
end

function bytes_to_int(str, endian, signed) -- use length of string to determine 8,16,32,64 bits
  local t = { str:byte(1, -1) }
  if endian == "big" then --reverse bytes
    local tt = {}
    for k = 1, #t do
      tt[#t - k + 1] = t[k]
    end
    t = tt
  end
  local n = 0
  for k = 1, #t do
    n = n + t[k] * 2 ^ ((k - 1) * 8)
  end
  if signed then
    n = (n > 2 ^ (#t - 1) - 1) and (n - 2 ^ #t) or n -- if last bit set, negative.
  end
  return n
end

function table_to_string(tbl)
  local result = "{"
  for k, v in pairs(tbl) do
    -- Check the key type (ignore any numerical keys - assume its an array)
    if type(k) == "string" then
      result = result .. "[\"" .. k .. "\"]" .. "="
    end

    -- Check the value type
    if type(v) == "table" then
      result = result .. table_to_string(v)
    elseif type(v) == "boolean" then
      result = result .. tostring(v)
    else
      result = result .. "\"" .. v .. "\""
    end
    result = result .. ","
  end
  -- Remove leading commas from the result
  if result ~= "" then
    result = result:sub(1, result:len() - 1)
  end
  return result .. "}"
end

----------------------------------------
-------------------------------------------------------------------------------
-- Decode
-------------------------------------------------------------------------------

local parse

local function create_set(...)
  local res = {}
  for i = 1, select("#", ...) do
    res[select(i, ...)] = true
  end
  return res
end

local space_chars  = create_set(" ", "\t", "\r", "\n")
local delim_chars  = create_set(" ", "\t", "\r", "\n", "]", "}", ",")
local escape_chars = create_set("\\", "/", '"', "b", "f", "n", "r", "t", "u")
local literals     = create_set("true", "false", "null")

local literal_map = {
  ["true"] = true,
  ["false"] = false,
  ["null"] = nil,
}


local function next_char(str, idx, set, negate)
  for i = idx, #str do
    if set[str:sub(i, i)] ~= negate then
      return i
    end
  end
  return #str + 1
end

local function decode_error(str, idx, msg)
  local line_count = 1
  local col_count = 1
  for i = 1, idx - 1 do
    col_count = col_count + 1
    if str:sub(i, i) == "\n" then
      line_count = line_count + 1
      col_count = 1
    end
  end
  error(string.format("%s at line %d col %d", msg, line_count, col_count))
end

local function codepoint_to_utf8(n)
  -- http://scripts.sil.org/cms/scripts/page.php?site_id=nrsi&id=iws-appendixa
  local f = math.floor
  if n <= 0x7f then
    return string.char(n)
  elseif n <= 0x7ff then
    return string.char(f(n / 64) + 192, n % 64 + 128)
  elseif n <= 0xffff then
    return string.char(f(n / 4096) + 224, f(n % 4096 / 64) + 128, n % 64 + 128)
  elseif n <= 0x10ffff then
    return string.char(f(n / 262144) + 240, f(n % 262144 / 4096) + 128,
      f(n % 4096 / 64) + 128, n % 64 + 128)
  end
  error(string.format("invalid unicode codepoint '%x'", n))
end

local function parse_unicode_escape(s)
  local n1 = tonumber(s:sub(3, 6), 16)
  local n2 = tonumber(s:sub(9, 12), 16)
  -- Surrogate pair?
  if n2 then
    return codepoint_to_utf8((n1 - 0xd800) * 0x400 + (n2 - 0xdc00) + 0x10000)
  else
    return codepoint_to_utf8(n1)
  end
end

local function parse_string(str, i)
  local has_unicode_escape = false
  local has_surrogate_escape = false
  local has_escape = false
  local last
  for j = i + 1, #str do
    local x = str:byte(j)

    if x < 32 then
      decode_error(str, j, "control character in string")
    end

    if last == 92 then -- "\\" (escape char)
      if x == 117 then -- "u" (unicode escape sequence)
        local hex = str:sub(j + 1, j + 5)
        if not hex:find("%x%x%x%x") then
          decode_error(str, j, "invalid unicode escape in string")
        end
        if hex:find("^[dD][89aAbB]") then
          has_surrogate_escape = true
        else
          has_unicode_escape = true
        end
      else
        local c = string.char(x)
        if not escape_chars[c] then
          decode_error(str, j, "invalid escape char '" .. c .. "' in string")
        end
        has_escape = true
      end
      last = nil

    elseif x == 34 then -- '"' (end of string)
      local s = str:sub(i + 1, j - 1)
      if has_surrogate_escape then
        s = s:gsub("\\u[dD][89aAbB]..\\u....", parse_unicode_escape)
      end
      if has_unicode_escape then
        s = s:gsub("\\u....", parse_unicode_escape)
      end
      if has_escape then
        s = s:gsub("\\.", escape_char_map_inv)
      end
      return s, j + 1

    else
      last = x
    end
  end
  decode_error(str, i, "expected closing quote for string")
end

local function parse_number(str, i)
  local x = next_char(str, i, delim_chars)
  local s = str:sub(i, x - 1)
  local n = tonumber(s)
  if not n then
    decode_error(str, i, "invalid number '" .. s .. "'")
  end
  return n, x
end

local function parse_literal(str, i)
  local x = next_char(str, i, delim_chars)
  local word = str:sub(i, x - 1)
  if not literals[word] then
    decode_error(str, i, "invalid literal '" .. word .. "'")
  end
  return literal_map[word], x
end

local function parse_array(str, i)
  local res = {}
  local n = 1
  i = i + 1
  while 1 do
    local x
    i = next_char(str, i, space_chars, true)
    -- Empty / end of array?
    if str:sub(i, i) == "]" then
      i = i + 1
      break
    end
    -- Read token
    x, i = parse(str, i)
    res[n] = x
    n = n + 1
    -- Next token
    i = next_char(str, i, space_chars, true)
    local chr = str:sub(i, i)
    i = i + 1
    if chr == "]" then break end
    if chr ~= "," then decode_error(str, i, "expected ']' or ','") end
  end
  return res, i
end

local function parse_object(str, i)
  local res = {}
  i = i + 1
  while 1 do
    local key, val
    i = next_char(str, i, space_chars, true)
    -- Empty / end of object?
    if str:sub(i, i) == "}" then
      i = i + 1
      break
    end
    -- Read key
    if str:sub(i, i) ~= '"' then
      decode_error(str, i, "expected string for key")
    end
    key, i = parse(str, i)
    -- Read ':' delimiter
    i = next_char(str, i, space_chars, true)
    if str:sub(i, i) ~= ":" then
      decode_error(str, i, "expected ':' after key")
    end
    i = next_char(str, i + 1, space_chars, true)
    -- Read value
    val, i = parse(str, i)
    -- Set
    res[key] = val
    -- Next token
    i = next_char(str, i, space_chars, true)
    local chr = str:sub(i, i)
    i = i + 1
    if chr == "}" then break end
    if chr ~= "," then decode_error(str, i, "expected '}' or ','") end
  end
  return res, i
end

local char_func_map = {
  ['"'] = parse_string,
  ["0"] = parse_number,
  ["1"] = parse_number,
  ["2"] = parse_number,
  ["3"] = parse_number,
  ["4"] = parse_number,
  ["5"] = parse_number,
  ["6"] = parse_number,
  ["7"] = parse_number,
  ["8"] = parse_number,
  ["9"] = parse_number,
  ["-"] = parse_number,
  ["t"] = parse_literal,
  ["f"] = parse_literal,
  ["n"] = parse_literal,
  ["["] = parse_array,
  ["{"] = parse_object,
}


parse = function(str, idx)
  local chr = str:sub(idx, idx)
  local f = char_func_map[chr]
  if f then
    return f(str, idx)
  end
  decode_error(str, idx, "unexpected character '" .. chr .. "'")
end

local json = { _version = "0.1.1" }
function json.decode(str)
  if type(str) ~= "string" then
    error("expected argument of type string, got " .. type(str))
  end
  local res, idx = parse(str, next_char(str, 1, space_chars, true))
  idx = next_char(str, idx, space_chars, true)
  if idx <= #str then
    decode_error(str, idx, "trailing garbage")
  end
  return res
end

----------------------------------------

-- dissect packet
function devp2p.dissector(tvb, pinfo, tree)
  local subtree = tree:add(devp2p, tvb())
  local offset = 0

  -- show protocol name in protocol column
  pinfo.cols.protocol = devp2p.name

  -- dissect field one by one, and add to protocol tree
  local hash = tvb(offset, 32)
  subtree:add(fields.hash, hash)
  -- subtree:append_text(", hash: " .. hash)
  offset = offset + 32

  local sign = tvb(offset, 65)
  subtree:add(fields.sign, sign)
  -- subtree:append_text(", sign: " .. sign)
  offset = offset + 65

  local ptype = tvb(offset, 1):uint()
  subtree:add(fields.type, tvb(offset, 1))
  pinfo.cols.info:append(" (" .. types[ptype] .. ")")
  subtree:append_text(" (" .. types[ptype] .. ")")
  offset = offset + 1

  local payload = tvb(offset)
  local payloadtree = subtree:add(fields.payload, payload)

  ---- 协议细节
  local payloadhex = tostring(payload:bytes())
  local decodedvalue = rlp_decode(string.fromhex(payloadhex))
  -- local payloadtree = tree:add(subtree, payload)
  -- message(decodedvalue)

  -- For debugging purposes, set the payload tree to the decoded value
  payloadtree:set_text("Payload Data: " .. decodedvalue)

  if types[ptype] == "PING" then
    -- payloadtree:set_text(decodedvalue)
    local version, fromip, fromudpport, fromtcpport, toip, toport, expiration, enrseq = string.match(decodedvalue,
      '%[([^,]+), %[([^,]+), ([^,]+), ([^%]]+)%], %[([^,]+), ([^%]]+)%], ([^%]]+)%, ([^%]]+)%]')
    -- message(version .. fromip .. fromudpport,fromtcpport,toip,toport,expiration)
    offset = offset + 1
    payloadtree:add(fields.ping_version, tvb(offset, 1))
    payloadtree:append_text(string.remove_quoted(version))
    offset = offset + 1
    local ping_fromtree = payloadtree:add(fields.ping_from, tvb(offset, 11))
    --payloadtree:add("Version: " .. string.remove_quoted(version), tvb(offset, 6))
    ping_fromtree:set_text("From: " ..
      string.toip(string.remove_quoted(fromip)) .. ":" .. string.toport(string.remove_quoted(fromudpport)))
    offset = offset + 2
    local ping_from_ip = ping_fromtree:add(fields.ping_from_ip, tvb(offset, 4))
    ping_from_ip:set_text("IP: " .. string.toip(string.remove_quoted(fromip)))
    offset = offset + 4 + 1
    local ping_from_udp = ping_fromtree:add(fields.ping_from_udp, tvb(offset, 2))
    ping_from_udp:set_text("UDP Port: " .. string.toport(string.remove_quoted(fromudpport)))
    offset = offset + 2 + 1
    local ping_from_tcp = ping_fromtree:add(fields.ping_from_tcp, tvb(offset, 2))
    ping_from_tcp:set_text("TCP Port: " .. string.toport(string.remove_quoted(fromtcpport)))
    --payloadtree:add(fields.ping_from)
    --payloadtree:add("From:", string.toip(string.remove_quoted(fromip)) .. ":" .. string.toport(string.remove_quoted(fromudpport)))
    offset = offset + 2
    local ping_totree = payloadtree:add(fields.ping_to, tvb(offset, 10))
    ping_totree:set_text("To: " ..
      string.toip(string.remove_quoted(toip)) .. ":" .. string.toport(string.remove_quoted(toport)))
    offset = offset + 2
    local ping_to_ip = ping_totree:add(fields.ping_to_ip, tvb(offset, 4))
    ping_to_ip:set_text("IP: " .. string.toip(string.remove_quoted(toip)))
    offset = offset + 4 + 1
    local ping_to_port = ping_totree:add(fields.ping_to_port, tvb(offset, 2))
    ping_to_port:set_text("Port: " .. string.toport(string.remove_quoted(toport)))
    --payloadtree:add("To:", string.toip(string.remove_quoted(toip)) .. ":" .. string.toport(string.remove_quoted(toport)))
    offset = offset + 2 + 2
    local ping_exp = payloadtree:add(fields.ping_expiration, tvb(offset, 4))
    ping_exp:set_text("Expiration: " .. os.date('%b %d, %Y %X', tonumber(string.remove_quoted(expiration), 16)))
    --payloadtree:add("Expiration:", os.date('%b %d, %Y %X', tonumber(string.remove_quoted(expiration),16)))
    offset = offset + 4 + 1
    local ping_enrseq = payloadtree:add(fields.ping_expiration, tvb(offset, 6))
    ping_enrseq:set_text("ENR Sequence #: " .. string.remove_quoted(enrseq))
    --payloadtree:add("ENR Sequence #:", string.remove_quoted(enrseq))
    payloadtree:set_text("Payload Data: (PING)")
  elseif types[ptype] == "PONG" then
    -- payloadtree:set_text(decodedvalue)
    local toip, toudpport, totcpport, replyhash, expiration, enrseq = string.match(decodedvalue,
      '%[%[([^,]+), ([^,]+), ([^%]]+)%], ([^,]+), ([^%]]+)%, ([^%]]+)%]')
    payloadtree:add("To:",
      string.toip(string.remove_quoted(toip)) .. ":" .. string.toport(string.remove_quoted(toudpport)),
      string.toport(string.remove_quoted(totcpport)))
    payloadtree:add("Hash:", string.remove_quoted(replyhash))
    payloadtree:add("Expiration:", os.date('%b %d, %Y %X', tonumber(string.remove_quoted(expiration), 16)))
    payloadtree:add("ENR Sequence #:", string.remove_quoted(enrseq))
    payloadtree:set_text("Payload Data: (PONG)")
  elseif types[ptype] == "FindNode" then
    -- payloadtree:set_text(decodedvalue)
    payloadtree:set_text("Payload Data: (FindNode)")
    local target, expiration = string.match(decodedvalue, '%[([^,]+), ([^%]]+)%]')
    payloadtree:add("Target:", target)
    payloadtree:add("Expiration:", os.date('%b %d, %Y %X', tonumber(string.remove_quoted(expiration), 16)))
  elseif types[ptype] == "Neighbors" then
    -- payloadtree:set_text(decodedvalue)
    -- message(decodedvalue)
    local tablev = json.decode(decodedvalue)
    local cnt = 0
    -- payloadtree:set_text("Neighbors")
    for i, v in ipairs(tablev) do
      if type(v) == "table" then
        for j, jv in ipairs(v) do
          if type(jv) == "table" then
            -- 这就是节点了
            payloadtree:add(string.toip(jv[1]) .. ":" .. string.toport(jv[2]), string.toport(jv[3]), jv[4])
            cnt = cnt + 1
          else
            payloadtree:add(jv)
          end
        end
      else
        payloadtree:add("Expiration:", os.date('%b %d, %Y %X', tonumber(v, 16)))
      end
    end
    payloadtree:set_text("Payload Data: (Neighbors (" .. cnt .. "))")
  elseif types[ptype] == "ENRRequest" then
    local expiration = string.match(decodedvalue, '%[([^,]+)%]')
    -- payloadtree:set_text(decodedvalue)
    payloadtree:add("Expiration:", os.date('%b %d, %Y %X', tonumber(string.remove_quoted(expiration), 16)))
    payloadtree:set_text("Payload Data: (ENRRequest)")
  elseif types[ptype] == "ENRResponse" then
    payloadtree:set_text("Payload Data: (ENRResponse)")
    local requesthash = string.match(decodedvalue, '%[([^,]+)')

    payloadtree:add("Request Hash:", string.remove_quoted(requesthash))

    local enr_table = json.decode(decodedvalue)[2]
    local cnt = 0
    local enrtree = payloadtree:add("ENR:")
    -- The following three fields "always" exists
    enrtree:add("Signature:", enr_table[1])
    enrtree:add("Sequence Num:", enr_table[2])
    for i, v in ipairs(enr_table) do
      if type(v) == "table" then
        -- for j,jv in ipairs(v) do
        --     if type(jv) == "table" then
        --         -- 这就是节点了
        --         enrtree:add()
        --         cnt = cnt + 1
        --     else
        --         enrtree:add(jv)
        --     end
        -- end
      else
        if (i % 2 ~= 0 and i > 2) then
          local key = string.fromhex(v)
          local output = key .. ": "
          if (key == "id") then
            enrtree:add(output .. string.fromhex(enr_table[i + 1]))
          elseif (key == "ip") then
            enrtree:add(output .. string.toip(enr_table[i + 1]))
          elseif (key == "tcp" or key == "udp") then
            enrtree:add(output .. string.toport(enr_table[i + 1]))
          elseif (key == "eth") then
            -- This is an "eth" ENR entry
            -- https://github.com/ethereum/devp2p/blob/master/enr-entries/eth.md
            enrtree:add(output .. enr_table[i + 1][1][1])
          else
            enrtree:add(output .. tostring(enr_table[i + 1]))
          end
        end
      end
    end
  else
    payloadtree:set_text(decodedvalue)
  end
end

-- register this dissector
DissectorTable.get("udp.port"):add(PORT, devp2p)
DissectorTable.get("udp.port"):add("30303", devp2p)
DissectorTable.get("udp.port"):add("30308", devp2p)
DissectorTable.get("udp.port"):add("30307", devp2p)
