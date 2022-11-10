local python = require 'python'
local g = python.globals()

-- Temporary for development
local sys = python.import 'sys'
sys.path.append('../pydevp2p/')
-- End of Temporary for development

local crypto_secp256k1 = python.import 'pydevp2p.crypto.secp256k1'
local discover_v4wire = python.import 'pydevp2p.discover.v4wire'
local rlpx = python.import 'pydevp2p.rlpx'
local utils = python.import 'pydevp2p.utils'

local show_prints = true

--could offer function wrappers--
local function privtopub(privk)
    return crypto_secp256k1.privtopub(privk)
end

-- Verify secp256k1
print("Verifying pydevp2p.crypto.secp256k1")

--The private keys of each of the GETH nodes, found in ~/.ethereum/geth/nodekey
local boot_priv_static_k = "3028271501873c4ecf501a2d3945dcb64ea3f27d6f163af45eb23ced9e92d85b"
local node1_priv_static_k = "4622d11b274848c32caf35dded1ed8e04316b1cde6579542f0510d86eb921298"
local node2_priv_static_k = "816efc6b019e8863c382fe94cefe8e408d53697815590f03ce0a5cbfdd5f23f2"
local node3_priv_static_k = "3fadc6b2fbd8c7cf1b2292b06ebfea903813b18b287dc29970a8a3aa253d757f"

--Calculate the public keys for each node from each static private key
local boot_pub_static_k = privtopub(boot_priv_static_k)
local node1_pub_static_k = privtopub(node1_priv_static_k)
local node2_pub_static_k = privtopub(node2_priv_static_k)
local node3_pub_static_k = privtopub(node3_priv_static_k)

if show_prints then
    print("boot_pub_static_k:", utils.bytes_to_hex(boot_pub_static_k))
    print("node1_pub_static_k:", utils.bytes_to_hex(node1_pub_static_k))
    print("node2_pub_static_k:", utils.bytes_to_hex(node2_pub_static_k))
    print("node3_pub_static_k:", utils.bytes_to_hex(node3_pub_static_k))
end

-- Verify discv4
print("\nVerifying pydevp2p.discover.discv4wire")

local bootnode_discv4_ping_1 = utils.hex_to_bytes("40bf8030711146d71c79ea5dcae110bfb3c8416c539a347fda9fcb2e44c1d20836758034194a203595b8daf1d5fb597dc7e882fc5768302d64b2523cb2b3f97359fd8d19f58f5d98bd3a53e4af70e62fcde96880e33cf09261a420639e8705610101e304cb84c0a80214827661827661c984c0a8031e82766380846361feb986018436b7839a")
local bootnode_discv4_ping_2 = utils.hex_to_bytes("8e1f1258435e178b79dae737f6d327571f9bf9bf6289c14aa77b3f21c5b0048991d10f821d78cf6e72e0c16e258a367b10305b39b13c38c05b4923c8d1c88be65b82fa3d46ea9f3fef625b2b5d2a25dc1ec01760235a76bcff8b3ec5ee52cb020101e304cb84c0a80214827661827661c984c0a8053282766580846361feb986018436b7839a")
local bootnode_discv4_ping_3 = utils.hex_to_bytes("647c6f56d08158037cba6957fad410ee5223caa33aedf2a6db29be59e63b7f2f9584c4e5df58d2a32487b0024f8a02f4eef69fc673948a2f672f2bbf6fec3bb14f1fa2e996c901b607ab59296ad41ed29f854b2e9d302c91857ad6e27c18028c0001e304cb84c0a80214827661827661c984c0a8042882766480846361feed86018436b7839a")
local bootnode_discv4_neighbors_4 = utils.hex_to_bytes("91971de97dea27a70f75c0dd6e7f8ab4ce3a539e3ff7d7d73f60bcee5b507ea52a9313995aba796531ab4285b185f9ad938bfa7d57a9a9e14d4b44b3fb8d76452dcd6bc3ca02661b76a5fb984d13220b490175780b3dad9cbf94ce2857b6408c0004f8a5f89ef84d84c0a80428827664827664b8401ae68ad9b2b095b5366d9a725a184bf1a6a5e101a4e6a3de62b38b07eac2c8fe365e8a184004191c96d2f365f3c116c5dfbb92247635cf49a730f02908d6e397f84d84c0a8031e827663827663b840c35c2b7f9ae974d1eee94a003394d1cc18135e7fe6665e6b4f221970f1d9d59f6a58e76763803bcc9097eba4c91fd08b30405e65c53272b8635348e37f93cedc846361feee")

local fromkey_1 = discover_v4wire.decodeDiscv4(bootnode_discv4_ping_1)
local fromkey_2 = discover_v4wire.decodeDiscv4(bootnode_discv4_ping_2)
local fromkey_3 = discover_v4wire.decodeDiscv4(bootnode_discv4_ping_3)
local fromkey_4 = discover_v4wire.decodeDiscv4(bootnode_discv4_neighbors_4)

if show_prints then
    print("fromkey_1:", utils.bytes_to_hex(fromkey_1))
    print("fromkey_2:", utils.bytes_to_hex(fromkey_2))
    print("fromkey_3:", utils.bytes_to_hex(fromkey_3))
    print("fromkey_4:", utils.bytes_to_hex(fromkey_4))
end

-- Verify RLPx
print("\nVerifying pydevp2p.rlpx")
local test_auth_msg_c = utils.hex_to_bytes("019004195b7107a1d7a067ec2ccf17062d07191bf34d05557853999557766d1ee02c131fb6d00adadb833dbf794777ea0b85635b7f65fe0961e39877e6e4f35a161726cb988e62f9d674601360f35b04973edf04b9bd8d9db3ad7fa23c0e189f7d6d847de4ac9a4e444492185a3e0347a5b9475c5e8f4271846b7e5ece9da1f45437ef6768a85584b63821337ecb5097fdb6dd4ac6001d7cc05efd1386cfe6c0ea7259151a7cc275a2c3926408db21cc8961c9bd55b1601cff3bfae04e954448a36b69c2b606685ba44455601538e991693ae977549c71cd7e4eee3bc24cf6e7a7836b49ee3c31aed41a1c624f03d8d53ca0b0bf9c36741e4e6095184749ef5aea3e7e5d36d27ff6e1a9beed2ef30cf1fb2dd6028b803a530950e1cd2799a4f8494ffe7ee15efd06bdaf2d34316325cb55c80918b46ed94364ce91288ec3a541c1f0f42441895644c1b5f70ebfa31dd0eee312f7e8e1dc819f2035ef916e33275ffa8544177eec40e4fe1c3544c74c76d0da6f79d997282889fbfbefde531146a51460da8b0a32488b23af706c0ee002eb4d")
local text_ack_msg_c = utils.hex_to_bytes("019904084dc15ee4efbe60965cdc07cdd21a9a7a177d5568e1567c8f6f24943c3ab7b235be23b8234f7b494fa1134c332ffba5c39fba588b440041c6ced2eb6069d115dfba3b30d66e88a621f16663208f567ec1033015cb7f750d10aa70c109cce839eee6b2e2ee4ae3163773ecc1e72ea2c2b18500bfeef7c21cdb821480da7d7b34d4d62a31ecb81d92f62af1e35d31d3ba7935591979d6092ea23a38d86e1a60eefef17731e3c0cfd512f2cffa9c794d882c9ff4a18da7a4f4490467a6f3e7fd44cea921c870c7230d93bfcef656f24423fe3bb2267a00a0f03a782a7d431c25bbbed8ac982e0862866b7a2966d22137a8c1b60969ec92c416375eece54733778042ed5e6a8f3a63390793b70f50b4a6e32810d154bc6711aa5aa6d69256edf14b9817fabd6811af8afb6065bd6bd2f4845b0ada2434047636ba04eb49bc17b09414f672318196bfbe8c17b67419d4c3acd52ca3765f067648362b63b2e3c7e8a52503b21b3b46bdff159e05c9668dcf162afc5805310d816560a74c73ad0ababe33de259c5dcc1c6863e3c8c5936265385b5453757ff78792")
local dec_auth_msg = rlpx.read_handshake_msg(boot_priv_static_k, test_auth_msg_c)
local dec_ack_msg = rlpx.read_handshake_msg(node2_priv_static_k, text_ack_msg_c)

if show_prints then
    print("dec_auth_msg:", dec_auth_msg)
    print("dec_ack_msg:", dec_ack_msg)
end

-- Verify Python <-> Lua Dictionaries
print("\nTesting Python <-> Lua Dictionaries")
if show_prints then
    print("[before] 0 nodes:", rlpx.all_nodes)
end
local bootnode = rlpx.add_new_node("192.168.2.20", utils.hex_to_bytes(boot_priv_static_k))
local node1 = rlpx.add_new_node("192.168.3.30", utils.hex_to_bytes(node1_priv_static_k))
local node2 = rlpx.add_new_node("192.168.4.40", utils.hex_to_bytes(node2_priv_static_k))
local node3 = rlpx.add_new_node("192.168.5.50", utils.hex_to_bytes(node3_priv_static_k))
if show_prints then
    print("[after] 4 nodes:", rlpx.all_nodes)
end
rlpx.remove_node(node3.ipaddr)
if show_prints then
    print("[after] -1 node:", rlpx.all_nodes)
    print("complex nested:", utils.bytes_to_hex(rlpx.all_nodes.get(node1.ipaddr).pubK))
    print("[before] 0 node1.peers:", node1.peers)
    print("[before] 0 rlpx.all_nodes.get(node1.ipaddr).peers:", rlpx.all_nodes.get(node1.ipaddr).peers)
end
node1.addConnection(boot_pub_static_k, false, "192.168.2.20")
if show_prints then
    print("[after] 1 node1.peers: ", node1.peers)
    print("[after] 1 rlpx.all_nodes.get(node1.ipaddr).peers:", rlpx.all_nodes.get(node1.ipaddr).peers)
end
