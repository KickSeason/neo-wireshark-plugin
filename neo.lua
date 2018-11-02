--V1.1.0 2018-11-1
do
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    M_MAINNET = 0x00746e41
    M_TESTNET = 0x74746e41
    M_PRIVNET = 0x00099e81

    C_VERSION       = "version"
    C_VERSION_ACK   = "verack"
    C_GET_ADDR      = "getaddr"
    C_ADDR          = "addr"
    C_GET_HEADERS   = "getheaders"
    C_HEADERS       = "headers"
    C_GET_BLOCKS    = "getblocks"
    C_INV           = "inv"
    C_GET_DATA      = "getdata"
    C_TX            = "tx"
    C_BLOCK         = "block"

    TX_MINER        = 0x00
    TX_ISSUE        = 0x01
    TX_CLAIM        = 0x02
    TX_CONTRACT     = 0x80
    TX_INVOCATION   = 0xd1

    DATA_TX         = 0x01
    DATA_BLOCK      = 0x02
    DATA_CONCENSUS  = 0xe0
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    NET_TYPE = {
        [M_MAINNET] = "MainNet",
        [M_TESTNET] = "TestNet",
        [M_PRIVNET] = "PrivNet"
    }
    CMD_TYPE = {
        [C_VERSION]       = "VERSION",
        [C_VERSION_ACK]   = "VERACK",
        [C_GET_ADDR]      = "GETADR",
        [C_ADDR]          = "ADDR",
        [C_GET_HEADERS]   = "GETHEADERS",
        [C_HEADERS]       = "HEADERS",
        [C_GET_BLOCKS]    = "GETBLOCKS",
        [C_INV]           = "INV",
        [C_GET_DATA]      = "GETDATA",
        [C_TX]            = "TX",
        [C_BLOCK]         = "BLOCK"
    }
    DATA_TYPE = {
        [DATA_TX]           = "Txs",
        [DATA_BLOCK]        = "Blocks",
        [DATA_CONCENSUS]    = "Concensus"
    }
    TX_TYPE = {
        [TX_MINER]      = "MinerTx",
        [TX_ISSUE]      = "IssueTx",
        [TX_CLAIM]      = "ClaimTx",
        [TX_CONTRACT]   = "ContractTx",
        [TX_INVOCATION] = "InvocationTx",
    }
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local function dprint(...)
        info(table.concat({"Lua: ", ...}, " "))
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_hashes = Proto("Hashes", "hashes")
    neop2p_hashes.fields.count = ProtoField.uint8("hashes.count", "COUNT", base.DEC)
    neop2p_hashes.fields.hash = ProtoField.string("hashes.hash", "HASH", base.ASCII)

    local function neop2p_hashes_dissector(buffer,  pinfo, tree, offset)
        local count = buffer(offset, 1):le_uint()
        local index = 0

        local hashes_tree = tree:add(neop2p_hashes, buffer(offset, count * 32 + 1), "Hashes")
        hashes_tree:add(neop2p_hashes.fields.count, buffer(offset, 1), count)
        while (index < count) do
            hashes_tree:add(neop2p_hashes.fields.hash, buffer(offset + 1 + index * 32, 32), tostring(buffer(offset + 1 + index * 32, 32)))
            index = index + 1
        end
        return count * 32 + 1
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_script = Proto("script", "script")

    neop2p_script.fields.scriptlen = ProtoField.uint8("script.scriptlen", "SCRIPTLEN", base.DEC)
    neop2p_script.fields.script = ProtoField.string("script.script", "SCRIPT", base.ASCII)

    local function neop2p_script_dissector(buffer, pinfo, tree, offset, name)
        local scriptlen = buffer(offset, 1):le_uint()
        local script_tree = tree:add(neop2p_script, buffer(offset, scriptlen + 1), name.."Script")

        script_tree:add(neop2p_script.fields.scriptlen, buffer(offset, 1), scriptlen)
        script_tree:add(neop2p_script.fields.script, buffer(offset + 1, scriptlen), tostring(buffer(offset + 1, scriptlen)))
        return scriptlen + 1
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_coin = Proto("Coin", "coin reference")

    neop2p_coin.fields.prehash = ProtoField.string("coin.prehash", "PREHASH", base.DEC)
    neop2p_coin.fields.preindex = ProtoField.uint16("coin.preindex", "PREINDEX", base.DEC)

    local function neop2p_coin_dissector(buffer, pinfo, tree, offset)
        local coin_tree = tree:add(neop2p_coin, buffer(offset, 34), "COIN")
        coin_tree:add(neop2p_coin.fields.prehash, buffer(offset, 32), tostring(buffer(offset, 32)))
        coin_tree:add(neop2p_coin.fields.preindex, buffer(offset + 32, 2), buffer(offset, 2):le_uint())
        return 34
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_coins = Proto("Coins", "coin reference array")

    local function neop2p_coins_dissector(buffer, pinfo, tree, offset)
        local index = 0
        local count = buffer(offset, 1):le_uint()
        local coins_tree = tree:add(neop2p_coins, buffer(offset, count * 34), "COINS")

        while (index < count) do
            local result = neop2p_coin_dissector(buffer, pinfo, coins_tree, offset + index * count)
            index = index + 1
        end
        return count * 34 + 1
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_attr = Proto("Attribute", "transaction attribute")

    neop2p_attr.fields.usage = ProtoField.uint8("attr.usage", "USAGE", base.DEC)
    neop2p_attr.fields.length = ProtoField.uint8("attr.length", "LENGTH", base.DEC)
    neop2p_attr.fields.data = ProtoField.string("attr.data", "DATA", base.ASCII)

    local function neop2p_attr_dissector(buffer, pinfo, tree, offset)
    
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_tx = Proto("Transaction", "Neo P2P Transaction")

    neop2p_tx.fields.type = ProtoField.uint8("tx.type", "TYPE", base.DEC, TX_TYPE)
    neop2p_tx.fields.version = ProtoField.uint8("tx.version", "VERSION", base.DEC)
    ----exclusive
    --miner
    neop2p_tx.fields.nonce = ProtoField.uint32("tx.nonce", "NONCE", base.DEC)
    --claims
    --neop2p_tx.fields.claims = coins
    --invocation
    --neop2p_tx.fields.script = script
    neop2p_tx.fields.gas = ProtoField.uint8("tx.gas", "GAS", base.DEC)
    --attributes
    neop2p_tx.fields.attributes =

    local inputs = Proto("inputs", "tx inputs")
    inputs.fields.input = ProtoField.string("tx.inputs", "INPUTS", base.ASCII)
    local outputs = Proto("outputs", "tx outpus")
    outputs.fields.outputs = ProtoField.string("tx.outputs", "OUTPUTS", base.ASCII)
    neop2p_tx.fields.script = ProtoField.string("tx.script", "SCRIPT", base.ASCII)
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_block = Proto("Block", "Neo P2P Block")
    
    neop2p_block.fields.version = ProtoField.uint32("block.version", "VERSION", base.DEC)
    neop2p_block.fields.preblock = ProtoField.string("block.preblock", "PREBLOCK", base.ASCII)
    neop2p_block.fields.merkleroot = ProtoField.string("block.merkleroot", "MERKLEROOT", base.ASCII)
    neop2p_block.fields.timestamp = ProtoField.uint32("block.timestamp", "TIMESTAMP", base.DEC)
    neop2p_block.fields.index = ProtoField.uint32("block.index", "INDEX", base.DEC)
    neop2p_block.fields.consecsusdata = ProtoField.uint64("block.consecsusdata", "CONSECSUSDATA", base.DEC)
    neop2p_block.fields.nextconsensus = ProtoField.string("block.nextconsensus", "NEXTCONSENSUS", base.ASCII)
    neop2p_block.fields._ = ProtoField.uint8("block._", "_", base.DEC)
    neop2p_block.fields.scriptcount = ProtoField.uint8("block.scriptcount", "scriptcount", base.DEC)
    neop2p_block.fields.script = ProtoField.string("block.script", "SCRIPT", base.ASCII)
    neop2p_block.fields.txs = ProtoField.string("block.txs", "TXS", base.ASCII)

    local function neop2p_block_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local offset = 0

        local block_tree = tree:add(neop2p_block, buffer, "Block")

        block_tree:add(neop2p_block.fields.version, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        block_tree:add(neop2p_block.fields.preblock, buffer(offset, 32), tostring(buffer(offset, 32)))
        offset = offset + 32
        block_tree:add(neop2p_block.fields.merkleroot, buffer(offset, 32), tostring(buffer(offset, 32)))
        offset = offset + 32
        block_tree:add(neop2p_block.fields.timestamp, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        block_tree:add(neop2p_block.fields.index, buffer(offset, 4), buffer(offset, 4):le_uint())
        offset = offset + 4
        block_tree:add(neop2p_block.fields.consecsusdata, buffer(offset, 8), buffer(offset, 8):le_uint64())
        offset = offset + 8
        block_tree:add(neop2p_block.fields.nextconsensus, buffer(offset, 20), tostring(buffer(offset, 20)))
        offset = offset + 20
        block_tree:add(neop2p_block.fields._, buffer(offset, 1), buffer(offset, 1):le_uint())
        offset = offset + 1
        local result = neop2p_script_dissector(buffer, pinfo, block_tree, offset, "invocation")
        offset = offset + result
        result = neop2p_script_dissector(buffer, pinfo, block_tree, offset, "verify")
        offset = offset + result
        block_tree:add(neop2p_block.fields.txs, buffer(offset, len - offset), tostring(buffer(offset, len - offset)))
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_headers = Proto("Headers", "Neo P2P Headers")

    neop2p_headers.fields.count = ProtoField.uint8("count", "COUNT", base.DEC)

    local function neop2p_headers_dissector(buffer, pinfo, tree)
        local result = neop2p_hashes_dissector(buffer, pinfo, tree, 0)
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_getheaders = Proto("GetHeaders", "Neo P2P Get Headers")

    neop2p_getheaders.fields.count = ProtoField.uint8("count", "COUNT", base.DEC)
    neop2p_getheaders.fields.hash = ProtoField.string("hashstop", "HASHSTOP", base.ASCII)

    local function neop2p_getheaders_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local offset = 0
        local getheaders_tree = tree:add(neop2p_getheaders, buffer(0, len), "GetHeaders")
        local result = neop2p_hashes_dissector(buffer, pinfo, getheaders_tree, 0)
        offset = offset + result
        getheaders_tree:add(neop2p_getheaders.fields.hash, buffer(offset, 32), tostring(buffer(offset, 32)))
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_ver = Proto("Version", "Neo P2P Version")

    neop2p_ver.fields.version = ProtoField.uint32("version.version", "VERSION", base.DEC)
    neop2p_ver.fields.services = ProtoField.uint64("version.services", "SERVICES", base.DEC)
    neop2p_ver.fields.timestamp = ProtoField.uint32("version.timestamp", "TIMESTAMP", base.DEC)
    neop2p_ver.fields.port = ProtoField.uint16("version.port", "PORT", base.DEC)
    neop2p_ver.fields.nonce = ProtoField.uint32("version.nonce", "NONCE", base.DEC)
    neop2p_ver.fields.useragent = ProtoField.string("version.useragent", "USERAGENT", base.ASCII)
    neop2p_ver.fields.height = ProtoField.uint32("version.height", "HEIGHT", base.DEC)
    neop2p_ver.fields.relay = ProtoField.bool("version.relay", "RELAY", base.NONE)

    local function neop2p_ver_dissector(buffer, pinfo, tree)
        local L = buffer:len()
        local useragent_len = L - 27
        
        local ver_tree = tree:add(neop2p_ver, buffer(0, L), "Version")
        local offset = 0
        ver_tree:add(neop2p_ver.fields.version, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
        offset = offset + 4
        ver_tree:add(neop2p_ver.fields.services, buffer(offset, 8), buffer(offset, 8):le_uint64())
        offset = offset + 8
        ver_tree:add(neop2p_ver.fields.timestamp, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
        offset = offset + 4
        ver_tree:add(neop2p_ver.fields.port, buffer(offset, 2), buffer(offset, 2):le_uint64():tonumber())
        offset = offset + 2
        ver_tree:add(neop2p_ver.fields.nonce, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
        offset = offset + 4
        ver_tree:add(neop2p_ver.fields.useragent, buffer(offset, useragent_len), buffer(offset, useragent_len):string())
        offset = offset + useragent_len
        ver_tree:add(neop2p_ver.fields.height, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
        offset = offset + 4
        ver_tree:add(neop2p_ver.fields.relay, buffer(offset, 1), buffer(offset, 1):le_uint())
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_getdata = Proto("GetData", "Neo P2P Get Data")

    neop2p_getdata.fields.type = ProtoField.uint8("inv.type", "TYPE", base.DEC, DATA_TYPE)
    neop2p_getdata.fields.count = ProtoField.uint8("inv.count", "COUNT", base.DEC)

    local function neop2p_getdata_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local data_type = buffer(0, 1):uint()
        local hash_count  = buffer(1, 1):uint()

        local getdata_tree = tree:add(neop2p_getdata, buffer(0, len), "GetData")
        getdata_tree:add(neop2p_getdata.fields.type, buffer(0, 1), buffer(0, 1):le_uint64():tonumber())
        local result = neop2p_hashes_dissector(buffer, pinfo, getdata_tree, 1)
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_addr = Proto("GetAddr", "Neo P2P Get Address")

    neop2p_addr.fields.count = ProtoField.uint8("getaddr.count", "COUNT", base.DEC)

    local neop2p_oneaddr = Proto("Address", "address")

    neop2p_oneaddr.fields.timestamp = ProtoField.uint32("addr.timestamp", "TIMESTAMP", base.DEC)
    neop2p_oneaddr.fields.services = ProtoField.uint64("addr.services", "SERVICES", base.DEC)
    -- addr.fields.ipv6 = ProtoField.string("addr.ipv6", "IPV6", base.DEC)
    -- addr.fields.port = ProtoField.string("addr.port", "PORT", base.DEC)
    neop2p_oneaddr.fields.iport = ProtoField.string("addr.iport", "IPORT", base.ASCII)

    local function neop2p_addr_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local addr_count = buffer(0, 1):uint()
    
        local addr_tree = tree:add(neop2p_addr, buffer(0, len), "GetAddress")

        addr_tree:add(neop2p_addr.fields.count, buffer(0, 1), addr_count)

        local index = 0
        while (index < addr_count) do
            local addr = addr_tree:add(neop2p_oneaddr, buffer(1 + index * 30, 30), "Address")
            addr:add(neop2p_oneaddr.fields.timestamp, buffer(1 + index * 30, 4), buffer(1 + index * 30, 4):le_uint64():tonumber())
            addr:add(neop2p_oneaddr.fields.services, buffer(1 + index * 30, 8), buffer(1 + index * 30, 8):le_uint64())
            addr:add(neop2p_oneaddr.fields.iport, buffer(1 + index * 30, 18), tostring(buffer(1 + index * 30, 18)))
            index = index + 1
        end
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_inv = Proto("InvData", "Neo P2P Version Data")

    neop2p_inv.fields.type = ProtoField.uint8("inv.type", "TYPE", base.DEC, DATA_TYPE)
    neop2p_inv.fields.count = ProtoField.uint8("inv.count", "COUNT", base.DEC)

    local function neop2p_inv_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local inv_type = buffer(0, 1):uint()
        local hash_count  = buffer(1, 1):uint()

        local inv_tree = tree:add(neop2p_inv, buffer(0, len), "InvData")
        inv_tree:add(neop2p_inv.fields.type, buffer(0, 1), buffer(0, 1):le_uint64():tonumber())
        local result = neop2p_hashes_dissector(buffer, pinfo, inv_tree, 1)
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        local neop2p = Proto("NEO", "Neo P2P Protocol")

        neop2p.fields.magic = ProtoField.uint32("neop2p.magic", "MAGIC", base.DEC, NET_TYPE)
        neop2p.fields.cmd = ProtoField.string("neop2p.cmd", "COMMAND", base.UNICODE)
        neop2p.fields.length = ProtoField.uint32("neop2p.length", "LENGTH", base.DEC)
        neop2p.fields.checksum = ProtoField.uint32("neop2p.checksum", "CHECKSUM", base.DEC)
        neop2p.fields.payload = ProtoField.string("neop2p.payload", "PAYLOAD", base.ASCII)

        local function neop2p_dissector(buffer, pinfo, tree)
            local L = buffer:len()
            local magic = buffer(0, 4):le_uint()
            local cmd = buffer(4, 12):stringz()
            local length = buffer(16, 4):le_uint()

            local p2p_tree = tree:add(neop2p, buffer(0, L), "Neo P2P Protocol, "..NET_TYPE[magic])
            pinfo.cols.protocol:set("NEO")
            pinfo.cols.info:set(" ".. NET_TYPE[magic]..":"..cmd)
    
            local offset = 0

            p2p_tree:add(neop2p.fields.magic, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
            offset = offset + 4
            p2p_tree:add(neop2p.fields.cmd, buffer(offset, 12), buffer(offset, 12):string())
            offset = offset + 12
            p2p_tree:add(neop2p.fields.length, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
            offset = offset + 4
            p2p_tree:add(neop2p.fields.checksum, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
            offset = offset + 4
            if length == 0 then
                return true
            end
            local payload = buffer(offset, length)
            if cmd == C_INV then
                neop2p_inv_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_ADDR then
                neop2p_addr_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_GET_DATA then
                neop2p_getdata_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_VERSION then
                neop2p_ver_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_GET_HEADERS then
                neop2p_getheaders_dissector(payload, pinfo, p2p_tree)
                return true
            end
            if cmd == C_BLOCK then
                neop2p_block_dissector(payload, pinfo, p2p_tree)
                return true
            end
            p2p_tree:add(neop2p.fields.payload, payload, tostring(payload))
            offset = offset + length
            return true
        end
        
        local function neop2p_detector(buffer, pinfo, tree, offset)
            local len = buffer:len() - offset
            if len < 4 then
                return 0 
            end
            local magic = buffer(offset, 4):le_uint()
            if NET_TYPE[magic] == nil then 
                return 0 
            end
            if len < 24 then
                return len - 24
            end
            local length = buffer(offset + 16, 4):le_uint() + 24
            local cmd = buffer(offset + 4, 12):stringz()
            if len < length then
                return len - length
            end
            neop2p_dissector(buffer(offset, length), pinfo, tree)
            return length
        end
     ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        local neo = Proto("NEOPROTOCOL", "Neo Protocol")
    
        function neo.dissector(buffer, pinfo, tree)
            local len = buffer:len()
            local offset = 0

            while offset < len do
     
                local result = neop2p_detector(buffer, pinfo, tree, offset)

                if 0 < result  then
                    offset = offset + result
                elseif 0 == result then
                    return 0
                else 
                    pinfo.desegment_offset = offset
                    result = -result
                    pinfo.desegment_len = result
                    return len
                end
            end
            return
        end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        neo:register_heuristic("tcp", neo.dissector)
    end