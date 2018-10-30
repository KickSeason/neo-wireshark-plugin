--V0.0.1 2018-10-30
do
    tw = TextWindow.new("neo")
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
    C_GET_BLOCKS    = "getblocks"
    C_INV           = "inv"
    C_GET_DATA      = "getdata"
    C_TX            = "tx"
    C_BLOCK         = "block"

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
    DATA_TYPE = {
        [DATA_TX]           = "Txs",
        [DATA_BLOCK]        = "Blocks",
        [DATA_CONCENSUS]    = "Concensus"
    }
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_hashes = Proto("Hashes", "hashes")
    neop2p_hashes.fields.hash = ProtoField.string("inv.hash", "HASH", base.ASCII)
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    local neop2p_data = Proto("GetData", "Neo P2P Get Data")

    neop2p_data.fields.type = ProtoField.uint8("inv.type", "TYPE", base.DEC, DATA_TYPE)
    neop2p_data.fields.count = ProtoField.uint8("inv.count", "COUNT", base.DEC)

    local function neop2p_getdata_dissector(buffer, pinfo, tree)
        local len = buffer:len()
        local data_type = buffer(0, 1):uint()
        local hash_count  = buffer(1, 1):uint()

        local getdata_tree = tree:add(neop2p_data, buffer(0, len), "GetData")
        getdata_tree:add(neop2p_data.fields.type, buffer(0, 1), buffer(0, 1):le_uint64():tonumber())
        getdata_tree:add(neop2p_data.fields.count, buffer(1, 1), hash_count)
        
        local hashes = getdata_tree:add(neop2p_hashes, buffer(2, len - 2), "HASHES")
        local index = 0
        while (index < hash_count) do
            hashes:add(neop2p_hashes.fields.hash, buffer(2 + index * 32, 32), tostring(buffer(2 + index * 32, 32)))
            index = index + 1
        end
        return true
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
        return true
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
        inv_tree:add(neop2p_inv.fields.count, buffer(1, 1), hash_count)
        
        local hashes = inv_tree:add(neop2p_hashes, buffer(2, len - 2), "HASHES")
        local index = 0
        while (index < hash_count) do
            hashes:add(neop2p_hashes.fields.hash, buffer(2 + index * 32, 32), tostring(buffer(2 + index * 32, 32)))
            index = index + 1
        end
        return true
    end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        local neop2p = Proto("NEOP2P", "Neo P2P Protocol")

        neop2p.fields.magic = ProtoField.uint32("neop2p.magic", "MAGIC", base.DEC, NET_TYPE)
        neop2p.fields.cmd = ProtoField.string("neop2p.cmd", "COMMAND", base.UNICODE)
        neop2p.fields.length = ProtoField.uint32("neop2p.length", "LENGTH", base.DEC)
        neop2p.fields.checksum = ProtoField.uint32("neop2p.checksum", "CHECKSUM", base.DEC)
        neop2p.fields.payload = ProtoField.string("neop2p.payload", "PAYLOAD", base.ASCII)

        local function neop2p_dissector(buffer, pinfo, tree)
            local L = buffer:len()
            local magic = buffer(0, 4):le_uint64():tonumber()
            local method = buffer(4, 16):string()
            local length = buffer(16, 4):le_uint64():tonumber()

            local p2p_tree = tree:add(neop2p, buffer(0, L), "Neo P2P Protocol, "..NET_TYPE[magic])
            pinfo.cols.protocol:set("NEOP2P")
            pinfo.cols.info:set("".. NET_TYPE[magic]..","..method)
    
            local offset = 0

            p2p_tree:add(neop2p.fields.magic, buffer(offset, 4), buffer(offset, 4):le_uint64():tonumber())
            offset = offset + 4
            local cmd = buffer(offset, 12):string()
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
            p2p_tree:add(neop2p.fields.payload, payload, tostring(payload))

            if cmd:sub(0, C_INV:len()) == C_INV then
                return neop2p_inv_dissector(payload, pinfo, p2p_tree)
            end
            if cmd:sub(0, C_ADDR:len()) == C_ADDR then
                return neop2p_addr_dissector(payload, pinfo, p2p_tree)
            end
            if cmd:sub(0, C_GET_DATA:len()) == C_GET_DATA then
                return neop2p_getdata_dissector(payload, pinfo, p2p_tree)
            end
            return true
        end
    
        local function neop2p_detector(buffer, pinfo, tree)
            local L = buffer:len()
            local magic = buffer(0, 4):le_uint64():tonumber()
            local length = buffer(16, 4):le_uint64():tonumber()
            local nettype = NET_TYPE[magic]
            if nettype == nil then 
                return false end
            if L ~= length + 24 then
                return false end
            return true
        end
     ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        local neo = Proto("NEO", "Neo Protocol")
    
        local f_pf_neo_ui32_net = ProtoField.uint32("neo.net", "net type", base.HEX, NET_TYPE)

        neo.fields =  {
            f_pf_neo_ui32_net
        }
    
        local function neo_detector(buffer, pinfo, tree)
    
            if buffer:len() < 24 then return false end
            local magic = buffer(0, 4):le_uint64():tonumber()
    
            if magic == M_MAINNET then if not neop2p_detector(buffer(0):tvb(), pinfo, tree) then return false end
            elseif magic == M_TESTNET then if not neop2p_detector(buffer(0):tvb(), pinfo, tree) then return false end
            elseif magic == M_PRIVNET then if not neop2p_detector(buffer(0):tvb(), pinfo, tree) then return false end
            else return false end
    
            return neop2p_dissector(buffer, pinfo, tree, cmd)
        end
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
    ---------------------------------------------------------------------------------------------------
        neo:register_heuristic("tcp", neo_detector)
    end