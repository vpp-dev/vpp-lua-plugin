-- lua run plugins/lua-plugin/samples/polua.lua
-- Just for simplicity for now lets turn the JIT off
jit.off()

--[[

Testing:

1. Install python virtualenv into $ROOT/virtualenv and install the API and scapy there

2. "make run" in a window to run VPP

3. launch scapy from within the virtualenv in sudo:

sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH virtualenv/bin/scapy
execfile("polua-classifier-test.py")

4. Optionally (on older checkouts): create bridge groups manually on VPP

create host-interface name s0_s1
create host-interface name s0_s2
set interface state host-s0_s1 up
set interface state host-s0_s2 up
set interface l2 bridge host-s0_s1 42
set interface l2 bridge host-s0_s2 42

4. Pull in the PoLua script using plugin and configure it on an interface:

lua run plugins/lua-plugin/samples/polua.lua
lua polua host-s0_s1 in

5. Run the tests from within the polua-classifier-test.py within the scapy window
 

]]


-- bag of stuff, instead of using global vars
local polua = {}

local ffi=require("ffi")
ffi.cdef("typedef uint64_t  uword;")
ffi.cdef("typedef uint64_t  u64;")
ffi.cdef("typedef uint32_t  u32;")
ffi.cdef("typedef int32_t  i32;")
ffi.cdef("typedef uint16_t  u16;")
ffi.cdef("typedef uint8_t  u8;")
ffi.cdef("uword vlib_node_add_named_next_with_slot (void *vm, uword node, char *name, uword slot);")
ffi.cdef("uword vlib_node_add_next_with_slot (void *vm, uword node_index, uword next_node_index, uword slot);")

ffi.cdef("int vnet_hw_interface_rx_redirect_to_node(void *vnm, u32 hw_if_index, u32 node_index);")
ffi.cdef("uword unformat(void *input, char *fmt, ...);")
ffi.cdef("uword unformat_vnet_sw_interface (void * input, void * args);")

-- structure definitions want to be in a pcall
function define_structures()
ffi.cdef([[

typedef struct
{
  u64 calls, vectors, clocks, suspends;
  u64 max_clock;
  u64 max_clock_n;
} vlib_node_stats_t;

typedef enum
{
  VLIB_NODE_TYPE_INTERNAL,
  VLIB_NODE_TYPE_INPUT,
  VLIB_NODE_TYPE_PRE_INPUT,
  VLIB_NODE_TYPE_PROCESS,
  VLIB_N_NODE_TYPE,
} vlib_node_type_t;

typedef struct short_vlib_node_t
{
  /* Vector processing function for this node. */
  void *function;

  /* Node name. */
  u8 *name;

  /* Node name index in elog string table. */
  u32 name_elog_string;

  /* Total statistics for this node. */
  vlib_node_stats_t stats_total;

  /* Saved values as of last clear (or zero if never cleared).
     Current values are always stats_total - stats_last_clear. */
  vlib_node_stats_t stats_last_clear;

  /* Type of this node. */
  vlib_node_type_t type;

  /* Node index. */
  u32 index;

  /* Index of corresponding node runtime. */
  u32 runtime_index;

  /* Runtime data for this node. */
  void *runtime_data;

  /* Node flags. */
  u16 flags;
  // .... more stuff here in real vlib_node_t! 
} short_vlib_node_t;

]])
end
if not pcall(define_structures) then
  print("Warning: structures were already defined. Skipping")
end


ffi.cdef("short_vlib_node_t *vlib_get_node_by_name (void * vm, u8 * name);")

ffi.cdef([[
int vnet_classify_add_del_table (void * cm,
                                 u8 * mask,
                                 u32 nbuckets,
                                 u32 memory_size,
                                 u32 skip,
                                 u32 match,
                                 u32 next_table_index,
                                 u32 miss_next_index,
                                 u32 * table_index,
                                 int is_add);

int vnet_classify_add_del_session (void * cm,
                                   u32 table_index,
                                   u8 * match,
                                   u32 hit_next_index,
                                   u32 opaque_index,
                                   i32 advance,
                                   int is_add);

]])

ffi.cdef([[int
vnet_l2_input_classify_set_tables (u32 sw_if_index,
                                   u32 ip4_table_index,
                                   u32 ip6_table_index, u32 other_table_index);
int
vnet_l2_output_classify_set_tables (u32 sw_if_index,
                                   u32 ip4_table_index,
                                   u32 ip6_table_index, u32 other_table_index);
void
vnet_l2_input_classify_enable_disable (u32 sw_if_index, int enable_disable);

void
vnet_l2_output_classify_enable_disable (u32 sw_if_index, int enable_disable);

]])



function c_str(text_in)
  local text = text_in .. "\0"
  local c_str = ffi.new("char[?]", #text)
  ffi.copy(c_str, text)
  return c_str
end

function classify_add_del_table(mask, nbuckets, memory_size, skip, match, next_table_index, miss_next_index, is_add)
  local c_out_table_index = ffi.new("u32[1]")
  local res = ffi.C.vnet_classify_add_del_table(vpp.vnet_classify_get_main(), 
                              c_str(mask), nbuckets, memory_size, skip, match, next_table_index, miss_next_index, c_out_table_index, is_add)
  return res, c_out_table_index[0]
end

function classify_add_del_session(table_index, match, hit_next_index, opaque_index, advance, is_add)
  return ffi.C.vnet_classify_add_del_session(vpp.vnet_classify_get_main(),
                                            table_index, c_str(match), hit_next_index, opaque_index, advance, is_add)
end

function hex_dump(buf)
  for i=1,math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then io.write(string.format('%08X  ', i-1)) end
    io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
    if i %  8 == 0 then io.write(' ') end
    if i % 16 == 0 then io.write( buf:sub(i-16+1, i):gsub('%c','.'), '\n' ) end
  end
end

function map(func, tbl)
     local newtbl = {}
     for i,v in pairs(tbl) do
         newtbl[i] = func(v)
     end
     return newtbl
 end


function get_node_index(node_name)
  local node = ffi.C.vlib_get_node_by_name(vpp.vlib_get_main(), c_str(node_name))
  if node == nil then
    print("get_node_index: could not find node '" .. tostring(node_name) .. "'")
    return -1
  end
  local idx = node.index
  print("get_node_index: node '" .. tostring(node_name) .. "' has index " .. tostring(idx))
  return idx
end


function vpp.api_message(id, data)
  print("API message number", id, " data: ", data)
  return 42, "reply from polua"
end

local AF_IP4 = 1
local AF_IP6 = 2
local DIR_IN = 1
local DIR_OUT= 2

function polua_print_cb(bi0)
  local sw_if_index = vpp.get_rx_interface(bi0)
  -- vpp.set_tx_interface(bi0, vpp.get_rx_interface(bi0))
  print("PoLua PRINT callback, buffer index:", bi0)
  print("RX interface: " .. tostring(vpp.get_rx_interface(bi0)))
  -- local txt = vpp.get_packet_bytes(bi0, 0) -- , 64)
  local txt = vpp.get_packet_bytes(bi0, 0, 64)
  hex_dump(txt)
end

local icmp_proto_value = { 1, 0x3a }
function add_session(ppi, ip_af, proto, packet_data, recirc_slot)
  if proto == 6 or proto == 17 then
    local a_table_index = ppi.tcp_udp_tables[ip_af] -- ip4 table = 1, ip6 table = 2
    local a_match = packet_data
    local a_hit_next_index = 0xffffffff -- polua.classify_slots_print[1] -- print
    local a_opaque_index = 42
    local a_advance = 0
    local a_is_add = 1
    local ret = classify_add_del_session(a_table_index, a_match, a_hit_next_index, a_opaque_index, a_advance, a_is_add)
    print("Result of adding session: ", tostring(ret))
    -- GOTCHA: if there is a train of the packets in the vector, then they will all arrive here.
    -- So the recirculation is the only sane way to deal with it ?
    print("Recirculate slot: ", recirc_slot)
    return recirc_slot
  elseif proto == icmp_proto_value[ip_af] then
    print("Need to add ICMP session")
    local a_table_index = ppi.icmp_tables[ip_af] -- ip4 table = 1, ip6 table = 2
    local a_match = packet_data
    local a_hit_next_index = 0xffffffff -- polua.classify_slots_print[1] -- print
    local a_opaque_index = 142
    local a_advance = 0
    local a_is_add = 1
    local ret = classify_add_del_session(a_table_index, a_match, a_hit_next_index, a_opaque_index, a_advance, a_is_add)
    print("Result of adding ICMP session: ", tostring(ret))
    -- GOTCHA: if there is a train of the packets in the vector, then they will all arrive here.
    -- So the recirculation is the only sane way to deal with it ?
    print("Recirculate slot: ", recirc_slot)
    return recirc_slot
  end
end

function swap_l3l4_src_dst(bi0, ip_af, proto)
  if false then
    return nil
  end
  if ip_af == AF_IP4 then
    local l3_src = vpp.get_packet_bytes(bi0, 26, 4)
    local l3_dst = vpp.get_packet_bytes(bi0, 30, 4)
    vpp.set_packet_bytes(bi0, 26, l3_dst)
    vpp.set_packet_bytes(bi0, 30, l3_src)
  elseif ip_af == AF_IP6 then
    local l3_src = vpp.get_packet_bytes(bi0, 22, 16)
    local l3_dst = vpp.get_packet_bytes(bi0, 38, 16)
    vpp.set_packet_bytes(bi0, 22, l3_dst)
    vpp.set_packet_bytes(bi0, 38, l3_src)
  end

  if proto == 6 or proto == 17 then
    if ip_af == AF_IP4 then
      local l4_src = vpp.get_packet_bytes(bi0, 34, 2)
      local l4_dst = vpp.get_packet_bytes(bi0, 36, 2)
      vpp.set_packet_bytes(bi0, 34, l4_dst)
      vpp.set_packet_bytes(bi0, 36, l4_src)
    elseif ip_af == AF_IP6 then
      local l4_src = vpp.get_packet_bytes(bi0, 54, 2)
      local l4_dst = vpp.get_packet_bytes(bi0, 56, 2)

      vpp.set_packet_bytes(bi0, 54, l4_dst)
      vpp.set_packet_bytes(bi0, 56, l4_src)
    end
  elseif proto == icmp_proto_value[ip_af] then
    if ip_af == AF_IP4 then
      local icmp_t = vpp.get_packet_bytes(bi0, 34, 1)
      if icmp_t == string.char(0) then
        vpp.set_packet_bytes(bi0, 34, string.char(8))
      elseif icmp_t == string.char(8) then
        vpp.set_packet_bytes(bi0, 34, string.char(0))
      end
    elseif ip_af == AF_IP6 then
      local icmp_t = vpp.get_packet_bytes(bi0, 54, 1)
      if icmp_t == string.char(128) then
        vpp.set_packet_bytes(bi0, 54, string.char(129))
      elseif icmp_t == string.char(129) then
        vpp.set_packet_bytes(bi0, 54, string.char(128))
      end
    end
  end
end


local proto_offset = { 23, 20 }

function slowpath_sessions_add(bi0, ip_af, sw_if_index, direction)
  local proto =  string.byte(vpp.get_packet_bytes(bi0, proto_offset[ip_af]))
  print("Protocol: " .. tostring(proto))
  local other_direction = ((direction == DIR_OUT) and DIR_IN) or DIR_OUT
  local ppi = polua.per_interface[sw_if_index][direction]
  local ppi_reverse = polua.per_interface[sw_if_index][other_direction]
  local recirc_slot = polua.classify_recirc_slots_by_af[ip_af][direction]
  print("Recirc slot: " .. tostring(recirc_slot))
  print("PPI: " .. tostring(ppi))
  print("PPI reverse: " .. tostring(ppi_reverse))

  swap_l3l4_src_dst(bi0, ip_af, proto) -- swap the src/dst in case we have a reverse session
  local packet_data = vpp.get_packet_bytes(bi0, 0, 80)
  if ppi_reverse then
    print("Add reverse session")
    add_session(ppi_reverse, ip_af, proto, packet_data, 0) -- 1 => IPv4, 2 => IPv6
  end

  swap_l3l4_src_dst(bi0, ip_af, proto) -- get the src/dest back in the original order
  packet_data = vpp.get_packet_bytes(bi0, 0, 80)

  if ppi then
    local next_slot = add_session(ppi, ip_af, proto, packet_data, recirc_slot) -- 1 => IPv4, 2=> IPv6
    print("Next slot: " .. tostring(next_slot))
    return next_slot
  else
    return -1 -- just continue the processing
  end
end

function policy_permit(bi0, ip_af, sw_if_index, direction)
  local ppi = polua.per_interface[sw_if_index][direction]
  local result = { }
  if ppi then
    if ppi.default_permit then
      result = { true, "Default permit"}
    else
      result = { false, "Default deny"}
    end
  else
    result = { true, "No policy = permit" }
  end
  print("Policy check result: " .. tostring(result[2]))
  return result[1]
end

function polua_ip4_input_cb(bi0)
  local sw_if_index = vpp.get_rx_interface(bi0)
  print("PoLua IP4 input callback, buffer index:", bi0)
  print("RX interface: " .. tostring(vpp.get_rx_interface(bi0)))
  print("L2 opaque: " .. tostring(vpp.get_l2_opaque(bi0)))
  local next_slot = 0
  if policy_permit(bi0, AF_IP4, sw_if_index, DIR_IN) then
    next_slot = slowpath_sessions_add(bi0, AF_IP4, sw_if_index, DIR_IN)
  end
  print("------- next_slot: " .. tostring(next_slot))
  return next_slot
end

function polua_ip4_output_cb(bi0)
  local sw_if_index = vpp.get_tx_interface(bi0)
  print("PoLua IP4 output callback, buffer index:", bi0)
  print("TX interface: " .. tostring(sw_if_index))
  local next_slot = 0
  if policy_permit(bi0, AF_IP4, sw_if_index, DIR_OUT) then
    next_slot = slowpath_sessions_add(bi0, AF_IP4, sw_if_index, DIR_OUT)
  end
  print("------- next_slot: " .. tostring(next_slot))
  return next_slot
end

function polua_ip6_input_cb(bi0)
  local sw_if_index = vpp.get_rx_interface(bi0)
  print("PoLua IP6 input callback, buffer index:", bi0)
  print("RX interface: " .. tostring(vpp.get_rx_interface(bi0)))
  print("L2 opaque: " .. tostring(vpp.get_l2_opaque(bi0)))
  local next_slot = 0
  if policy_permit(bi0, AF_IP6, sw_if_index, DIR_IN) then
    next_slot = slowpath_sessions_add(bi0, AF_IP6, sw_if_index, DIR_IN)
  end
  print("------- next_slot: " .. tostring(next_slot))
  return next_slot
end

function polua_ip6_output_cb(bi0)
  local sw_if_index = vpp.get_tx_interface(bi0)
  print("PoLua IP6 output callback, buffer index:", bi0)
  print("L2 opaque: " .. tostring(vpp.get_l2_opaque(bi0)))
  print("TX interface: " .. tostring(sw_if_index))
  local next_slot = 0
  if policy_permit(bi0, AF_IP6, sw_if_index, DIR_OUT) then
    next_slot = slowpath_sessions_add(bi0, AF_IP6, sw_if_index, DIR_OUT)
  end
  print("------- next_slot: " .. tostring(next_slot))
  return next_slot
end

function set_classify_table_in(sw_if_index, ip4_table_index, ip6_table_index, other_table_index)
  print("SET_CLASSIFY_L2_IN:" .. tostring(sw_if_index) .. " ip4: " .. tostring(ip4_table_index) .. " ip6: " .. ip6_table_index .. " other: " .. other_table_index)
  return ffi.C.vnet_l2_input_classify_set_tables(sw_if_index, ip4_table_index, ip6_table_index, other_table_index)
end
function set_classify_table_out(sw_if_index, ip4_table_index, ip6_table_index, other_table_index)
  print("SET_CLASSIFY_L2_OUT:" .. tostring(sw_if_index) .. " ip4: " .. tostring(ip4_table_index) .. " ip6: " .. ip6_table_index .. " other: " .. other_table_index)
  return ffi.C.vnet_l2_output_classify_set_tables(sw_if_index, ip4_table_index, ip6_table_index, other_table_index)
end

function set_classify_enable_in(sw_if_index, enable_disable)
  print("CLASSIFY_L2_ENABLE_IN: " .. tostring(sw_if_index) .. " enable: " .. tostring(enable_disable))
  return ffi.C.vnet_l2_input_classify_enable_disable (sw_if_index, enable_disable)
end
function set_classify_enable_out(sw_if_index, enable_disable)
  print("CLASSIFY_L2_ENABLE_OUT: " .. tostring(sw_if_index) .. " enable: " .. tostring(enable_disable))
  return ffi.C.vnet_l2_output_classify_enable_disable (sw_if_index, enable_disable)
end



polua.dirs            = { "input" , "output" }
polua.node_ip4_names            = { "lua-polua-ip4-input", "lua-polua-ip4-output" }
polua.node_ip4_cbs              = { polua_ip4_input_cb, polua_ip4_output_cb }
polua.node_ip4_idxs             = { -1, -1 }
polua.node_ip6_names            = { "lua-polua-ip6-input", "lua-polua-ip6-output" }
polua.node_ip6_cbs              = { polua_ip6_input_cb, polua_ip6_output_cb }
polua.node_ip6_idxs             = { -1, -1 }
polua.node_print_names          = { "lua-polua-input-print", "lua-polua-output-print" }
polua.node_print_cbs              = { polua_print_cb, polua_print_cb }
polua.node_print_idxs           = { -1, -1 }
polua.node_classify_names   = { "l2-input-classify" , "l2-output-classify" }
polua.node_classify_idxs    = { -1, -1 }
polua.classify_slots_ip4        = { -1, -1 }
polua.classify_slots_ip6        = { -1, -1 }
polua.classify_slots_print      = { -1, -1 }
-- recirculation slots in ip4/ip6 callbacks for classifiers
polua.classify_recirc_slots_ip4        = { -1, -1 }
polua.classify_recirc_slots_ip6        = { -1, -1 }
polua.classify_recirc_slots_by_af      = { polua.classify_recirc_slots_ip4, polua.classify_recirc_slots_ip6 }
-- polua.fn_set_classify_tables   = { ffi.C.vnet_l2_input_classify_set_tables, ffi.C.vnet_l2_output_classify_set_tables }
polua.fn_set_classify_tables   = { set_classify_table_in, set_classify_table_out }
-- polua.fn_classify_enable_disable = { ffi.C.vnet_l2_input_classify_enable_disable, ffi.C.vnet_l2_output_classify_enable_disable }
polua.fn_classify_enable_disable = { set_classify_enable_in, set_classify_enable_out }
polua.per_interface = {}

function preconfig_polua(i)
  local is_new, idx = vpp.register_node(polua.node_ip4_names[i], polua.node_ip4_cbs[i])
  print("Node registration index: " .. polua.node_ip4_names[i] .. " index: " .. tostring(idx))
  polua.node_ip4_idxs[i] = idx

  local is_new, idx = vpp.register_node(polua.node_ip6_names[i], polua.node_ip6_cbs[i])
  print("Node registration index: " .. polua.node_ip6_names[i] .. " index: " .. tostring(idx))
  polua.node_ip6_idxs[i] = idx

  local is_new, idx = vpp.register_node(polua.node_print_names[i], polua.node_print_cbs[i])
  print("Node registration index: " .. polua.node_print_names[i] .. " index: " .. tostring(idx))
  polua.node_print_idxs[i] = idx

  idx = get_node_index(polua.node_classify_names[i])
  print("Classify index: ", idx)
  polua.node_classify_idxs[i] = idx
  if idx < 0 then
    return nil
  end
  polua.classify_slots_ip4[i] = ffi.C.vlib_node_add_next_with_slot(vpp.vlib_get_main(), polua.node_classify_idxs[i], polua.node_ip4_idxs[i], -1)
  print("Slot for " .. tostring(polua.node_ip4_idxs[i]) .. " in " .. tostring(polua.node_classify_idxs[i]) .. " is " .. tostring(polua.classify_slots_ip4[i]))

  polua.classify_slots_ip6[i] = ffi.C.vlib_node_add_next_with_slot(vpp.vlib_get_main(), polua.node_classify_idxs[i], polua.node_ip6_idxs[i], -1)
  print("Slot for " .. tostring(polua.node_ip6_idxs[i]) .. " in " .. tostring(polua.node_classify_idxs[i]) .. " is " .. tostring(polua.classify_slots_ip6[i]))

  polua.classify_slots_print[i] = ffi.C.vlib_node_add_next_with_slot(vpp.vlib_get_main(), polua.node_classify_idxs[i], polua.node_print_idxs[i], -1)
  print("Slot for " .. tostring(polua.node_print_idxs[i]) .. " in " .. tostring(polua.node_classify_idxs[i]) .. " is " .. tostring(polua.classify_slots_print[i]))

  -- add the classifier nodes for recirculation

  polua.classify_recirc_slots_ip4[i] = ffi.C.vlib_node_add_next_with_slot(vpp.vlib_get_main(), polua.node_ip4_idxs[i], polua.node_classify_idxs[i], -1)
  print("recirc Slot in " .. tostring(polua.node_ip4_idxs[i]) .. " for " .. tostring(polua.node_classify_idxs[i]) .. " is " .. tostring(polua.classify_recirc_slots_ip4[i]))

  polua.classify_recirc_slots_ip6[i] = ffi.C.vlib_node_add_next_with_slot(vpp.vlib_get_main(), polua.node_ip6_idxs[i], polua.node_classify_idxs[i], -1)
  print("recirc Slot in " .. tostring(polua.node_ip6_idxs[i]) .. " for " .. tostring(polua.node_classify_idxs[i]) .. " is " .. tostring(polua.classify_recirc_slots_ip6[i]))


  return "ok"
end

for i = 1,2 do
  if not preconfig_polua(i) then
    print("preconfig failed for i ", tostring(i))
    return 0
  end
end


--[[

 IPv4/TCP/UDP 5-tuple table

 000000000000 000000000000 0000 00 00 0000 0000 0000 00 FF 0000 FFFFFFFF FFFFFFFF  FFFF FFFF
   eth dst      eth src    et   ihl t  len id    fo ttl pr  cs   ip4src   ip4dst    sp  dp  
   +-------- L2 ---------------+----------- L3 IPv4 ------------------------------+--------L4 ---

 IPv4/ICMP 5-tuple table (TBD)
 000000000000 000000000000 0000 00 00 0000 0000 0000 00 FF 0000 FFFFFFFF FFFFFFFF  FF FF 0000 0000 
   eth dst      eth src    et   ihl t  len id    fo ttl pr  cs   ip4src   ip4dst    t  c  cs   id
   +-------- L2 ---------------+----------- L3 IPv4 ------------------------------+--------L4 ICMP -----+


 IPv6/TCP/UDP 5-tuple table
 000000000000 000000000000 0000 0 00 00000 0000 FF 00 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFF FFFF 
   eth dst      eth src    et   v TC  fll  len  nh hl             ipv6 src                   ipv dst                      sp  dp  
   +-------- L2 ---------------+----------- L3 IPv6 --------------------------------------------------------------------+--------L4 --

 IPv6/ICMP

 000000000000 000000000000 0000 0 00 00000 0000 FF 00 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FF FF 0000 0000 
   eth dst      eth src    et   v TC  fll  len  nh hl             ipv6 src                   ipv dst                    t  c  cs   id
   +-------- L2 ---------------+----------- L3 IPv6 --------------------------------------------------------------------+--------L4 ICMP -----+

]]

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function pad2vec(txt)
  local len = #txt
  local padded_len = len - len%16 + 16
  return (txt .. string.rep("\000", padded_len - len))
end

function mask2bin(txt)
  return pad2vec(txt:gsub(" ", ""):fromhex())
end

function table_for_mask(mask, next_tbl, miss_index) 
  local a_match = #mask/16
  local a_next_tbl = next_tbl or -1 
  local a_miss_index = miss_index or -1
  -- fixme : next IDX needs to be correct
  res, table_id = classify_add_del_table(mask, 64, 20000, 0, a_match, a_next_tbl, a_miss_index, 1)
  return res, table_id
end

function polua_ppi_config_policy(polua, ppi)
  print ("Configuring policy for " .. tostring(ppi.sw_if_index) .. " direction " .. polua.dirs[ppi.inout])
  local ip4imask  = "000000000000 000000000000 0000 00 00 0000 0000 0000 00 FF 0000 FFFFFFFF FFFFFFFF  FF FF 0000 0000"
  local ip6imask  = "000000000000 000000000000 0000 0 00 00000 0000 FF 00 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FF FF 0000 0000"
  local res4, ip4t = table_for_mask(mask2bin(ip4imask), -1, polua.classify_slots_ip4[ppi.inout] )
  local res6, ip6t = table_for_mask(mask2bin(ip6imask), -1, polua.classify_slots_ip6[ppi.inout] )
  print("ICMP ===> IPv4: " .. tostring(res4) .. " " .. tostring(ip4t) .. " IPv6: " .. tostring(res6) .. " " .. tostring(ip6t))
  if not (res4 == 0) or not (res6 == 0) then
    -- FIXME: cleanup the partially created tables
    return "Could not create classifier tables"
  end
  ppi.icmp_tables = { ip4t, ip6t }

  local ip4tumask = "000000000000 000000000000 0000 00 00 0000 0000 0000 00 FF 0000 FFFFFFFF FFFFFFFF  FFFF FFFF"
  local ip6tumask = "000000000000 000000000000 0000 0 00 00000 0000 FF 00 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFF FFFF"
  -- use below in case only one session table - else we need to link it to ICMP tables above
  -- local res4, ip4t = table_for_mask(mask2bin(ip4tumask), -1, polua.classify_slots_ip4[ppi.inout] )
  -- local res6, ip6t = table_for_mask(mask2bin(ip6tumask), -1, polua.classify_slots_ip6[ppi.inout] )
  local res4, ip4t = table_for_mask(mask2bin(ip4tumask), ppi.icmp_tables[1], -1)
  local res6, ip6t = table_for_mask(mask2bin(ip6tumask), ppi.icmp_tables[2], -1)
  print("IPv4: " .. tostring(res4) .. " " .. tostring(ip4t) .. " IPv6: " .. tostring(res6) .. " " .. tostring(ip6t))
  if not (res4 == 0) or not (res6 == 0) then
    -- FIXME: cleanup the partially created tables
    return "Could not create classifier tables"
  end
  ppi.tcp_udp_tables = { ip4t, ip6t }
  print("Setting classify tables for " .. tostring(ppi.sw_if_index) .. " to " .. tostring(ip4t) .. " and " .. tostring(ip6t))
  res = polua.fn_set_classify_tables[ppi.inout](ppi.sw_if_index, ip4t, ip6t, -1)
  print("Set classify tables result: " .. tostring(res))
  res = polua.fn_classify_enable_disable[ppi.inout](ppi.sw_if_index, 1); -- enable
  print("Set classify enable result: " .. tostring(res))
  return nil
end


function polua_setup_inout(inout, sw_if_index, is_enable, is_permit)
  if not polua.per_interface[sw_if_index] then
    polua.per_interface[sw_if_index] = {}
  end
  if is_enable then
    if polua.per_interface[sw_if_index][inout] then
      return "PoLua already enabled for " .. polua.dirs[inout] .. ", disable first!"
    else 
       local ppi = {}
       ppi["sw_if_index"] = sw_if_index
       ppi["inout"] = inout
       ppi["default_permit"] = is_permit
       local ret = polua_ppi_config_policy(polua, ppi, inout)
       if ret then 
         return ret
       else
         polua.per_interface[sw_if_index][inout] = ppi
       end
    end
  else
    ppi = polua.per_interface[sw_if_index][inout]
    polua.per_interface[sw_if_index][inout] = nil
  end
  return nil
end


function polua_setup_in(sw_if_index, is_enable, is_permit)
  print("PoLua setup IN for interface " .. tostring(sw_if_index) .. " is_enable: " .. tostring(is_enable))
  print("Default permit: " .. tostring(is_permit))
  return polua_setup_inout(1, sw_if_index, is_enable, is_permit)
end

function polua_setup_out(sw_if_index, is_enable, is_permit)
  print("PoLua setup OUT for interface " .. tostring(sw_if_index) .. " is_enable: " .. tostring(is_enable))
  print("Default permit: " .. tostring(is_permit))
  return polua_setup_inout(2, sw_if_index, is_enable, is_permit)
end

function polua_setup_clean()
  vpp.for_interfaces(function(name, swid)
     print(tostring(name) .. " : " .. tostring(swid))
     res = polua.fn_set_classify_tables[1](swid, -1, -1, -1)
     res = polua.fn_set_classify_tables[2](swid, -1, -1, -1)
  end)
end

function vpp.CLI_lua_polua(cmd, input)
  -- If no input has been supplied, it is registration time, return help strings
  if not input then
    return { 
      long_help = "long help for polua commands",
      short_help = "lua polua commands" 
    }
  end

  local sw_if_index = ffi.new("u32[1]")
  local vnm = vpp.vnet_get_main()
  local res = ffi.C.unformat(input, c_str("%U"), ffi.C.unformat_vnet_sw_interface, vnm, sw_if_index);
  if (1 == res) then
    local is_in = (1 == ffi.C.unformat(input, c_str("in")))
    local is_out = (1 == ffi.C.unformat(input, c_str("out")))
    if not is_in and not is_out then
      return "Need direction (in or out)"
    end
    local is_permit = (1 == ffi.C.unformat(input, c_str("permit")))
    local is_enable = (1 ~= ffi.C.unformat(input, c_str("disable")))
    local swidx = sw_if_index[0]
    if is_in then
      return polua_setup_in(swidx, is_enable, is_permit)
    end
    if is_out then
      return polua_setup_out(swidx, is_enable, is_permit)
    end
  elseif (1 == ffi.C.unformat(input, c_str("clean"))) then
    polua_setup_clean()
  else
    -- If we return a string, this triggers an error with that string as a message
    return "need interface name"
  end
end

function vpp.CLI_show_lua_polua(cmd, input)
  -- If no input has been supplied, it is registration time, return help strings
  if not input then
    return {
      long_help = "long help for polua commands",
      short_help = "lua polua commands"
    }
  end

  vpp.for_interfaces(function(name, swid)
    print(tostring(name) .. " : " .. tostring(swid))
    local ppi = polua.per_interface[swid] or {}
    local inout_name = { "in", "out" }
    for i = 1,2 do
      if ppi[i] then
        print("    [ " .. inout_name[i] .. " ] default permit: " .. tostring(ppi[i].default_permit))
        print("             TCP/UDP=> ip4table " .. tostring(ppi[i].tcp_udp_tables[1]) .. " ip6table    " .. tostring(ppi[i].tcp_udp_tables[2]))
        print("             ICMP   => ip4table " .. tostring(ppi[i].icmp_tables[1]) .. " ip6table    " .. tostring(ppi[i].icmp_tables[2]))
      end
    end
  end)

end


