local ffi=require("ffi")
ffi.cdef("typedef uint64_t  uword;")
ffi.cdef("uword vlib_node_add_named_next_with_slot (void *vm, uword node, char *name, uword slot);")
ffi.cdef("uword vlib_node_add_next_with_slot (void *vm, uword node_index, uword next_node_index, uword slot);")

function c_str(text_in)
  local text = text_in .. "\0"
  local c_str = ffi.new("char[?]", #text)
  ffi.copy(c_str, text)
  return c_str
end


function hex_dump(buf)
  for i=1,math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then io.write(string.format('%08X  ', i-1)) end
    io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
    if i %  8 == 0 then io.write(' ') end
    if i % 16 == 0 then io.write( buf:sub(i-16+1, i):gsub('%c','.'), '\n' ) end
  end
end

function lua_cb(bi0)
  print("Lua callback, buffer index:", bi0)
  local txt = vpp.get_packet_bytes(bi0, 0) -- , 64)
  hex_dump(txt)
end

function lua_2_cb(bi0)
  print("Lua second callback, buffer index:", bi0)
  local txt = vpp.get_packet_bytes(bi0, 0) -- , 64)
  hex_dump(txt)
end

function lua_3_cb(bi0)
  print("Lua third callback, buffer index:", bi0)
  local txt = vpp.get_packet_bytes(bi0, 0) -- , 64)
  hex_dump(txt)
end


local is_new, node_id = vpp.register_node("lua-test-print", lua_cb)
print("Node ID: ", node_id)

local is_new2, node_id2 = vpp.register_node("lua-test2-print", lua_2_cb)
print("Node ID 2: ", node_id2)

local is_new3, node_id3 = vpp.register_node("lua-test3-print", lua_3_cb)
print("Node ID 3: ", node_id3)

ffi.C.vlib_node_add_next_with_slot(vpp.vlib_get_main(), 183, node_id, 16)
ffi.C.vlib_node_add_next_with_slot(vpp.vlib_get_main(), 183, node_id2, 17)
ffi.C.vlib_node_add_next_with_slot(vpp.vlib_get_main(), 183, node_id3, 18)

--[[

lua run plugins/lua-plugin/samples/l2classify.lua

classify table mask l3 ip6 dst buckets 64
classify session hit-next 16 table-index 0 match l3 ip6 dst ff02::1 opaque-index 42
classify session hit-next 17 table-index 0 match l3 ip6 dst ff02::1 opaque-index 42
classify session hit-next 16 table-index 0 match l3 ip6 dst ff02::2 opaque-index 42
set interface l2 input classify intfc af_packet1 ip6-table 0

set interface l2 input classify intfc af_packet1 ip6-table -1

set interface input acl intfc af_packet1 ip6-table 0

classify session del hit-next 15 table-index 0 match l3 ip6 dst ff02::1 opaque-index 42
classify session del hit-next 15 table-index 0 match l3 ip6 dst ff02::2 opaque-index 42

set interface input acl intfc af_packet1 ip6-table -1

classify table mask l2 dst buckets 64
classify session hit-next 16 table-index 1 match l2 dst 33:33:00:00:00:01 opaque-index 42
set interface l2 input classify intfc af_packet1 ip6-table 1



_(L2_PATCH_ADD_DEL, l2_patch_add_del)                                   \
_(CLASSIFY_ADD_DEL_TABLE, classify_add_del_table)                       \
_(CLASSIFY_ADD_DEL_SESSION, classify_add_del_session)                   \
_(CLASSIFY_SET_INTERFACE_IP_TABLE, classify_set_interface_ip_table)     \
_(CLASSIFY_SET_INTERFACE_L2_TABLES, classify_set_interface_l2_tables)   \
_(GET_NODE_INDEX, get_node_index)                                       \
_(ADD_NODE_NEXT, add_node_next)                                         \

]]

