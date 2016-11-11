local ffi=require("ffi")
ffi.cdef("typedef uint64_t  uword;")
ffi.cdef("uword vlib_node_add_named_next_with_slot (void *vm, uword node, char *name, uword slot);")
ffi.cdef("void icmp6_register_type(void *vm, uword type, uword node);")

function c_str(text_in)
  local text = text_in
  local c_str = ffi.new("char[?]", #text+1)
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


local is_new, node_id = vpp.register_node("lua-icmp6reply-print", lua_cb)

ffi.C.icmp6_register_type(vpp.vlib_get_main(), 129, node_id)

