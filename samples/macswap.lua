local ffi=require("ffi")
ffi.cdef("typedef uint64_t  uword;")
ffi.cdef("typedef uint32_t  u32;")
ffi.cdef("uword vlib_node_add_named_next_with_slot (void *vm, uword node, char *name, uword slot);")
ffi.cdef("int vnet_hw_interface_rx_redirect_to_node(void *vnm, u32 hw_if_index, u32 node_index);")
ffi.cdef("uword unformat(void *input, char *fmt, ...);")
ffi.cdef("uword unformat_vnet_sw_interface (void * input, void * args);")


function c_str(text_in)
  local text = text_in .. "\0"
  local c_str = ffi.new("char[?]", #text)
  ffi.copy(c_str, text)
  return c_str
end

function macswap_cb(bi0)
  local dst = vpp.get_packet_bytes(bi0, 0, 6)
  local src = vpp.get_packet_bytes(bi0, 6, 6)
  vpp.set_packet_bytes(bi0, 0, src)
  vpp.set_packet_bytes(bi0, 6, dst)
  vpp.set_tx_interface(bi0, vpp.get_rx_interface(bi0))
end

local is_new, macswap_node_index = vpp.register_node("lua-macswap", macswap_cb)

local res = ffi.C.vlib_node_add_named_next_with_slot(vpp.vlib_get_main(),
                                       macswap_node_index, c_str("interface-output"), 0)

function vpp.api_message(id, data)
  print("API message number", id, " data: ", data)
  return 42, "reply from macswap"
end

function vpp.CLI_lua_macswap(cmd, input)
  -- If no input has been supplied, it is registration time, return help strings
  if not input then
    return { 
      long_help = "long help for macswap commands",
      short_help = "lua macswap commands" 
    }
  end

  local sw_if_index = ffi.new("u32[1]")
  local vnm = vpp.vnet_get_main()
  local res = ffi.C.unformat(input, c_str("%U"), ffi.C.unformat_vnet_sw_interface, vnm, sw_if_index);
  if (1 == res) then
    local disable = (1 == ffi.C.unformat(input, c_str("disable")))
    local redirect_node_index = macswap_node_index
    local swidx = sw_if_index[0]
    if (disable) then
      redirect_node_index = 0xffffffff
    end
    res = ffi.C.vnet_hw_interface_rx_redirect_to_node(vpp.vnet_get_main(), swidx, redirect_node_index)
  else
    -- If we return a string, this triggers an error with that string as a message
    return "need interface name"
  end
end




