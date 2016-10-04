function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

function hex_dump(buf)
  local ret = {}
  for i=1,math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then table.insert(ret, string.format('%08X  ', i-1)) end
    table.insert(ret, ( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) ))
    if i %  8 == 0 then table.insert(ret, ' ') end
    if i % 16 == 0 then table.insert(ret, buf:sub(i-16+1, i):gsub('%c','.')..'\n' ) end
  end
  return table.concat(ret)
end


function new_vpp_api(pneum_path)
  local vpp = {}
  vpp.ffi = require("ffi")
  vpp.pneum_path = pneum_path
  vpp.pneum = vpp.ffi.load(vpp.pneum_path)

  vpp.next_msg_num = 1
  vpp.msg_name_to_number = {}
  vpp.msg_name_to_fields = {}
  vpp.msg_number_to_name = {}
  vpp.events = {}
  vpp.c_str = function(text_in)
     local text = text_in .. "\0"
     local c_str = vpp.ffi.new("char[?]", #text)
     vpp.ffi.copy(c_str, text)
     return c_str
    end

-- pneum API
  local pneum_api = [[
 int pneum_connect(char *name);
 int pneum_connect_sync(char *name);
 int pneum_disconnect(void);
 int pneum_read(char **data, int *l);
 int pneum_write(char *data, int len);

void pneum_data_free(char *data);

typedef int (__stdcall *pneum_cb_t)(char *data, int len);
int pneum_set_callback (pneum_cb_t cb);

]]

  vpp.ffi.cdef(pneum_api);


local vppapi = [[
typedef uint8_t u8;
typedef int8_t i8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef int32_t i32;
typedef uint64_t u64;
typedef int64_t i64;
typedef double f64;
typedef float f32;

uint16_t htons(uint16_t hostshort);
uint16_t ntohs(uint16_t hostshort);
uint32_t htonl(uint32_t along);
uint32_t ntohl(uint32_t along);

#pragma pack(1)
typedef struct _vl_api_opaque_message {
  u16 _vl_msg_id;
  u8  data[32768]; 
} vl_api_opaque_message_t;
]]

  vpp.ffi.cdef(vppapi)

  vpp.accessors = {}
  vpp.accessors["u64"] = {}
  vpp.accessors["u64"].lua2c = function(luaval) return luaval end
  vpp.accessors["u64"].c2lua = function(cval) return cval end
  vpp.accessors["u32"] = {}
  vpp.accessors["u32"].lua2c = function(luaval) return vpp.ffi.C.htonl(luaval) end
  vpp.accessors["u32"].c2lua = function(cval) return vpp.ffi.C.ntohl(cval) end
  vpp.accessors["u16"] = {}
  vpp.accessors["u16"].lua2c = function(luaval) return vpp.ffi.C.htons(luaval) end
  vpp.accessors["u16"].c2lua = function(cval) return vpp.ffi.C.ntohs(cval) end
  vpp.accessors["u8"] = {}
  vpp.accessors["u8"].lua2c = function(luaval) return luaval end
  vpp.accessors["u8"].c2lua = function(cval) return cval end

  vpp.accessors["i64"] = {}
  vpp.accessors["i64"].lua2c = function(luaval) return luaval end
  vpp.accessors["i64"].c2lua = function(cval) return cval end
  vpp.accessors["i32"] = {}
  vpp.accessors["i32"].lua2c = function(luaval) return luaval end
  vpp.accessors["i32"].c2lua = function(cval) return cval end
  vpp.accessors["i16"] = {}
  vpp.accessors["i16"].lua2c = function(luaval) return luaval end
  vpp.accessors["i16"].c2lua = function(cval) return cval end
  vpp.accessors["i8"] = {}
  vpp.accessors["i8"].lua2c = function(luaval) return luaval end
  vpp.accessors["i8"].c2lua = function(cval) return cval end
  vpp.accessors["_string_"] = {}
  vpp.accessors["_string_"].lua2c = function(luaval) return vpp.c_str(luaval) end
  vpp.accessors["_string_"].c2lua = function(cval, len) return len and vpp.ffi.string(cval, len) or vpp.ffi.string(cval) end
  vpp.accessors["_message_"] = {}
  vpp.accessors["_message_"].lua2c = function(luaval)
    return luaval
  end
  vpp.accessors["_message_"].c2lua = function(cval)
    return cval
  end



  vpp.connect = function (vpp, client_name)
    local name = "lua_client"
    if client_name then
      name = client_name
    end
    return vpp.pneum.pneum_connect_sync(vpp.c_str(client_name))
  end

  vpp.disconnect = function (vpp)
    vpp.pneum.pneum_disconnect()
  end

  vpp.consume_api = function(vpp, path)
    print("Consuming the VPP api from "..path)
    local ffii = {}
    local data = io.open(path, "r"):read("*all")
    print ("data len: ", #data)
    data = data:gsub("\n(.-)(%S+)%s*{([^}]*)}", function (preamble, name, members) 
      local onedef = "\n\n#pragma pack(1)\ntypedef struct _vl_api_"..name.. " {\n" ..
	   "   u16 _vl_msg_id;" ..
	   members:gsub("%[[a-zA-Z_]+]", "[0]") ..
	   "} vl_api_" .. name .. "_t;"


      local fields = {}
      vpp.msg_name_to_fields[name] = fields

      -- populate the field reflection table for the message
      -- sets the various type information as well as the accessors for lua<->C conversion
      members:gsub("(%S+)%s+(%S+);", function (fieldtype, fieldname)
          local fieldcount = nil
          local fieldcountvar = nil
          -- data = data:gsub("%[[a-zA-Z_]+]", "[0]")
          fieldname = fieldname:gsub("(%b[])", function(cnt) 
              fieldcount = tonumber(cnt:sub(2, -2));
              if not fieldcount then
                fieldcount = 0
                fieldcountvar = cnt:sub(2, -2)
              end
              return "" 
            end)
	  local fieldrec = { name = fieldname, ctype = fieldtype, array = fieldcount, array_size = fieldcountvar }
          if fieldcount then 
            if fieldtype == "u8" then
              -- any array of bytes is treated as a string
              fieldrec.accessors = vpp.accessors["_string_"]
            else
              print(name,  " : " , fieldname, " : ", fieldtype, ":", fieldcount, ":", fieldcountvar)
              fieldrec.accessors = vpp.accessors["_unknown_type_"]
            end
          else
            -- Just use the respective type's accessors
            fieldrec.accessors = vpp.accessors[fieldtype]
          end
	  fields[fieldname] = fieldrec
	end)

      -- print(dump(fields))
    
      local _, typeonly = preamble:gsub("typeonly", "")
      if typeonly == 0 then
	local this_message_number = vpp.next_msg_num
	vpp.next_msg_num = vpp.next_msg_num + 1
	vpp.msg_name_to_number[name] = this_message_number
	vpp.msg_number_to_name[this_message_number] = name
	onedef = onedef .. "\n\n enum { vl_msg_" .. name .. " = " .. this_message_number .. " };\n\n"
      end
      table.insert(ffii, onedef);
      return ""; 
      end)
    local cdef = table.concat(ffii)
    -- print(cdef)
    vpp.ffi.cdef(cdef)
  end

  vpp.api_write = function (vpp, api_name, req_table_arg)
    local msg_num = vpp.msg_name_to_number[api_name]
    if not msg_num then
      print ("API call "..api_name.." is not known")
      return nil
    end
    local req_table = {}

    local req_type = "vl_api_" .. api_name .. "_t"

    local reqptr = vpp.ffi.new(req_type .. "[1]")
    local req = reqptr[0]

    req._vl_msg_id = vpp.ffi.C.htons(msg_num);
    if req_table_arg then
      req_table = req_table_arg
    end
    for k,v in pairs(req_table) do 
      if type(v) == "string" then
        vpp.ffi.copy(req[k], v)
      else 
        req[k] = v
      end
    end

    -- print("Len of req:", vpp.ffi.sizeof(req))
    res = vpp.pneum.pneum_write(vpp.ffi.cast('void *', reqptr), vpp.ffi.sizeof(req))
    -- print("write res:", res)
  end

  vpp.api_read = function (vpp)
    local rep_type = "vl_api_opaque_message_t"
    local rep = vpp.ffi.new(rep_type .. ' *[1]')
    local replen = vpp.ffi.new("int[1]")
    local out = {}
    -- print("Before read")
    res = vpp.pneum.pneum_read(vpp.ffi.cast("void *", rep), replen)

    --print("read:", res)
    --print("Length: ", replen[0])
    local reply_msg_num = vpp.ffi.C.ntohs(rep[0]._vl_msg_id)
    local reply_msg_name = vpp.msg_number_to_name[reply_msg_num]
    -- hex_dump(vpp.ffi.string(rep[0], replen[0]))
    -- print("L7 result:", ffi.C.ntohl(rep[0].retval))
    local result_bytes =  vpp.ffi.string(rep[0], replen[0])
    -- print("Just before data free")
    local reply_typed_ptr = vpp.ffi.cast("vl_api_" .. reply_msg_name .. "_t *", rep[0])
    for k, v in pairs(vpp.msg_name_to_fields[reply_msg_name]) do
      if v.accessors and v.accessors.c2lua then
        local len = v.array
        out[k] =  v.accessors.c2lua(reply_typed_ptr[k]) 
        -- print(dump(v))
        if len then
          local len_field = vpp.msg_name_to_fields[reply_msg_name][k .. "_length"]
          if (len_field) then
            local real_len = len_field.accessors.c2lua(reply_typed_ptr[k .. "_length"])
            out[k] =  v.accessors.c2lua(reply_typed_ptr[k], real_len) 
          elseif len == 0 then
            -- check if len = 0, then must be a field which contains the size
            len_field =  vpp.msg_name_to_fields[reply_msg_name][v.array_size]
            local real_len = len_field.accessors.c2lua(reply_typed_ptr[v.array_size])
            out[k] =  v.accessors.c2lua(reply_typed_ptr[k], real_len) 
          end
          out["luaapi_" .. k .. "_full"] = v.accessors.c2lua(reply_typed_ptr[k], len)
        end
      else
        out[k] = "<no accessor function>"
      end
      -- print(k, out[k])
    end
    out.luaapi_message_name = reply_msg_name
    out.luaapi_message_number = reply_msg_num
    vpp.pneum.pneum_data_free(vpp.ffi.cast('void *',rep[0]))
    -- print("Just after data free")
    return reply_msg_name, out, result_bytes
  end

  vpp.api_call = function (vpp, api_name, req_table, options_in)
    local msg_num = vpp.msg_name_to_number[api_name] 
    local end_message_name = api_name .."_reply"
    local replies = {}
    local cstruct = ""
    local options = options_in or {}
    if msg_num then
      vpp:api_write(api_name, req_table)
      if not vpp.msg_name_to_number[end_message_name] or options.force_ping then
        end_message_name = "control_ping_reply" 
        vpp:api_write("control_ping")
      end
      repeat 
        reply_message_name, reply = vpp:api_read()
        if not reply.context then
          -- there may be async events inbetween
          table.insert(vpp.events, reply)
        else
          if reply_message_name ~= "control_ping_reply" then
            -- do not insert the control ping encapsulation
            table.insert(replies, reply)
          end
        end
        -- print(reply)
      until reply_message_name == end_message_name
    else
      print(api_name .. " is an unknown API call")
      return nil
    end
    return replies
  end

  return vpp
end

function sleep(n)
  os.execute("sleep " .. tonumber(n))
end


root_dir = "/home/ubuntu/vpp"
pneum_path = root_dir .. "/build-root/install-vpp_debug-native/vpp-api/lib64/libpneum.so"
vpp = new_vpp_api(pneum_path)

vpp:consume_api(root_dir .. "/build-root/install-vpp_debug-native/vlib-api/vlibmemory/memclnt.api")
vpp:consume_api(root_dir .. "/build-root/install-vpp_debug-native/vpp/vpp-api/vpe.api")

vpp:connect("aytest")


-- api calls
reply = vpp:api_call("show_version")
print("Version: ", reply[1].version)
print(hex_dump(reply[1].version))
print(dump(reply))
print("---")


-- reply = vpp:api_call("sw_interface_dump", { context = 42, name_filter = "local", name_filter_valid = 1 } )
reply = vpp:api_call("sw_interface_dump", { context = 42 }) 
for i, intf in ipairs(reply) do
  print(i, intf.sw_if_index, intf.interface_name)
  print(hex_dump(intf.l2_address))
end
print(dump(reply))
print("---")

reply = vpp:api_call("get_first_msg_id", { name = "lua_plugin_a97dbfae" } )
vpp.next_msg_num = tonumber(reply[1].first_msg_id)
print(dump(reply))
vpp:consume_api(root_dir .. "/plugins/lua-plugin/lua/lua.api")
print("---")

data = "asdfg"
reply = vpp:api_call("lua_plugin_cmd", { submsg_id = 32, submsg_data = data, submsg_data_length = #data }, { force_ping = true } )
print(dump(reply))

-- print(reply[1].program)
os.exit(1)

print("About to start cycle")

count = 1
for i = 1,100000 do
  -- print(i)
  vpp:api_call("show_version")
  count = count + 1
  -- print(i, "done")
end
print (count)
-- vpp:api_write("sw_interface_dump", { context = 42 } )
--[[
replies = vpp:api_call("get_first_msg_id", { name = "snat_93f810b9" } )
hex_dump(replies[1])
replies = vpp:api_call("get_first_msg_id", { name = "ioam_export_eb694f98" } )
hex_dump(replies[1])
]]

vpp:disconnect()


