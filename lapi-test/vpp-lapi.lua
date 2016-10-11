--[[
/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
]]

local vpp = {}

local ffi = require("ffi")

--[[

The basic type definitions. A bit of weird gymnastic with
unionization of the hton* and ntoh* functions results
is to make handling of signed and unsigned types a bit cleaner,
essentially building typecasting into a C union.

The vl_api_opaque_message_t is a synthetic type assumed to have
enough storage to hold the entire API message regardless of the type.
During the operation it is casted to the specific message struct types.

]]


ffi.cdef([[

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

#pragma pack(1)
typedef union {
  u16 u16;
  i16 i16;
} lua_ui16t;

#pragma pack(1)
typedef union {
  u32 u32;
  i32 i32;
} lua_ui32t;

lua_ui16t htons(uint16_t hostshort);
lua_ui16t ntohs(uint16_t hostshort);
lua_ui32t htonl(uint32_t along);
lua_ui32t ntohl(uint32_t along);

#pragma pack(1)
typedef struct _vl_api_opaque_message {
  u16 _vl_msg_id;
  u8  data[65536];
} vl_api_opaque_message_t;
]])


function vpp.dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. vpp.dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

function vpp.hex_dump(buf)
  local ret = {}
  for i=1,math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then table.insert(ret, string.format('%08X  ', i-1)) end
    table.insert(ret, ( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) ))
    if i %  8 == 0 then table.insert(ret, ' ') end
    if i % 16 == 0 then table.insert(ret, buf:sub(i-16+1, i):gsub('%c','.')..'\n' ) end
  end
  return table.concat(ret)
end


function vpp.c_str(text_in)
  local text = text_in .. "\0"
  local c_str = ffi.new("char[?]", #text)
  ffi.copy(c_str, text)
  return c_str
end


function vpp.init(vpp, args)
  local pneum_api = args.pneum_api or [[
 int pneum_connect(char *name);
 int pneum_connect_sync(char *name);
 int pneum_disconnect(void);
 int pneum_read(char **data, int *l);
 int pneum_write(char *data, int len);

void pneum_data_free(char *data);
]]

  vpp.pneum_path = args.pneum_path
  vpp.pneum = ffi.load(vpp.pneum_path)
  ffi.cdef(pneum_api)

  vpp.next_msg_num = 1
  vpp.msg_name_to_number = {}
  vpp.msg_name_to_fields = {}
  vpp.msg_number_to_name = {}
  vpp.events = {}

  vpp.accessors = {}
  vpp.accessors["u64"] = {}
  vpp.accessors["u64"].lua2c = function(luaval) return luaval end -- FIXME
  vpp.accessors["u64"].c2lua = function(cval) return cval end -- FIXME
  vpp.accessors["u32"] = {}
  vpp.accessors["u32"].lua2c = function(luaval) return ffi.C.htonl(luaval).u32 end
  vpp.accessors["u32"].c2lua = function(cval) return ffi.C.ntohl(cval).u32 end
  vpp.accessors["u16"] = {}
  vpp.accessors["u16"].lua2c = function(luaval) return ffi.C.htons(luaval).u16 end
  vpp.accessors["u16"].c2lua = function(cval) return ffi.C.ntohs(cval).u16 end
  vpp.accessors["u8"] = {}
  vpp.accessors["u8"].lua2c = function(luaval) return luaval end
  vpp.accessors["u8"].c2lua = function(cval) return cval end

  vpp.accessors["i64"] = {}
  vpp.accessors["i64"].lua2c = function(luaval) return luaval end -- FIXME
  vpp.accessors["i64"].c2lua = function(cval) return cval end -- FIXME
  vpp.accessors["i32"] = {}
  vpp.accessors["i32"].lua2c = function(luaval) return ffi.C.htonl(ffi.cast('u32'),luaval).i32 end
  vpp.accessors["i32"].c2lua = function(cval) return ffi.C.ntohl(ffi.cast('u32', cval)).i32 end
  vpp.accessors["i16"] = {}
  vpp.accessors["i16"].lua2c = function(luaval) return luaval end
  vpp.accessors["i16"].c2lua = function(cval) return cval end
  vpp.accessors["i8"] = {}
  vpp.accessors["i8"].lua2c = function(luaval) return luaval end
  vpp.accessors["i8"].c2lua = function(cval) return cval end
  vpp.accessors["_string_"] = {}
  vpp.accessors["_string_"].lua2c = function(luaval) return vpp.c_str(luaval) end
  vpp.accessors["_string_"].c2lua = function(cval, len) return len and ffi.string(cval, len) or ffi.string(cval) end
  vpp.accessors["_message_"] = {}
  vpp.accessors["_message_"].lua2c = function(luaval)
    return luaval
  end
  vpp.accessors["_message_"].c2lua = function(cval)
    return cval
  end

end

function vpp.connect(vpp, client_name)
    local name = "lua_client"
    if client_name then
      name = client_name
    end
    return vpp.pneum.pneum_connect_sync(vpp.c_str(client_name))
  end

function vpp.disconnect(vpp)
    vpp.pneum.pneum_disconnect()
  end

function vpp.consume_api(vpp, path)
    print("Consuming the VPP api from "..path)
    local ffii = {}
    local f = io.open(path, "r")
    if not f then
      print("Could not open " .. path)
      return nil
    end
    local data = f:read("*all")
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
    ffi.cdef(cdef)
  end

function vpp.api_write(vpp, api_name, req_table_arg)
    local msg_num = vpp.msg_name_to_number[api_name]
    if not msg_num then
      print ("API call "..api_name.." is not known")
      return nil
    end
    local req_table = {}

    local req_type = "vl_api_" .. api_name .. "_t"

    local reqstore = ffi.new("vl_api_opaque_message_t[1]")

    local reqptr = ffi.cast(req_type .. "*", reqstore) -- ffi.new(req_type .. "[1]")
    local req = reqptr[0]
    local additional_len = 0 -- for the variable length field at the end of the message

    req._vl_msg_id = ffi.C.htons(msg_num).u16;
    if req_table_arg then
      req_table = req_table_arg
    end
    for k,v in pairs(req_table) do 
      local field = vpp.msg_name_to_fields[api_name][k]
      if type(v) == "string" then
        ffi.copy(req[k], v)
        if 0 == field.array then
          additional_len = additional_len + #v
          -- If there is a variable storing the length
          -- and the input table does not set it, do magic
          if field.array_size and not req_table[field.array_size] then
            local size_field = vpp.msg_name_to_fields[api_name][field.array_size]
            if size_field then
              req[field.array_size] = size_field.accessors.lua2c(#v)
            end
          end
        end
      else 
        req[k] = field.accessors.lua2c(v)
      end
    end

    -- print("Len of req:", ffi.sizeof(req))
    res = vpp.pneum.pneum_write(ffi.cast('void *', reqptr), ffi.sizeof(req) + additional_len)
    -- print("write res:", res)
  end

function vpp.api_read(vpp)
    local rep_type = "vl_api_opaque_message_t"
    local rep = ffi.new(rep_type .. ' *[1]')
    local replen = ffi.new("int[1]")
    local out = {}
    -- print("Before read")
    res = vpp.pneum.pneum_read(ffi.cast("void *", rep), replen)

    --print("read:", res)
    --print("Length: ", replen[0])
    local reply_msg_num = ffi.C.ntohs(rep[0]._vl_msg_id).u16
    local reply_msg_name = vpp.msg_number_to_name[reply_msg_num]
    -- hex_dump(ffi.string(rep[0], replen[0]))
    -- print("L7 result:", ffi.C.ntohl(rep[0].retval))
    local result_bytes =  ffi.string(rep[0], replen[0])
    -- print("Just before data free")
    local reply_typed_ptr = ffi.cast("vl_api_" .. reply_msg_name .. "_t *", rep[0])
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
    vpp.pneum.pneum_data_free(ffi.cast('void *',rep[0]))
    -- print("Just after data free")
    return reply_msg_name, out, result_bytes
  end

function vpp.api_call(vpp, api_name, req_table, options_in)
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
