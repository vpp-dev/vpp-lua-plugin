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

u16 ntohs(uint16_t hostshort);
u16 htons(uint16_t hostshort);
u32 htonl(uint32_t along);
u32 ntohl(uint32_t along);

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
 int cough_pneum_attach(char *pneum_path, char *cough_path);
 int pneum_connect(char *name, char *chroot_prefix);
 int pneum_connect_sync(char *name, char *chroot_prefix);
 int pneum_disconnect(void);
 int pneum_read(char **data, int *l);
 int pneum_write(char *data, int len);

void pneum_data_free(char *data);
]]

  vpp.pneum_path = args.pneum_path
  ffi.cdef(pneum_api)
  local init_res = 0
  if pcall(function()
		     vpp.cough_path = args.cough_path or "./libcough.so"
                     vpp.cough = ffi.load(vpp.cough_path)
           end) then
    pcall(function()
      if(vpp.cough.cough_pneum_attach) then
        vpp.pneum_is_cough = true
        print("libcough detected\n")
        init_res = vpp.cough.cough_pneum_attach(vpp.c_str(vpp.pneum_path), vpp.c_str(vpp.cough_path))
        vpp.pneum = vpp.cough
      end
    end)
  else
    vpp.pneum = ffi.load(vpp.pneum_path)
  end
  if (init_res < 0) then
    return nil
  end

  vpp.next_msg_num = 1
  vpp.msg_name_to_number = {}
  vpp.msg_name_to_fields = {}
  vpp.msg_number_to_name = {}
  vpp.msg_number_to_type = {}
  vpp.msg_number_to_pointer_type = {}
  vpp.c_type_to_fields = {}
  vpp.events = {}


  vpp.t_lua2c = {}
  vpp.t_c2lua = {}
  vpp.t_lua2c["u8"] = function(c_type, src, dst_c_ptr)
    if type(src) == "string" then
      ffi.copy(dst_c_ptr, src)
      return(#src)
    elseif type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("u8 *", dst_c_ptr)[i-1] = v
      end
      return(#src)
    else
      return 1, ffi.cast("u8", src)
    end
  end
  vpp.t_c2lua["u8"] = function(c_type, src_ptr, src_len)
    if src_len then
      return ffi.string(src_ptr, src_len)
    else
      return (tonumber(src_ptr))
    end
  end

  vpp.t_lua2c["u16"] = function(c_type, src, dst_c_ptr)
    if type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("u16 *", dst_c_ptr)[i-1] = ffi.C.htons(v)
      end
      return(2 * #src)
    else
      return 2, (ffi.C.htons(src))
    end
  end
  vpp.t_c2lua["u16"] = function(c_type, src_ptr, src_len)
    if src_len then
      local out = {}
      for i = 0,src_len-1 do
        out[i+1] = tonumber(ffi.C.ntohs(src_ptr[i]))
      end
    else
      return (tonumber(ffi.C.ntohs(src_ptr)))
    end
  end

  vpp.t_lua2c["u32"] = function(c_type, src, dst_c_ptr)
    if type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("u32 *", dst_c_ptr)[i-1] = ffi.C.htonl(v)
      end
      return(4 * #src)
    else
      return 4, (ffi.C.htonl(src))
    end
  end
  vpp.t_c2lua["u32"] = function(c_type, src_ptr, src_len)
    if src_len then
      local out = {}
      for i = 0,src_len-1 do
        out[i+1] = tonumber(ffi.C.ntohl(src_ptr[i]))
      end
      return out
    else
      return (tonumber(ffi.C.ntohl(src_ptr)))
    end
  end
  vpp.t_lua2c["i32"] = function(c_type, src, dst_c_ptr)
    if type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("i32 *", dst_c_ptr)[i-1] = ffi.C.htonl(v)
      end
      return(4 * #src)
    else
      return 4, (ffi.C.htonl(src))
    end
  end
  vpp.t_c2lua["i32"] = function(c_type, src_ptr, src_len)
    local ntohl = function(src)
      local u32val = ffi.cast("u32", src)
      local ntohlval = (ffi.C.ntohl(u32val))
      local out = tonumber(ffi.cast("i32", ntohlval + 0LL))
      return out
    end
    if src_len then
      local out = {}
      for i = 0,src_len-1 do
        out[i+1] = tonumber(ntohl(src_ptr[i]))
      end
    else
      return (tonumber(ntohl(src_ptr)))
    end
  end

  vpp.t_lua2c["u64"] = function(c_type, src, dst_c_ptr)
    if type(src) == "table" then
      for i,v in ipairs(src) do
        ffi.cast("u64 *", dst_c_ptr)[i-1] = v --- FIXME ENDIAN
      end
      return(8 * #src)
    else
      return 8, ffi.cast("u64", src) --- FIXME ENDIAN
    end
  end
  vpp.t_c2lua["u64"] = function(c_type, src_ptr, src_len)
    if src_len then
      local out = {}
      for i = 0,src_len-1 do
        out[i+1] = tonumber(src_ptr[i]) -- FIXME ENDIAN
      end
    else
      return (tonumber(src_ptr)) --FIXME ENDIAN
    end
  end




  vpp.t_lua2c["__MSG__"] = function(c_type, src, dst_c_ptr)
    local dst = ffi.cast(c_type .. " *", dst_c_ptr)
    local additional_len = 0
    local fields_info = vpp.c_type_to_fields[c_type]
    -- print("__MSG__ type: " .. tostring(c_type))
    -- print(vpp.dump(fields_info))

    for k,v in pairs(src) do
      local field = fields_info[k]
      local lua2c = vpp.t_lua2c[field.c_type]
      -- print("__MSG__ field " .. tostring(k) .. " : " .. vpp.dump(field))
      -- if the field is not an array type, try to coerce the argument to a number
      if not field.array and type(v) == "string" then
        v = tonumber(v)
      end
      if not lua2c then
        print("__MSG__ " .. tostring(c_type) .. " t_lua2c: can not store field " .. field.name ..
              " type " .. field.c_type .. " dst " .. tostring(dst[k]))
        return 0
      end
      local len, val = lua2c(field.c_type, v, dst[k])
      if not field.array then
        dst[k] = val
      else
        if 0 == field.array then
          additional_len = additional_len + len
          -- If there is a variable storing the length
          -- and the input table does not set it, do magic
          if field.array_size and not src[field.array_size] then
            local size_field = fields_info[field.array_size]
            if size_field then
              dst[field.array_size] = vpp.t_c2lua[size_field.c_type](size_field.c_type, len)
            end
          end
        end
      end
    end
    return (ffi.sizeof(dst[0])+additional_len)
  end

  vpp.t_c2lua["__MSG__"] = function(c_type, src_ptr, src_len)
    local out = {}
    local reply_typed_ptr = ffi.cast(c_type .. " *", src_ptr)
    local field_desc = vpp.c_type_to_fields[c_type]
    for k, v in pairs(field_desc) do
      local v_c2lua = vpp.t_c2lua[v.c_type]
      if v_c2lua then
        local len = v.array
        -- print(dump(v))
        if len then
          local len_field_name = k .. "_length"
          local len_field = field_desc[len_field_name]
          if (len_field) then
            local real_len = vpp.t_c2lua[len_field.c_type](len_field.c_type, reply_typed_ptr[len_field_name])
            out[k] =  v_c2lua(v.c_type, reply_typed_ptr[k], real_len)
          elseif len == 0 then
            -- check if len = 0, then must be a field which contains the size
            len_field =  field_desc[v.array_size]
            local real_len = vpp.t_c2lua[len_field.c_type](len_field.c_type, reply_typed_ptr[v.array_size])
            out[k] = v_c2lua(v.c_type, reply_typed_ptr[k], real_len)
          else
            -- alas, just stuff the entire array
            out[k] = v_c2lua(v.c_type, reply_typed_ptr[k], len)
          end
        else
          out[k] =  v_c2lua(v.c_type, reply_typed_ptr[k])
        end
      else
        out[k] = "<no accessor function for type " .. tostring(v.c_type) .. ">"
      end
      -- print(k, out[k])
    end
    return out
  end

  return vpp
end

function vpp.connect(vpp, client_name)
    local name = "lua_client"
    if client_name then
      name = client_name
    end
    return vpp.pneum.pneum_connect_sync(vpp.c_str(client_name), nil)
  end

function vpp.disconnect(vpp)
    vpp.pneum.pneum_disconnect()
  end

function vpp.consume_api(vpp, path)
    -- print("Consuming the VPP api from "..path)
    local ffii = {}
    local f = io.open(path, "r")
    if not f then
      print("Could not open " .. path)
      return nil
    end
    local data = f:read("*all")
    -- Remove all C comments
    data = data:gsub("/%*.-%*/", "")
    -- print ("data len: ", #data)
    data = data:gsub("\n(.-)(%S+)%s*{([^}]*)}", function (preamble, name, members)
      local onedef = "\n\n#pragma pack(1)\ntypedef struct _vl_api_"..name.. " {\n" ..
	   "   u16 _vl_msg_id;" ..
	   members:gsub("%[[a-zA-Z_]+]", "[0]") ..
	   "} vl_api_" .. name .. "_t;"

      local c_type = "vl_api_" .. name .. "_t"

      local fields = {}
      -- vpp.msg_name_to_fields[name] = fields
      -- print("CTYPE " .. c_type)
      vpp.c_type_to_fields[c_type] = fields
      vpp.t_lua2c[c_type] = vpp.t_lua2c["__MSG__"]
      vpp.t_c2lua[c_type] = vpp.t_c2lua["__MSG__"]
      local mirec = { name = "_vl_msg_id", c_type = "u16", array = nil, array_size = nil }
      fields[mirec.name] = mirec

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
	  local fieldrec = { name = fieldname, c_type = fieldtype, array = fieldcount, array_size = fieldcountvar }
          if fieldcount then
            if fieldtype == "u8" then
              -- any array of bytes is treated as a string
            elseif vpp.t_lua2c[fieldtype] then
              -- print("Array of " .. fieldtype .. " is ok!")
            else
              print("Unknown array type: ", name,  " : " , fieldname, " : ", fieldtype, ":", fieldcount, ":", fieldcountvar)
            end
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
	vpp.msg_number_to_type[this_message_number] = "vl_api_" .. name .. "_t"
	vpp.msg_number_to_pointer_type[this_message_number] = vpp.msg_number_to_type[this_message_number] .. " *"
	onedef = onedef .. "\n\n enum { vl_msg_" .. name .. " = " .. this_message_number .. " };\n\n"
      end
      table.insert(ffii, onedef);
      return "";
      end)
    local cdef = table.concat(ffii)
    -- print(cdef)
    ffi.cdef(cdef)
  end


function vpp.lua2c(vpp, c_type, src, dst_c_ptr)
  -- returns the number of bytes written to memory pointed by dst
  local lua2c = vpp.t_lua2c[c_type]
  if lua2c then
    return(lua2c(c_type, src, dst_c_ptr))
  else
    print("vpp.lua2c: do not know how to store type " .. c_type)
    return 0
  end
end

function vpp.c2lua(vpp, c_type, src_ptr, src_len)
  -- returns the lua data structure
  local c2lua = vpp.t_c2lua[c_type]
  if c2lua then
    return(c2lua(c_type, src_ptr, src_len))
  else
    print("vpp.c2lua: do not know how to load type " .. c_type)
    return nil
  end
end

local req_store_cache = ffi.new("vl_api_opaque_message_t[1]")

function vpp.api_write(vpp, api_name, req_table)
    local msg_num = vpp.msg_name_to_number[api_name]
    if not msg_num then
      print ("API call "..api_name.." is not known")
      return nil
    end

    if not req_table then
      req_table = {}
    end
    req_table._vl_msg_id = msg_num

    local packed_len = vpp:lua2c(vpp.msg_number_to_type[msg_num], req_table, req_store_cache)

    res = vpp.pneum.pneum_write(ffi.cast('void *', req_store_cache), packed_len)
    return res
  end

local rep_store_cache = ffi.new("vl_api_opaque_message_t *[1]")
local rep_len_cache = ffi.new("int[1]")

function vpp.api_read(vpp)
    local rep_type = "vl_api_opaque_message_t"
    local rep = rep_store_cache
    local replen = rep_len_cache
    res = vpp.pneum.pneum_read(ffi.cast("void *", rep), replen)

    local reply_msg_num = ffi.C.ntohs(rep[0]._vl_msg_id)
    local reply_msg_name = vpp.msg_number_to_name[reply_msg_num]

    local reply_typed_ptr = ffi.cast(vpp.msg_number_to_pointer_type[reply_msg_num], rep[0])
    local out = vpp:c2lua(vpp.msg_number_to_type[reply_msg_num], rep[0], replen[0])
    if type(out) == "table" then
      out["luaapi_message_name"] = reply_msg_name
    end

    vpp.pneum.pneum_data_free(ffi.cast('void *',rep[0]))

    return reply_msg_name, out
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
        if reply and not reply.context then
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
