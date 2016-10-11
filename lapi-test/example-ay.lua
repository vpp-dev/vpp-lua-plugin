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

-- random stuff here, can change at any point in time

vpp = require "vpp-lapi"

root_dir = "/home/ubuntu/vpp"
pneum_path = root_dir .. "/build-root/install-vpp_debug-native/vpp-api/lib64/libpneum.so"

vpp:init({ pneum_path = pneum_path })

vpp:consume_api(root_dir .. "/build-root/install-vpp_debug-native/vlib-api/vlibmemory/memclnt.api")
vpp:consume_api(root_dir .. "/build-root/install-vpp_debug-native/vpp/vpp-api/vpe.api")

vpp:connect("aytest")

-- api calls
reply = vpp:api_call("show_version")
print("Version: ", reply[1].version)
print(vpp.hex_dump(reply[1].version))
print(vpp.dump(reply))
print("---")


-- reply = vpp:api_call("sw_interface_dump", { context = 42, name_filter = "local", name_filter_valid = 1 } )
reply = vpp:api_call("sw_interface_dump", { context = 42 }) 
for i, intf in ipairs(reply) do
  print(i, intf.sw_if_index, intf.interface_name)
  print(vpp.hex_dump(intf.l2_address))
end
print(vpp.dump(reply))
print("---")

reply = vpp:api_call("get_first_msg_id", { name = "lua_plugin_a97dbfae" } )
vpp.next_msg_num = tonumber(reply[1].first_msg_id)
print(vpp.dump(reply))
vpp:consume_api(root_dir .. "/plugins/lua-plugin/lua/lua.api")
print("---")

data = "asdfg"
reply = vpp:api_call("lua_plugin_cmd", { submsg_id = 32, submsg_data = data, submsg_data_length = #data }, { force_ping = true } )
print(vpp.dump(reply))

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


