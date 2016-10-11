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

#ifndef LUAPLUGIN_H
#define LUAPLUGIN_H

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>



#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>


typedef struct {
  char *name;
  int callback_ref;
} lua_node_data_t;


typedef struct {
  lua_State *L;
  u16 lua_api_message;
} lua_main_t;


#endif //LUAPLUGIN_H
