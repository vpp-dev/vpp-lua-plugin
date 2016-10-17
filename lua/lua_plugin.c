
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

#define LUA_LIB

#include <stdio.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#include <lua/lua_plugin.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/lookup.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>


/* define message structures */
#define vl_typedefs
#include <lua/lua.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <lua/lua.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <lua/lua.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <lua/lua.api.h>
#undef vl_api_version



static lua_main_t lua_main;

typedef struct {
  u32 next_index;
  u32 sw_if_index;
} luanode_trace_t;

/* packet trace format function */
static u8 * format_luanode_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  luanode_trace_t * t = va_arg (*args, luanode_trace_t *);

  s = format (s, "LUA_plugin: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}


static uword
luaplugin_node_fn (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  // sample_next_t next_index;
  int next_index;
  lua_node_data_t *lnd = (lua_node_data_t *)&node->runtime_data;
  u32 pkts_swapped = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0 = 0; // SAMPLE_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
	  // printf("lnd: %p\n", lnd);

	  if (lnd->callback_ref >= 0) {
		lua_State *L = lua_main.L;
                int top = lua_gettop(L);
		lua_rawgeti(L, LUA_REGISTRYINDEX, lnd->callback_ref);
		lua_pushnumber(L, bi0);
		int nargs = 1;
		if (lua_pcall(L, nargs, LUA_MULTRET, 0) != 0)
        		clib_warning("error running function `f': %s", lua_tostring(L, -1));
                int nstack = lua_gettop(L) - top;
                next0 = lua_isnumber(L, -1) ? luaL_checknumber(L, -1) : 0;
                lua_pop(L, nstack);
          }

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            luanode_trace_t *t =
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->sw_if_index = sw_if_index0;
            t->next_index = next0;
            }
          next0 = next0 < node->n_next_nodes ? next0 : 0; // sanity check

          pkts_swapped += 1;

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
/*
  vlib_node_increment_counter (vm, sample_node.index,
                               SAMPLE_ERROR_SWAPPED, pkts_swapped);
*/
  return frame->n_vectors;


}


static int
sw_interface_name_compare (void *a1, void *a2)
{
  vnet_sw_interface_t *si1 = a1;
  vnet_sw_interface_t *si2 = a2;

  return vnet_sw_interface_compare (vnet_get_main (),
                                    si1->sw_if_index, si2->sw_if_index);
}


static int lua_for_interfaces(lua_State *L) {
  /* arguments: callback */
  int n_interfaces = 0;
  // vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si, *sorted_sis = 0;
  sorted_sis =
      vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
  _vec_len (sorted_sis) = 0;
  pool_foreach (si, im->sw_interfaces, (
                                             {
                                             vec_add1 (sorted_sis, si[0]);
                                             }
                  ));

  /* Sort by name. */
  vec_sort_with_function (sorted_sis, sw_interface_name_compare);
  vec_foreach (si, sorted_sis) {
    u8 *name = format(0, "%U", format_vnet_sw_if_index_name, vnm, si->sw_if_index);
    lua_pushvalue(L, 1); // function to call
    lua_pushstring(L, (void *)name);
    lua_pushnumber(L, si->sw_if_index);
    int nargs = 2;
    if (lua_pcall(L, nargs, LUA_MULTRET, 0) != 0)
        		clib_warning("error running function `f': %s", lua_tostring(L, -1));
    vec_free(name);
    n_interfaces++;
  }
  vec_free (sorted_sis);
  lua_pushnumber(L, n_interfaces);
  return 1; 
}

extern vnet_classify_main_t vnet_classify_main;
static int lua_vnet_classify_get_main(lua_State *L) {
  lua_pushlightuserdata(L, &vnet_classify_main);
  return 1;
}

static int lua_vnet_get_main(lua_State *L) {
  lua_pushlightuserdata(L, vnet_get_main());
  return 1;
}

static int lua_vlib_get_main(lua_State *L) {
  lua_pushlightuserdata(L, vlib_get_main());
  return 1;
}

static int lua_vlib_buffer_advance(lua_State *L) {
  vlib_main_t *vm = vlib_get_main ();
  u32 bi0 = luaL_checknumber(L, 1);
  int offset = luaL_checknumber(L, 2);
  vlib_buffer_t * b0 = vlib_get_buffer (vm, bi0);
  vlib_buffer_advance(b0, offset);
  return 0;
}

static int lua_set_packet_length(lua_State *L) {
  /* arguments: bi0, length */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;
  u32 bi0 = luaL_checknumber(L, 1);
  b0 = vlib_get_buffer (vm, bi0);
  int len = luaL_checknumber(L, 2);
  b0->current_length = len;
  return 0;
}


static int lua_get_packet_length(lua_State *L) {
  /* arguments: bi0 */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;

  u32 bi0 = luaL_checknumber(L, 1);
  b0 = vlib_get_buffer (vm, bi0);
  lua_pushnumber(L, b0->current_length);
  return 1;
}

static int lua_get_rx_interface(lua_State *L) {
  /* arguments: bi0 */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;

  u32 bi0 = luaL_checknumber(L, 1);
  b0 = vlib_get_buffer (vm, bi0);
  lua_pushnumber(L, vnet_buffer(b0)->sw_if_index[VLIB_RX]);
  return 1;
}

static int lua_get_tx_interface(lua_State *L) {
  /* arguments: bi0 */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;

  u32 bi0 = luaL_checknumber(L, 1);
  b0 = vlib_get_buffer (vm, bi0);
  lua_pushnumber(L, vnet_buffer(b0)->sw_if_index[VLIB_TX]);
  return 1;
}

static int lua_set_tx_interface(lua_State *L) {
  /* arguments: bi0, swidx */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;
  u32 bi0 = luaL_checknumber(L, 1);
  b0 = vlib_get_buffer (vm, bi0);
  u32 swid = luaL_checknumber(L, 2);
  vnet_buffer(b0)->sw_if_index[VLIB_TX] = swid;
  
  return 0;
}

static int lua_get_l2_opaque(lua_State *L) {
  /* arguments: bi0 */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;

  u32 bi0 = luaL_checknumber(L, 1);
  b0 = vlib_get_buffer (vm, bi0);
  lua_pushnumber(L, vnet_buffer (b0)->l2_classify.opaque_index);
  return 1;
}

static int lua_set_l2_opaque(lua_State *L) {
  /* arguments: bi0, swidx */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;
  u32 bi0 = luaL_checknumber(L, 1);
  b0 = vlib_get_buffer (vm, bi0);
  u32 opaque = luaL_checknumber(L, 2);
  vnet_buffer (b0)->l2_classify.opaque_index = opaque;
  return 0;
}


static int lua_set_packet_bytes(lua_State *L) {
  /* arguments: bi0, offset, bytes */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;
  char *data;

  u32 bi0 = luaL_checknumber(L, 1);
  int offset = luaL_checknumber(L, 2);
  size_t nbytes;
  const char *bytes = luaL_checklstring(L, 3, &nbytes);

  b0 = vlib_get_buffer (vm, bi0);
  if (b0->current_length - offset < nbytes) {
    if (b0->current_length > offset) {
      nbytes = b0->current_length - offset;
    } else {
      nbytes = 0;
    }
  }
  data = vlib_buffer_get_current (b0);
  if (nbytes > 0) {
    memcpy(data+offset, bytes, nbytes);
  }
  lua_pushnumber(L, nbytes); 
  return 1;
}

static int lua_get_packet_bytes(lua_State *L) {
  /* arguments: bi0, offset, nbytes */
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b0;
  char *data;
  u32 bi0 = luaL_checknumber(L, 1);
  int offset = lua_isnumber(L, 2) ? luaL_checknumber(L, 2) : 0;
  size_t nbytes = lua_isnumber(L, 3) ? luaL_checknumber(L, 3) : 0;
  int whole_packet = !lua_isnumber(L, 3);

  b0 = vlib_get_buffer (vm, bi0);

  if (whole_packet) {
    nbytes = (b0->current_length - offset);
  } else {
    nbytes = luaL_checknumber(L, 3);
  }
  data = vlib_buffer_get_current (b0);
  /* Trim the data request as necessary */
  if (b0->current_length - offset < nbytes) {
    if (b0->current_length > offset) {
      nbytes = b0->current_length - offset;
    } else {
      nbytes = 0;
    }
  }
  if (nbytes > 0) {
    lua_pushlstring(L, data+offset, nbytes);
  } else {
    lua_pushstring(L, "");
  }
  return 1;
}



static int lua_register_node(lua_State *L) {
  vlib_node_registration_t nr = {
     .name = "lua-sample",
     .function = luaplugin_node_fn,
     .vector_size = sizeof(u32),
     .n_next_nodes = 0,
     .format_trace = format_luanode_trace,
  };
  vlib_main_t *vm = vlib_get_main ();
  lua_node_data_t lnd_temp;
  lua_node_data_t *lnd = &lnd_temp;
  u32 node_idx;
  nr.name = (char *) luaL_checkstring(L, 1);
  vlib_node_t *node = vlib_get_node_by_name (vm, (void *)nr.name);
  if (!lua_isfunction(L, 2)) {
    lua_pushstring(L, "vpp.register_node: second argument needs to be a function callback");
    lua_error(L);
  }

  if (!node) {
    memset(lnd, 0, sizeof(*lnd));
    // printf("lnd: %p (%p) (%d bytes)\n", lnd, &lnd, nr.runtime_data_bytes);
    // printf("Is a function: %d\n", lua_isfunction(L, 2));
    // printf("Registering node: %s\n", nr.name);
    lua_pushvalue(L, 2);
    int cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    // printf("Callback reference: %d\n", cb_ref);
    lnd->callback_ref = cb_ref;
    vec_append(lnd->name, nr.name);
    vec_terminate_c_string(lnd->name);
    node_idx = vlib_register_node(vm, &nr);
    // printf("node IDX: %d\n", node_idx);
    vlib_node_add_named_next_with_slot(vm, node_idx, "error-drop", 0);
    vlib_node_set_runtime_data(vm, node_idx, lnd, sizeof(*lnd));
    // icmp6_register_type(vm, ICMP6_echo_reply, node_idx);
    /* Push a node index as a true value since this is a new registration */
    lua_pushnumber(L, node_idx);
  } else {
    /* The node exists */
    node_idx = node->index;
    // printf("The node '%s' already registered, index: %d!\n", nr.name, node_idx);
    // printf("Is a function: %d\n", lua_isfunction(L, 2));
    lnd = *(lua_node_data_t **)node->runtime_data;
    lua_pushvalue(L, 2); /* Update the reference slot to a new callback */
    lua_rawseti(L, LUA_REGISTRYINDEX, lnd->callback_ref);
    /* Not a new registration - push a false value */
    lua_pushnil(L);
  }
  // Push a node index unconditionally
  lua_pushnumber(L, node_idx);
  return 2;
}

static const luaL_Reg vpplib[] = {
  {"register_node",   lua_register_node},
  {"vnet_classify_get_main", lua_vnet_classify_get_main},
  {"vlib_get_main",   lua_vlib_get_main},
  {"vnet_get_main",   lua_vnet_get_main},
  {"get_packet_bytes", lua_get_packet_bytes},
  {"set_packet_bytes", lua_set_packet_bytes},
  {"get_packet_length", lua_get_packet_length},
  {"set_packet_length", lua_set_packet_length},
  {"vlib_buffer_advance", lua_vlib_buffer_advance },
  {"for_interfaces", lua_for_interfaces },
  {"get_rx_interface", lua_get_rx_interface},
  {"get_tx_interface", lua_get_tx_interface},
  {"set_tx_interface", lua_set_tx_interface},
  {"get_l2_opaque", lua_get_l2_opaque },
  {"set_l2_opaque", lua_set_l2_opaque },
  {NULL, NULL}
};

/*
** Open VPP library
*/
LUALIB_API int luaopen_vpp(lua_State *L) {
  luaL_register(L, "vpp", vpplib);
  return 1;
}




static clib_error_t *
lua_eval_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lua_main_t *lm = &lua_main;
  u8 *lua_script = NULL;

  if (!unformat(input, "%U", unformat_line, &lua_script)) {
    return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, input);
  }

  luaL_loadstring(lm->L, (void *)lua_script);
  int ret = lua_pcall(lm->L, 0, 0, 0);
  if (ret != 0) {
    return clib_error_return (0, "error %s", lua_tostring(lm->L, -1));
  }

  lua_settop(lm->L, 0); 

  return NULL;
}

VLIB_CLI_COMMAND (lua_eval_command, static) =
{
  .path = "lua eval",
  .short_help = "lua eval <string>",
  .function = lua_eval_command_fn,
};


static int
lua_call_cli_fn(vlib_main_t * vm,
                          unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lua_main_t *lm = &lua_main;
  lua_State *L = lm->L;
  char *lua_fn_name = 0;
  char *c;
  int top = lua_gettop(L);

  lua_fn_name = vec_new(char *, 4);
  clib_memcpy(lua_fn_name, "CLI_", 4);
  vec_append(lua_fn_name, cmd->path);
  vec_terminate_c_string(lua_fn_name);
  for(c=lua_fn_name; *c; c++) {
    if(' ' == *c) {
      *c = '_';
    }
  }

  lua_getglobal( L, "vpp");
  if(lua_istable(L, -1)) {
    lua_pushstring(L, lua_fn_name);
    lua_gettable(L, -2);
    if (lua_isfunction(L, -1)) {
      lua_pushlightuserdata(L, cmd);
      if (input) {
        lua_pushlightuserdata(L, input);
      } else  {
        lua_pushnil(L);
      }
      int nargs = 2;
      if (lua_pcall(L, nargs, LUA_MULTRET, 0) != 0)
        		clib_warning("error running CLI function `%s': %s", lua_fn_name, lua_tostring(L, -1));
    } else {
      clib_warning("%s is not a function", lua_fn_name);
    }
  }

  vec_free(lua_fn_name); 

  int nstack = lua_gettop(L) - top;
  return nstack;
  /* the caller will needs to do lua_pop(L, nstack) to keep the stack balanced */
}

static clib_error_t *
lua_cli_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lua_main_t *lm = &lua_main;
  lua_State *L = lm->L;
  int nstack = lua_call_cli_fn(vm, input, cmd); 
  clib_error_t *ret_error;
  if (lua_isstring(L, -1)) {
    ret_error = clib_error_return(0, "%s", lua_tostring(L, -1));
  } else {
    ret_error = 0;
  } 
  lua_pop(L, nstack);
  return ret_error;
}

static void register_lua_cli(vlib_main_t * vm, lua_main_t *lm, char *name) {
  lua_State *L = lm->L;
  vlib_cli_command_t cli;
  char *cli_path = 0;
  char *c;

  cli_path = vec_new(char *, strlen(name));
  clib_memcpy(cli_path, name, strlen(name));
  vec_terminate_c_string(cli_path);
  for(c=cli_path; *c; c++) {
    if('_' == *c) {
      *c = ' ';
    }
  }
  
  cli.path = cli_path;
  cli.function = lua_cli_command_fn;

  int nstack = lua_call_cli_fn(vm, NULL, &cli);

  if(lua_isstring(L, -1)) {
    cli.short_help = (void *)lua_tostring(L, -1);
  } else if (lua_istable(L, -1)) {
    lua_getfield(L, -1, "short_help");
    if(lua_isstring(L, -1)) {
      cli.short_help = (void *)lua_tostring(L, -1);
    }
    lua_pop(L, 1);
    lua_getfield(L, -1, "long_help");
    if(lua_isstring(L, -1)) {
      cli.long_help = (void *)lua_tostring(L, -1);
    }
    lua_pop(L, 1);

   
  }

  vlib_cli_register(vm, &cli); 
  lua_pop(L, nstack);
  vec_free(cli_path);
}



static clib_error_t *
lua_run_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lua_main_t *lm = &lua_main;
  lua_State *L = lm->L;

  u8 *lua_file_name = NULL;

  if (!unformat(input, "%s", &lua_file_name)) {
    return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, input);
  }
  if (!unformat (input, "%U", unformat_eof)) {
    return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, input);
  }

  luaL_loadfile(L, (void *)lua_file_name); 
  int ret = lua_pcall(L, 0, 0, 0);
  if (ret != 0) {
    return clib_error_return (0, "error running %s: %s", lua_file_name, lua_tostring(L, -1));
  }

  lua_getglobal( L, "vpp");
  if(lua_istable(L, -1)) {
    lua_pushnil(L);               // put a nil key on stack
    while (lua_next(L,-2) != 0) { // key(-1) is replaced by the next key(-1) in table(-2)
      if (lua_isstring(L, -2)) {
	char *name = (void *)lua_tostring(L,-2);  // Get key(-2) name
        if(strstr(name, "CLI_") == name) {
          register_lua_cli(vm, lm, name+4);
        }
	lua_pop(L,1);               // remove value(-1), now key on top at(-1)
      }
    }
  }
  lua_pop(L,1);                 // remove global table(-1)

  lua_settop(lm->L, 0);

  return NULL;
}

VLIB_CLI_COMMAND (lua_run_command, static) =
{
  .path = "lua run",
  .short_help = "lua run <file-name>",
  .function = lua_run_command_fn,
};

/* API message handler */
static void vl_api_lua_plugin_cmd_t_handler
(vl_api_lua_plugin_cmd_t * mp)
{
  lua_main_t *lm = &lua_main;
  lua_State *L = lm->L;
  vl_api_lua_plugin_cmd_reply_t * rmp;
  int rv;
  char *lua_fn_name = "api_message";
  int top = lua_gettop(L);

  rv = 0;
  unix_shared_memory_queue_t * q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset(rmp, 0, sizeof(*rmp));

  lua_getglobal( L, "vpp");
  if(lua_istable(L, -1)) {
    lua_pushstring(L, lua_fn_name);
    lua_gettable(L, -2);
    if (lua_isfunction(L, -1)) {
      lua_pushnumber(L, mp->submsg_id);
      lua_pushlstring(L, (void *)mp->submsg_data, mp->submsg_data_length);
      int nargs = 2;
      if (lua_pcall(L, nargs, LUA_MULTRET, 0) != 0) {
                        clib_warning("error running CLI function `%s': %s", lua_fn_name, lua_tostring(L, -1));
         rv = -1;
      } else {
        int nstack = lua_gettop(L) - top;
        if ((nstack == 3) && lua_isstring(L, -1) && lua_isnumber(L, -2)) {
           size_t l = lua_strlen(L, -1);
           size_t real_len = l > 255 ? 255 : l;
           memcpy(rmp->submsg_data, lua_tostring(L, -1), real_len);
           rmp->submsg_data_length = real_len;
           rmp->submsg_id = htonl(lua_tonumber(L, -2));
        } else {
          clib_warning("%s should return an error code and the data", lua_fn_name);
        }
        lua_pop(L, nstack);
      }
    } else {
      clib_warning("%s is not a function", lua_fn_name);
      rv = -2;
    }
  }


  rmp->_vl_msg_id = ntohs(1+lm->lua_api_message);
  rmp->context = mp->context;
  rmp->retval = ntohl(rv);
  vl_msg_api_send_shmem (q, (u8 *)&rmp);
}


clib_error_t *
lua_init (vlib_main_t * vm)
{
  lua_main_t *lm = &lua_main;
  u8 * name;

  lm->L = luaL_newstate();
  if (!lm->L) {
    return clib_error_return (0, "can not create Lua state");
  }
  luaL_openlibs(lm->L);
  luaopen_vpp(lm->L);
  lua_getglobal(lm->L, "vpp");
  if(lua_istable(lm->L, -1)) {
    lua_createtable(lm->L, 0, 0);
    lua_setfield(lm->L, -2, "short_help");
  }

  name = format (0, "lua_plugin_%08x%c", api_version, 0);

  lm->lua_api_message = vl_msg_api_get_msg_ids
      ((char *) name, 1);
  vec_free(name);
  printf("LUA API message#: %d\n", lm->lua_api_message);

  vl_msg_api_set_handlers(lm->lua_api_message, "LUA_PLUGIN_CMD",
     vl_api_lua_plugin_cmd_t_handler,
     vl_noop_handler,
     vl_api_lua_plugin_cmd_t_endian,
     vl_api_lua_plugin_cmd_t_print,
     sizeof(vl_api_lua_plugin_cmd_t), 1);

  return NULL;
}

clib_error_t *
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
		      int from_early_init)
{
  clib_error_t *error = 0;

  return error;
}

VLIB_INIT_FUNCTION(lua_init);


/*
static clib_error_t *
lua_show_entries_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  lua_main_t *ilm = &lua_main;
  lua_entry_t *e;
  vlib_cli_output (vm, "  %U\n", format_lua_entry, vnm, NULL);
  pool_foreach (e, ilm->entries,
    ({
      vlib_cli_output (vm, "  %U\n", format_lua_entry, vnm, e);
    }));

  return NULL;
}

VLIB_CLI_COMMAND (lua_show_entries_command, static) =
{
  .path = "show lua entries",
  .short_help = "show lua entries",
  .function = lua_show_entries_command_fn,
};

*/

