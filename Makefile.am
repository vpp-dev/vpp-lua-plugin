# Copyright (c) 2016 Cisco Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall -I/usr/include/luajit-2.0 -L/usr/lib -lluajit-5.1
# $(pkg-config --cflags --libs luajit)
AM_LDFLAGS = -module -shared -avoid-version -I/usr/include/luajit-2.0 -L/usr/lib -lluajit-5.1 -lm -ldl

vpppluginsdir = ${libdir}/vpp_plugins

vppplugins_LTLIBRARIES = lua_plugin.la

lua_plugin_la_SOURCES = lua/lua_plugin.c \
	lua/lua.api.h

BUILT_SOURCES = lua/lua.api.h lua/lua.py

noinst_HEADERS = \
	lua/lua_plugin.h                              \
	lua/lua.api.h

#
#	# lua/lua_all_api_h.h                     \
#	# lua/lua_msg_enum.h                      \
SUFFIXES = .api.h .api

%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

%.py: %.api
	$(info Creating Python binding for $@)
	$(CC) $(CPPFLAGS) -E -P -C -x c $<                              \
	| vppapigen --input - --python -                                \
	| pyvppapigen.py --input - > $@

pyapidir = ${prefix}/vpp_papi_plugins
pyapi_DATA = lua/lua.py



# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
