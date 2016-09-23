# vpp-lua-plugin
A Lua plugin for VPP
# compiling within the tree (for make run)


```
# get the Luajit dependency
sudo apt-get install libluajit-5.1-dev
# cd into a working VPP repository
cd vpp
# clean up the results of the build and the plugins config
 rm -rf plugins build-root
# restore the original contents
git checkout plugins
git checkout build-root
cd plugins
# checkout the lua plugin
git clone https://github.com/vpp-dev/vpp-lua-plugin.git lua-plugin
cd ..
# patch the in-tree files to adopt the lua plugin
patch -p1 <plugins/lua-plugin/diff-for-in-tree.diff
make build
make plugins
```
# Running the Lua code

The plugin adds two commands: "lua run" and "lua eval". 
The first one feeds a supplied file to the Luajit library,
the second one evaluates the code right there. No quotes are necessary.

An example:

```
DBGvpp# lua run plugins/lua-plugin/samples/macswap.lua
DBGvpp# lua ?
  lua eval                                 lua eval <string>
  lua macswap                              lua macswap commands
  lua run                                  lua run <file-name>
DBGvpp#
```
