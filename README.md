# vpp-lua-plugin
A Lua plugin for VPP
# compiling within the tree (for make run)

```
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

