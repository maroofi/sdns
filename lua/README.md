### Lua binding for sdns library

This directory contains examples of Lua source code to demonstrate the usage of sdns library in Lua.

Almost all the APIs in `sdns_api.c` file wrapped in `sdns_lua.c` file to create the Lua binding.

You can also read the full documentation of the Lua APIs in [DOCLUASDNS.md](./DOCLUASDNS.md)


### How to install lua5.4

In order to comile `sdns` library with Lua, you must have Lua5.4 installed. You can install Lua5.4 using the following commands.

```bash
# install lua binary
sudo apt install lua5.4

# install lua lib
sudo apt install liblua5.4-dev
```

after installing lua5.4, using `pkg-config`, you should see the following path:
```bash
pkg-config --cflags --libs lua5.4

# output
# -I/usr/include/lua5.4 -llua5.4
```

If the headers directory or library name is different, then you should change the Makefile or pass the environment variable like this:
```bash
make LUALIB=<your-lua-lib-name> LUAINCDIR=<your-path-to-lua-include-dir> with-lua

or

make LUALIB=<your-lua-lib-name> LUAINCDIR=<your-path-to-lua-include-dir> all
```


