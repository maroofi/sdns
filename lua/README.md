### Lua binding for sdns library

This directory contains examples of Lua source code to demonstrate the usage of sdns library in Lua.

All most all the APIs in `sdns_api.c` file wrapped in `sdns_lua.c` file to creat the lua binding.

You can also read the full documentation of the Lua APIs in [DOCLUASDNS.md](./DOCLUASDNS.md)

#### Compile the lua binding separately:
```bash

git clone https://github.com/maroofi/sdns.git

cd sdns/lua

chmod +x makeluabind.sh

./makeluabind.sh
```

This will generate two .so files in the current directory which can be used in Lua programming.

If the compiler complains about not finding the lua header files (e.g., lua.h), then export
`LUAINCDIR` variable first and then run the script.

```bash
# let's say this is where your lua header files are

export LUAINCDIR=/usr/include/lua5.4 && ./makeluabind.sh
```


