CC := gcc
CFLAGS := -I./include -Wall -Werror
CLIBS := -ljansson
SHELL = /bin/bash
LUALIB=lua5.4
LUAINCDIR=/usr/include/lua5.4
LUAMLIB=-lm
LIBNAME = libsdns.so
ONLY_SDNS_CFILE=sdns.c sdns_api.c sdns_dynamic_buffer.c sdns_utils.c sdns_print.c
SDNS_JSON_CFILE=sdns_json.c
SDNS_LUA_CFILE=sdns_lua.c
ONLY_SDNS_HFILE="sdns.h sdns_api.h sdns_dynamic_buffer.h sdns_utils.h sdns_print.h"
SDNS_JSON_HFILE="sdns_json.h"


sdns: dummy
	$(CC) -c $(CFLAGS) -fPIC  $(addprefix ./src/, $(ONLY_SDNS_CFILE))
	$(CC) $(CFLAGS) -o $(LIBNAME) -shared *.o
	@rm -f *.o
	@mv $(LIBNAME) bin/$(LIBNAME)

with-json: dummy
	$(CC) -shared -c $(CFLAGS) -fPIC $(addprefix ./src/, $(ONLY_SDNS_CFILE)) $(addprefix ./src/, $(SDNS_JSON_CFILE))
	$(CC) $(CFLAGS) -o $(LIBNAME) -fPIC -shared *.o $(CLIBS)
	@rm -f *.o
	@mv $(LIBNAME) bin/$(LIBNAME)

with-lua: dummy 
	$(CC) -shared -c $(CFLAGS) -fPIC $(addprefix ./src/, $(ONLY_SDNS_CFILE)) $(addprefix ./src/, $(SDNS_LUA_CFILE)) -I$(LUAINCDIR)
	$(CC) $(CFLAGS) -fPIC -o $(LIBNAME) -shared -l$(LUALIB) $(LUAMLIB) *.o 
	@rm -f *.o
	@mv $(LIBNAME) bin/$(LIBNAME)

all: dummy
	$(CC) -c $(CFLAGS) -shared -fPIC -Wl,-E $(addprefix ./src/, $(ONLY_SDNS_CFILE)) $(addprefix ./src/, $(SDNS_JSON_CFILE)) $(addprefix ./src/, $(SDNS_LUA_CFILE)) -I$(LUAINCDIR)
	$(CC) $(CFLAGS) -o $(LIBNAME) -fPIC -shared  *.o   $(CLIBS) -l$(LUALIB) $(LUAMLIB)
	@rm -f *.o
	@mv $(LIBNAME) bin/$(LIBNAME)

#-l$(LUALIB) $(LUAMLIB)

dummy:
	@mkdir -p bin
	@rm -f bin/*.o

.PHONY: clean
clean:
	@rm -f *.o
	@rm -f bin/*.so
	@rm -f $(LIBNAME)

