CC := gcc
CFLAGS := -I./include -Wall
CLIBS := -ljansson
SHELL = /bin/bash


OUTDIR = bin
DEPS = $(wildcard ./src/*.c)
HDEPS = $(wildcard ./include/*.h)
OBJS_wj = sdns.o sdns_print.o sdns_json.o sdns_dynamic_buffer.o sdns_utils.o sdns_api.o
LIBOBJS_wj = sdns.o sdns_print.o sdns_json.o sdns_dynamic_buffer.o sdns_utils.o sdns_api.o
OBJSTEST = sdns.o sdns_print.o sdns_json.o sdns_dynamic_buffer.o sdns_utils.o test1.o sdns_api.o
LIBNAME = libsdns.so
OBJS = sdns.o sdns_print.o sdns_dynamic_buffer.o sdns_utils.o sdns_api.o
LIBOBJS = sdns.o sdns_print.o sdns_dynamic_buffer.o sdns_utils.o sdns_api.o


sdns: dummy $(OBJS) $(HDEPS)
	@$(CC) -shared $(CFLAGS) $(addprefix bin/, $(LIBOBJS)) -Wl,-soname,$(LIBNAME) $ -o bin/$(LIBNAME)

with-json: dummy $(OBJS_wj) $(HDEPS)
	@$(CC) -shared $(CFLAGS) $(addprefix bin/, $(LIBOBJS_wj)) -Wl,-soname,$(LIBNAME) $ -o bin/$(LIBNAME)

test: dummy $(OBJSTEST) $(HDEPS) test.o
	echo "Executing test rules...."
	@$(CC) $(CFLAGS) $(addprefix bin/, $(OBJSTEST)) -o bin/test $(CLIBS)

sdns.o: src/sdns.c include/sdns.h
	@$(CC) $(CFLAGS) -fPIC -c $< -o bin/$@

sdns_print.o: src/sdns_print.c include/sdns_print.h
	@$(CC) $(CFLAGS) -fPIC -c $< -o bin/$@

sdns_api.o: src/sdns_api.c include/sdns_api.h
	@$(CC) $(CFLAGS) -fPIC -c $< -o bin/$@

sdns_json.o: src/sdns_json.c include/sdns_json.h
	@$(CC) $(CFLAGS) -fPIC -c $< -o bin/$@

sdns_dynamic_buffer.o: src/sdns_dynamic_buffer.c include/sdns_dynamic_buffer.h
	@$(CC) $(CFLAGS) -fPIC -c $< -o bin/$@

sdns_utils.o: src/sdns_utils.c include/sdns_utils.h
	@$(CC) $(CFLAGS) -fPIC -c $< -o bin/$@

dummy:
	@mkdir -p bin
	@rm -f bin/*.o

.PHONY: clean
clean:
	@rm -f bin/*.o

