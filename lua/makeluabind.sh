#!/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR

ROOTDIR=$(realpath $SCRIPT_DIR/..)
INCLUDEDIR=$(realpath $ROOTDIR/include)
SRCDIR=$(realpath $ROOTDIR/src)

if [ -z "$LUAINCDIR" ]
then
    LUAINCDIR=/usr/include
fi

# make  sdnsnetlib.so file
gcc  -c -Wall -Werror -fpic $SRCDIR/sdns_luanet.c -I"$INCLUDEDIR"  -I"$LUAINCDIR"  && gcc -I"$INCLUDEDIR" -I"$LUAINCDIR" -shared -o sdnsnetlib.so *.o

rm -f *.o

# make luabinding (libsdns.so)
CSOURCE="$SRCDIR/sdns_lua.c $SRCDIR/sdns.c   $SRCDIR/sdns_api.c   $SRCDIR/sdns_print.c   $SRCDIR/sdns_utils.c   $SRCDIR/sdns_dynamic_buffer.c"
gcc  -c -Wall -Werror -fpic $CSOURCE -I$INCLUDEDIR -I$LUAINCDIR && gcc -I. -I$LUAINCDIR -shared -o sdnslib.so *.o

rm -f *.o

echo "Finish creating the shared object files"
ls $SCRIPT_DIR/*.so


