[![C-build-and-test](https://github.com/maroofi/sdns/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/maroofi/sdns/actions/workflows/c-cpp.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![Lua](https://img.shields.io/badge/lua-%232C2D72.svg?style=for-the-badge&logo=lua&logoColor=white)
![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
### sdns - low-level DNS library in C

A small DNS library written in C

(if you are interested in the Lua binding of the library, check the [lua](./lua) directory.)

### How to compile

1. sdns does not have any external dependency. However, all the `sdns_json_*` functions are based on libjansson library.
So if you don't need JSON output, you can compile it just by making it.

```bash
# compile the library
make
```

2. If you also need `sdns_json_*` functions, you need to have libjansson installed.

```bash
# make sure jaonson library is installed
sudo apt-get install libjansson-dev

# now you can build the library
make with-json
```

3. If you want to build the library with Lua binding, you must have Lua installed. I only show the 5.4 version but you can build it
for 5.3 and 5.2 as well:

```bash
# make sure you have Lua dev installed
sudo apt-get install liblua5.4-dev lua5.4

# now you can build the library
make with-lua
```

4. To have both lua binding and `sdns_json_*` functions:

```bash
# make sure you have lua and libjansson installed
sudo apt-get install liblua5.4-dev lua5.4 libjansson-dev

# and then
make all
```


The make file is quite easy and you can change it to whatever you want. You can also manually build the library as it has only 5 .C files.


make commmand will create a  `bin` directory and inside you will have `libsdns.so` file.

Now you can use it in your project by passing `-lsdns` switch. For example, here is the command to build the `test1.c` file in `test` directory:

```bash
gcc  -o test/test -Iinclude test/test1.c  -Lbin -lsdns -ljansson
```

NOTE: Another way of using this library in you project is to simply copy all the `src/*.c` and `include/*.h` files into your project.

### Running tests

Tests are using Python3 and bash. You can optionally use valgrind to check memory leaks as well. You need to have 'jsoncomparison' package installed.
```bash
# make sure you make the library with-json
make with-json

cd test
pip install jsoncomparison

# Running the tests without valgrind
./sdns_test.sh

# Or running the tests with valgrind
./sdns_test.sh with-valgrind
```

### Documentation

Here is the online documentation of the library: [https://maroofi.github.io/sdns](https://maroofi.github.io/sdns)

Or you can compile it yourself:
```bash
doxygen Doxygen
```

### Example sourece code

(this source code creates a DNS packet the same as using dig command: `dig google.com IN A +noedns`)

```c
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sdns.h"

int main(){
    sdns_context * dnsctx = sdns_init_context();
    if (NULL == dnsctx){    // we are done as we can create the context
        fprintf(stderr, "Can not create a DNS context\n");
        return 1;
    }
    char * qname = strdup("google.com");
    int res = sdns_make_query(dnsctx, sdns_rr_type_A, sdns_q_class_IN, qname, 0);
    if (res != 0){  
        // sdns_make_query() failed. The return value can tell us why.
        // we have to call sdns_error_string() with 'res' to know the reason.
        fprintf(stderr, "Can not create the query packet\n");
        sdns_free_context(dnsctx);
        return 1;
    }
    // we are done. Now if we want to get the binary data to send it over the socket
    // we have to call sdns_to_wire() function.
    res = sdns_to_wire(dnsctx);
    if (res != 0){
        fprintf(stderr, "Can not covert to binary data\n");
        sdns_free_context(dnsctx);
        return 1;
    }
    // let's print the hex presentation of the data
    fprintf(stdout, "Raw data ready for the socket:\n");
    for (int i=0; i < dnsctx->raw_len; ++i){
        fprintf(stdout, "%02x ", (unsigned char)dnsctx->raw[i]);
    }
    fprintf(stdout, "\n");
    // let's free the context and we are done
    sdns_free_context(dnsctx);
    return 0;
}
```

### paractical tutorials of using sdns library

[Checkout the first tutorial](./Tutorials/tutorial_1.md): In this tutorial, we are making a naive [dig](https://linux.die.net/man/1/dig) using sdns library.

[The second tutorial](./Tutorials/tutorial_2.md): Creating a DNS packet sniffer (naive-wireshark for DNS)

[here is the Lua tutorial](./lua/DOCLUASDNS.md)

