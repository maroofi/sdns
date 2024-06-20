### sdns - low-level DNS library in C

A small DNS library written in C

### How to compile

1. sdns depends on libjansson to produce JSON output. So you must have it installed 
```bash

# make sure jaonson library is installed
sudo apt-get install libjansson-dev

# now you can build the library
make
```

This will create a `bin` directory and inside you will have `libsdns.so` file.

Now you can use it in your project by passing `-lsdns` switch. For example, here is the command to build the `test1.c` file in `test` directory:

```bash
gcc  -o test/test -Iinclude test/test1.c  -Lbin -lsdns -ljansson
```

### Documentation

Here is the online documentation of the library: <link to online>

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



