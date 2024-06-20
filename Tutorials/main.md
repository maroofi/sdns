Welcome to **sdns** documentation! Here I explain how to use the library and how to create/manipulate a DNS packet.

To work with DNS packets, one should both have the knowledge of the APIs (this library and this tutorial) as well as the DNS structure. If you don't know how DNS works in general, this 
tutorial is not for you! You must know the general structure of a DNS packet ([RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)) as well as some knowledge of DNS resolvers.

I tried to document all the APIs but I can not explain the whole DNS concept in the documentation. First, I explain the concept of the library and then we go through three tutorials (step by step)
and create some applications using the library.

> [NOTE]
> You can also directly jump into the practical tutorials/projects

+ [First tutorial](./tutorial_1.md): Creating a naive dig command-line tool using sdns library.

+ [Second tutorial](./tutorial_2.md): Creating a DNS packet sniffer (naive-wireshark for DNS)

#### General concept
Working with the library, everything is about DNS context, an instance of the C structure ::sdns_context that is created by calling sdns_init_context() function. This context (we call it DNS context),
contains all the information about the DNS packet we are making or the DNS packet we received from the socket. Depending on what we want to do (making a DNS packet or parsing a received data from the socket), 
we have the following steps:

* We want to make a DNS packet and send it through UDP (or TCP) socket.
    1. We have to create a new DNS context by calling sdns_init_context() function.
    2. Passing the created context to several functions like sdns_make_query(), sdns_add_answer_section(), ... based on the packet we want to build.
    3. Passing the context to sdns_to_wire() function to convert the context to wire format (a sequence of bytes ready for the socket).
    4. Sending whatever that is inside the **raw** field of the context structure to the socket.
    5. Free the created context by calling sdns_free_context() function.

Or

* We have received a sequence of bytes from the socket and we want to parse it to get a DNS structure.
    1. We create a DNS context by calling sdns_init_context() function.
    2. Set the **raw** field of the context to the data buffer we received from the socket (and also set the **raw_len** field to the length of the buffer).
    3. Pass the DNS context to sdns_from_wire() function to parse the binary data to a DNS packet.
    4. Do whatever you want with the parsed data.
    5. Free the created context by calling sdns_free_context() function.

Let's see a very small example of how we can do the above-mentioned steps.

We want to create a DNS packet, asking about the `A` record of `google.com`. This packet has one question section only.

Using [Dig](https://linux.die.net/man/1/dig), here is the command to create this packet:

```bash
# +noedns tells dig not to add edns0 support.
# So additional section will be empty and we only have 1 question in question section.

dig google.com IN A +noedns
```

Now let's see how we can make it using sdns library:

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

Copy and paste the following code into a file named 'minimain.c' and compile it manually by:

```bash
gcc -g -I. sdns.c neat_print.c dns_utils.c dynamic_buffer.c minimain.c -o make_packet.o
```
After executing the file, you will have the following output:

```bash
Raw data ready for the socket:
b0 f2 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01
```

Now if we convert the binary data to a DNS packet using [dnspython](https://www.dnspython.org/) package in Python:

```python3
# python3 source code
import dns.message
data = "b0 f2 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01"
data = data.split()
data = [int(x, 16) for x in data]
print(dns.message.from_wire(bytes(data)))
```

Here is the output we get:

```text
id 45298
opcode QUERY
rcode NOERROR
flags RD
;QUESTION
google.com. IN A
;ANSWER
;AUTHORITY
;ADDITIONAL
```

Well, that's probably the easiest use case of the library! Still not as easy as Python but easy enough for C.

I have also provided a few tutorials to cover almost all the APIs of the library and show how to use them. In each tutorial, we try to make
an easy application using sdns library and explain each step throughly. We try to avoid external libraries as much as possible to keep things clear
and only focus on our APIs.

[Checkout the first tutorial](./tutorial_1.md): In this tutorial, we are making a naive [dig](https://linux.die.net/man/1/dig) using sdns library.

[The second tutorial](./tutorial_2.md): Creating a DNS packet sniffer (naive-wireshark for DNS)


