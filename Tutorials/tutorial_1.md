## Tutorial 1: Making a naive dig command line tool using sdns library

In this tutorial, we are going to use sdns library to make a naive version of dig command-line utility. **dig** (Domain Information Groper) is 
a powerful tool to query domains and get information about different aspects of the domain name system. It supports hundreds of options which can 
be combined to create a complicated query and several options to display the output result. _dig_ is part of BIND since version 4 (1990) and it's been under development
for more than 30 years!

I gave this introduction to say that what we are trying to write here is not even close to _dig_. The tutorial is just to show how to use sdns library.

Let's create a simple, naive version of the _dig_ to perform simple queries. Our _naivedig_ is capable of querying _A_, _NS_, _TXT_, _SOA_ and _MX_ record for a given domain name. It sends the
query to Cloudflare 1.1.1.1 and prints the results. The initial connection is UDP. However, if the packet is truncated, it will switch to TCP and perform the query again (this is the standard 
behavior of a DNS stub resolver).

Let's start by writing the socket part of the code!

```c
// the following function sends data to UDP socket and receive the result
// the return value of the function is 0 on success and other values on failure.

int perform_lookup_udp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer, size_t * toreceive_len){
    char buffer[256] = {0x00};
    char resolver[] = "1.1.1.1";
    char * error = buffer;
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    struct sockaddr_in server;
    struct sockaddr_in from;
    unsigned int from_size;
    server.sin_port = htons(53);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(resolver);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1){
        close(sockfd);
        perror("Error in creating socket");
        return 1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
        perror("Error in setsocketopt");
        close(sockfd);
        return 2;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0){
        perror("Error in setsockeopt() function");
        return 3;
    }

    ssize_t sent = 0;
    sent = sendto(sockfd, tosend_buffer, tosend_len, 0, (struct sockaddr *)&server, sizeof(server));
    if (sent == -1){  //error
        perror("Error in sendto()");
        close(sockfd);
        return 4;
    }
    if (sent == 0){
        fprintf(stderr, "Can not send the data to the server\n");
        close(sockfd);
        return 5;
    }
    // now let's receive the data
    ssize_t received = 0;
                                                    
    from_size = 0;
    received = recvfrom(sockfd, *toreceive_buffer, 65535, MSG_WAITALL, (struct sockaddr*)&server, &from_size);
    if (received == -1){
        close(sockfd);
        perror("Error in receive function");
        return 2;
    }
    if (received == 0){
        close(sockfd);
        return 2;
    }
    *toreceive_len = received;
    close(sockfd);
    return 0;
}
```

The `perform_lookup_udp()` function is just a very simple routine to send data to a destination (1.1.1.1, 53) and receive the response. It has nothing to do with DNS.
Whatever data you pass to this function, it will send it to the destination, wait 3 seconds for the response and return the response to the caller. That's it!

The next function is called `perform_lookup_tcp()`. It's exactly the same as `perform_lookup_udp()` but instead of UDP, it sends the data using TCP!

```c
int perform_lookup_tcp(char * tosend_buffer, size_t tosend_len, char ** toreceive_buffer, size_t * toreceive_len){
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    struct sockaddr_in server;
    struct sockaddr_in from;
    unsigned int from_size;
    server.sin_port = htons(53);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("1.1.1.1");
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1){
        close(sockfd);
        perror("Error in creating socket");
        return 1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
        perror("Error in setsocketopt");
        close(sockfd);
        return 2;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0){
        perror("Error in setsockeopt() function");
        return 2;
    }
    if (connect(sockfd, (struct sockaddr *) &server, sizeof(server)) < 0){
        perror("Can not connect to TCP socket");
        return 2;
    }
    ssize_t sent = 0;
    uint16_t payload_size = tosend_len;
    char * payload = (char*) malloc(2 + payload_size);
    payload[0] = (uint8_t)((payload_size >> 8) & 0xFF);
    payload[1] = (uint8_t)(payload_size & 0xFF);
    memcpy(payload + 2, tosend_buffer, tosend_len);
    sent = send(sockfd, payload, tosend_len + 2, 0);
    if (sent < 0){
        free(payload);
        perror("Cann not send data to TCP socket...");
        return 1;
    }
    free(payload);
    ssize_t received = 0;
    char recv_payload[2] = {0x00};
    received = recv(sockfd, (void*)recv_payload, 2, 0);
    uint16_t to_allocate = (uint8_t)recv_payload[0] << 8 |
                           (uint8_t)recv_payload[1];

    received = 0;
    char * receive_payload = (char*) malloc(to_allocate);
    received = recv(sockfd, receive_payload, to_allocate, MSG_WAITALL);
    if (received < 0){  // we have socket error
        perror("Error reading from socket...");
        close(sockfd);
        free(receive_payload);
        return 1;
    }
    *toreceive_len = to_allocate;
    *toreceive_buffer = receive_payload;
    return 0;   //success
}
```


The user input to our _naivedig_ is like './naivedig NS google.com' for example. So we need to write another function to get the second argument and convert the text to an acceptable
value for DNS using ::sdns_rr_type enum.

```c
// converts the RR name to its numerical value
int convert_type_to_int(char * type){
    // no allocation no leak
    if (type == NULL)
        return -1;
    if (strcasecmp(type, "A") == 0)
        return sdns_rr_type_A;
    if (strcasecmp(type, "NS") == 0)
        return sdns_rr_type_NS;
    if (strcasecmp(type, "TXT") == 0)
        return sdns_rr_type_TXT;
    if (strcasecmp(type, "MX") == 0)
        return sdns_rr_type_MX;
    if (strcasecmp(type, "SOA") == 0)
        return sdns_rr_type_SOA;
    return -2;
}
```

As our _naivedig_ only supports A, NS, TXT, MX and SOA, we only hard-coded these values. You can add more resource records (e.g., CNAME, PTR, AAAA, RRSIG, ...) if you want. In case of 
unknown RR type, `convert_type_to_int()` function returns -2 and the caller (main function) prints an error code saying that this type is not supported.

Now let's write the `main()` function which is responsible for making DNS packets and parsing data from sockets.

```c
// main function
int main(int argc, char ** argv){
    if (argc != 3){
        fprintf(stdout, "Usage: ./naivedig <rr-type> <host>\n");
        return 1;
    }
    int type_int = convert_type_to_int(argv[1]);   // A or TXT or NS or SOA or MX
    if (type_int == -2){
        fprintf(stderr, "We only support A, TXT, NS, SOA or MX records\n");
        return 1;
    }
    char * domain_name = strdup(argv[2]);
    fprintf(stdout, "querying %s for %s record...\n", domain_name, argv[1]);

    // let's create our query packet
    sdns_context * query_ctx = sdns_init_context();
    if (NULL == query_ctx){
        fprintf(stderr, "Can not create the context\n");
        return 2;
    }
    int res = sdns_make_query(query_ctx, type_int, sdns_q_class_IN, domain_name, 0);
    if (res != 0){
        fprintf(stderr, "Can not create the query packet\n");
        sdns_free_context(query_ctx);
        return 1;
    }
    res = sdns_to_wire(query_ctx);
    if (res != 0){
        fprintf(stderr, "Can not convert the query to binary data\n");
        return 1;
    }
    char * receive_buffer = (char *) malloc(65535); // maximum UDP packet
    size_t received_len = 0;
    res = perform_lookup_udp(query_ctx->raw, query_ctx->raw_len, &receive_buffer, &received_len);
    if (res != 0){
        fprintf(stderr, "Can not perform UDP lookup\n");
        sdns_free_context(query_ctx);
        free(receive_buffer);
        return 1;
    }
    // if the received data is not truncated, we have the answer and we can print it
    // otherwise, we have to perform a TCP lookup
    // first we need to parse the received packet.
    sdns_context * received_udp_ctx = sdns_init_context();
    if (NULL == received_udp_ctx){
        fprintf(stderr, "Can not create a new context\n");
        sdns_free_context(query_ctx);
        free(receive_buffer);
        return 1;
    }
    received_udp_ctx->raw = receive_buffer;
    received_udp_ctx->raw_len = received_len;
    res = sdns_from_wire(received_udp_ctx);
    if (res != 0){
        fprintf(stderr, "Can not parse the received data from UDP socket\n");
        sdns_free_context(received_udp_ctx);
        sdns_free_context(query_ctx);
        return 2;
    }
    // check if the packet is truncated or not (should we do TCP or not?)
    if (received_udp_ctx->msg->header.tc == 1){
        // we need to perform TCP lookup
        fprintf(stdout, "The packet is truncated...querying using TCP socket....\n");
        // we don't need the answer from UDP and we can free() it
        sdns_free_context(received_udp_ctx);
        receive_buffer = NULL;
        received_len = 0;
        res = perform_lookup_tcp(query_ctx->raw, query_ctx->raw_len, &receive_buffer, &received_len);
        sdns_free_context(query_ctx);
        if (res != 0){
            fprintf(stderr, "Can not perform TCP lookup\n");
            return 1;
        }
        sdns_context *tcp_ctx = sdns_init_context();
        tcp_ctx->raw = receive_buffer;
        tcp_ctx->raw_len = received_len;
        res = sdns_from_wire(tcp_ctx);
        if (res != 0){
            sdns_free_context(tcp_ctx);
            fprintf(stderr, "Can not parse the DNS packet from TCP wire\n");
            return 1;
        }
        sdns_neat_print_dns(tcp_ctx);
        sdns_free_context(tcp_ctx);
    }else{
        // we have the response and we don't need TCP lookup
        // we don't need the query context anymore
        sdns_free_context(query_ctx);
        // print the received packet nicely
        sdns_neat_print_dns(received_udp_ctx);
        // free everything and we are done
        sdns_free_context(received_udp_ctx);
    }
    return 0;
}
```

Most parts of the `main()` function are error checking but we are going to break it down and explain each part.

```c
if (argc != 3){
    fprintf(stdout, "Usage: ./naivedig <rr-type> <host>\n");
    return 1;
}
int type_int = convert_type_to_int(argv[1]);   // A or TXT or NS or SOA or MX
if (type_int == -2){
    fprintf(stderr, "We only support A, TXT, NS, SOA or MX records\n");
    return 1;
}
char * domain_name = strdup(argv[2]);
fprintf(stdout, "querying %s for %s record...\n", domain_name, argv[1]);
```

At first, we check the number of input from the user and if it's not 3, we show the usage and exit. We also convert the input RR type using `convert_type_to_int()` function
and if the user input is not one of the A, NS, TXT, SOA or, MX values, we show an error and exit. We also copy the hostname using `strdup()` function. This is important because
later in the code, we will pass this value to sdns_make_query() function and it will be part of our DNS packet structure. When we call sdns_free_context() function, it tries to
use `free()` on **qname** field of the ::sdns_question structure. So, we need to make sure it's a heap-allocated memory so that we can free it without errors.


```c

// let's create our query packet
sdns_context * query_ctx = sdns_init_context();
if (NULL == query_ctx){
    fprintf(stderr, "Can not create the context\n");
    return 2;
}
int res = sdns_make_query(query_ctx, type_int, sdns_q_class_IN, domain_name, 0);
if (res != 0){
    fprintf(stderr, "Can not create the query packet\n");
    sdns_free_context(query_ctx);
    return 1;
}
res = sdns_to_wire(query_ctx);
if (res != 0){
    fprintf(stderr, "Can not convert the query to binary data\n");
    return 1;
}
```

The second part of the `main()` function is about making the query packet from users input data. First we create a DNS context (query_ctx) using sdns_init_context() function. Then we make the 
question section of our DNS packet by calling sdns_make_query() function and user's input data. The last parameter of sdns_make_query() is 0 which tells the function not to add EDNS0 option. 
This means that our packet is not EDNS0 aware. If you want to add EDNS0 support, all you have to do is to pass 1 instead of 0.

Finally, we try to convert the created context to wire format by calling sdns_to_wire() function. sdns_to_wire() function basically reads the **msg** field of the context and fill the 
**raw** and **raw_len** field appropriately. If the operation is successful, it returns zero.

For all the 3 functions we called (sdns_init_context(), sdns_make_query(), and sdns_to_wire()), we must check the return value. All of them return 0 on success. If they return any other value than
0, then we can get the description of the error by calling sdns_error_string() function and passing the return value to it.


```c
char * receive_buffer = (char *) malloc(65535); // maximum UDP packet
size_t received_len = 0;
res = perform_lookup_udp(query_ctx->raw, query_ctx->raw_len, &receive_buffer, &received_len);
if (res != 0){
    fprintf(stderr, "Can not perform UDP lookup\n");
    sdns_free_context(query_ctx);
    free(receive_buffer);
    return 1;
}
```

We don't know the length of the packet we receive from the destination (here the destination is 1.1.1.1:53), However, we know that the maximum size of a UDP packet is 65535 bytes. So we 
allocate a buffer of this size for receiving the result and we pass it to `perform_lookup_udp()` function. In case of success (sending and receiving data successfully), the function return 0.

What we send to the socket is the data in the **raw** field of the DNS context which was field by calling sdns_to_wire() function.

```c
// if the received data is not truncated, we have the answer and we can print it
// otherwise, we have to perform a TCP lookup
// first we need to parse the received packet.
sdns_context * received_udp_ctx = sdns_init_context();
if (NULL == received_udp_ctx){
    fprintf(stderr, "Can not create a new context\n");
    sdns_free_context(query_ctx);
    free(receive_buffer);
    return 1;
}
received_udp_ctx->raw = receive_buffer;
received_udp_ctx->raw_len = received_len;
res = sdns_from_wire(received_udp_ctx);
if (res != 0){
    fprintf(stderr, "Can not parse the received data from UDP socket\n");
    sdns_free_context(received_udp_ctx);
    sdns_free_context(query_ctx);
    return 2;
}
```

After successfully receiving data from the UDP socket, we need to convert the raw data we received, to a DNS packet. This is done by creating a new context (using sdns_init_context()) 
and setting its **raw** and **raw_len** fields, then, pass the newly created context to sdns_from_wire() function to parse the binary data to a meaningful DNS packet.

Note that sdns_from_wire() is exactly the opposite of sdns_to_wire() function.

In case of error, we have to clean up the memory and quit. Otherwise we can continue to:

```c
// check if the packet is truncated or not (should we do TCP or not?)
if (received_udp_ctx->msg->header.tc == 1){
    // we need to perform TCP lookup
    fprintf(stdout, "The packet is truncated...querying using TCP socket....\n");
    // we don't need the answer from UDP and we can free() it
    sdns_free_context(received_udp_ctx);
    receive_buffer = NULL;
    received_len = 0;
    res = perform_lookup_tcp(query_ctx->raw, query_ctx->raw_len, &receive_buffer, &received_len);
    sdns_free_context(query_ctx);
    if (res != 0){
        fprintf(stderr, "Can not perform TCP lookup\n");
        return 1;
    }
    sdns_context *tcp_ctx = sdns_init_context();
    tcp_ctx->raw = receive_buffer;
    tcp_ctx->raw_len = received_len;
    res = sdns_from_wire(tcp_ctx);
    if (res != 0){
        sdns_free_context(tcp_ctx);
        fprintf(stderr, "Can not parse the DNS packet from TCP wire\n");
        return 1;
    }
    sdns_neat_print_dns(tcp_ctx);
    sdns_free_context(tcp_ctx);
}else{
    // we have the response and we don't need TCP lookup
    // we don't need the query context anymore
    sdns_free_context(query_ctx);
    // print the received packet nicely
    sdns_neat_print_dns(received_udp_ctx);
    // free everything and we are done
    sdns_free_context(received_udp_ctx);
}

```

So this part of the code is doing the main job for us. It has a big if..else which breaks the code into two parts for us:

1. if the data is truncated (`received_udp_ctx->msg->header.tc == 1`)
2. if the data is not truncated (tc != 1)

Let's explain the second part which is more common (i.e., `tc != 1`). 

**TC** is the truncation bit in the DNS header (RFC1035). When its value is 1, it means that the response is bigger than a single UDP transaction. Therefore, the requester must switch to 
TCP and send the request again.

When TC is zero, it means we have received the full answer from the remote server and we don't need another request (the _else_ part of the code). In this case, we can just print the 
DNS packet (or do whatever we want). You can print the DNS packet in any format you want. However, I also provided a few functions (__sdns_neat_print_*()__ functions) to simplify the job.
So we have the final answer from the server and we have already parsed the answer packet by calling sdns_from_wire() function. Now we can easily call sdns_neat_print_dns() function to see the output!

finally we need to clean the memory and we are done!

Now consider if TC=1. That means the package is truncated, the received answer from UDP is not the real, valid answer and we need to make another query but this time on TCP!

So we don't need the received answer from UDP anymore. We can free its memory by calling `sdns_free_context(received_udp_ctx)` and then we perform a new TCP lookup by 
calling `perform_lookup_tcp` function. This is the final result no matter what it is and we can print it out by calling sdns_neat_print_dns() function.

That's it! We have our _naivedig_ in ~250 lines of code.

You can compile the code manually by:

```bash
# compile our naivedig
gcc -I. sdns.c naivedig.c dns_utils.c dynamic_buffer.c neat_print.c -o naivedig

```
And let's see the output of executing `./naivedig NS microsoft.com`

```text
querying microsoft.com for NS record...
** DNS MESSAGE HEADER
	ID: 45298,  qr: 1,  opcode: 0,  aa: 0,  tc: 0,  rd: 1,  ra: 1
	z: 0,  AD: 0,  CD: 0,  rcode: NoError  qdcount: 1,  ancount: 4,  arcount: 0,  nscount: 0
** DNS QUESTION SECTION
	microsoft.com.	IN	NS
** DNS ANSWER SECTION
	microsoft.com.	164773	IN	NS	ns1-39.azure-dns.com.
	microsoft.com.	164773	IN	NS	ns2-39.azure-dns.net.
	microsoft.com.	164773	IN	NS	ns3-39.azure-dns.org.
	microsoft.com.	164773	IN	NS	ns4-39.azure-dns.info.
** DNS AUTHORITY SECTION
** DNS ADDITIONAL SECTION
```

And the output of `./naivedig TXT microsoft.com`

```text
querying microsoft.com for TXT record...
The packet is truncated...querying using TCP socket....
** DNS MESSAGE HEADER
	ID: 45298,  qr: 1,  opcode: 0,  aa: 0,  tc: 0,  rd: 1,  ra: 1
	z: 0,  AD: 0,  CD: 0,  rcode: NoError  qdcount: 1,  ancount: 20,  arcount: 0,  nscount: 0
** DNS QUESTION SECTION
	microsoft.com.	IN	TXT
** DNS ANSWER SECTION
	microsoft.com.	1786	IN	TXT		"d365mktkey=3uc1cf82cpv750lzk70v9bvf2" 
	microsoft.com.	1786	IN	TXT		"facebook-domain-verification=fwzwhbbzwmg5fzgotc2go51olc3566" 
	microsoft.com.	1786	IN	TXT		"google-site-verification=pjPOauSPcrfXOZS9jnPPa5axowcHGCDAl1_86dCqFpk" 
	microsoft.com.	1786	IN	TXT		"fg2t0gov9424p2tdcuo94goe9j" 
	microsoft.com.	1786	IN	TXT		"t7sebee51jrj7vm932k531hipa" 
	microsoft.com.	1786	IN	TXT		"google-site-verification=M--CVfn_YwsV-2FGbCp_HFaEj23BmT0cTF4l8hXgpvM" 
	microsoft.com.	1786	IN	TXT		"google-site-verification=GfDnTUdATPsK1230J0mXbfsYw-3A9BVMVaKSd4DcKgI" 
	microsoft.com.	1786	IN	TXT		"d365mktkey=SxDf1EZxLvMwx6eEZUxzjFFgHoapF8DvtWEUjwq7ZTwx" 
	microsoft.com.	1786	IN	TXT		"hubspot-developer-verification=OTQ5NGIwYWEtODNmZi00YWE1LTkyNmQtNDhjMDMxY2JjNDAx" 
	microsoft.com.	1786	IN	TXT		"d365mktkey=QDa792dLCZhvaAOOCe2Hz6WTzmTssOp1snABhxWibhMx" 
	microsoft.com.	1786	IN	TXT		"d365mktkey=6358r1b7e13hox60tl1uagv14" 
	microsoft.com.	1786	IN	TXT		"google-site-verification=uFg3wr5PWsK8lV029RoXXBBUW0_E6qf1WEWVHhetkOY" 
	microsoft.com.	1786	IN	TXT		"docusign=d5a3737c-c23c-4bd0-9095-d2ff621f2840" 
	microsoft.com.	1786	IN	TXT		"d365mktkey=j2qHWq9BHdaa3ZXZH8x64daJZxEWsFa0dxDeilxDoYYx" 
	microsoft.com.	1786	IN	TXT		"v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.msft.net include:spf-a.hotmail.com include:_spf1-meo.microsoft.com -all" 
	microsoft.com.	1786	IN	TXT		"atlassian-domain-verification=xvoaqRfxSg3PnlVnR4xCSOlKyw1Aln0MMxRiKXnwWroFG7vI76TUC8xYb03MwMXv" 
	microsoft.com.	1786	IN	TXT		"workplace-domain-verification=lK0QDLk73xymCYMKUXNpfKAT8TY5Mx" 
	microsoft.com.	1786	IN	TXT		"google-site-verification=uhh5_jbxpcQgnb-A7gDIjlrr5Ef34lA2t2_BAveYpnk" 
	microsoft.com.	1786	IN	TXT		"MS=ms79629062" 
	microsoft.com.	1786	IN	TXT		"ms-domain-verification=9feeb5bd-0f21-44bd-aa3d-ad0b1085c629" 
** DNS AUTHORITY SECTION
** DNS ADDITIONAL SECTION
```

In the next tutorial, we will build more interesting tools.




