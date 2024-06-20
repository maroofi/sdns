## Tutorial 2: Making a DNS packet sniffer using sdns library

Probably you have all worked with [Wireshark](https://www.wireshark.org/) before. The handy tool that is used to capture the network traffic on 
different interfaces. In this tutorial, we are going to make a simple command line tool to use sdns library and some to capture and parse
DNS packets like Wireshark. Again, this tool is just good to show you how to use _sdns_.

So here is the scenario of the project:

Capture the network traffic and select those that are IPv4. Then we select those that are UDP packets and then only keep the packets
with the source port or destination port of 53. We pass these packets to _sdns_ library to see it can parse it successfully or not. Those 
packets that are successfully parsed, will be printed in the output with the following format:

```text
<DNS_ID> SRCIP:SRCPORT -> DSTIP:DSTPORT ----  [Q|R]  Qname Qclass RR
```

For example

```text
23456 1.2.3.4:26123 -> 2.3.4.5:53 ---- [Q] gogole.com IN AAAA
23456 2.3.4.5:53 -> 1.2.3.4:26123 ---- [R] gogole.com IN AAAA
```
First we explains those functions that have nothing to do with _sdns_ library and finally we write the main routine where we parse and print the DNS packet. We don't 
use any third party library to keep things as simple as possible.

Here is the whole source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>

#include "sdns.h"
#include "neat_print.h"

void analyze_data(char *, ssize_t);
void process_udp_payload(char * src_ip, uint16_t src_port, char* dst_ip, uint16_t dst_port, char * buffer, uint16_t len);

int main(int argc, char** argv){
    struct sockaddr saddr;
    int sock_addr_len = sizeof(saddr);
    int sockfd;
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1){
        perror("Can not create RAW socket");
        return 1;
    }
    // create a buffer for incomming data
    char * buffer = (char*) malloc(65535);
    if (NULL == buffer){
        fprintf(stderr, "Can not allocate buffer with malloc()\n");
        return 1;
    }
    ssize_t recv_data;
    do{
        // capture packets, process and repeat
        recv_data = recvfrom(sockfd, buffer, 65535, 0, &saddr, (socklen_t*)&sock_addr_len); 
        if (recv_data < 0){
            perror("Error in receiving data");
            break;
        }
        analyze_data(buffer, recv_data);
    }while(1);
    // clean up memory
    free(buffer);
    close(sockfd);
    return 0;
}

void analyze_data(char * ethbuffer, ssize_t ethbuffer_len){
    // here the buffer is an EETH packet.
    // ETH packet header is 14 bytes and then we have IP packet
    // in IPv4 packet, 10th byte is the protocol
    // if protocol == 17 => we have UDP packet else drop it!
    if (ethbuffer_len < 24)
        return;
    char * buffer = ethbuffer + 14;
    if ((((uint8_t)buffer[0] >> 4) & 0x0F) != 4)   // return if it's not IPv4
        return;
    if ((uint8_t)buffer[9] != 17)   // drop it as it's not UDP
        return;
    // where is the start of the UDP packet?
    // we have to first get the size of the IP header
    // size of the IP header = IPHL * 4
    // IPHL = lower 4 bits of the first byte of the IP packet
    // IPHL shows the number of 32bits for the header of the IP packet
    // That's why we need to multiply it by 4
    unsigned int iphl = ((uint8_t) buffer[0] & 0x0F) * 4;
    char * udp_packet = buffer + iphl;
    char * src_ip = NULL;
    char * dst_ip = NULL;
    struct in_addr ip_addr;
    in_addr_t ipaddress = (buffer[12] << 24) | (buffer[13] << 16) |
                         (buffer[14] << 8 ) | (buffer[15]);
    ip_addr.s_addr = ipaddress;
    src_ip = strdup(inet_ntoa(ip_addr));
    ipaddress = (buffer[16] << 24) | (buffer[17] << 16) |
                 (buffer[18] << 8 ) | (buffer[19]);
    ip_addr.s_addr = ipaddress;
    dst_ip = strdup(inet_ntoa(ip_addr));
    uint16_t src_port = (udp_packet[0] << 8) | (udp_packet[1]);
    uint16_t dst_port = (udp_packet[2] << 8) | (udp_packet[3]);
    // one of the ports must be 53 otherwise drop the packet (this is an assumption)
    if (src_port != 53 && dst_port != 53){
        free(src_ip);
        free(dst_ip);
        return;
    }
    // calculate the size of the UDP payload
    uint16_t payload_len = ((udp_packet[4] << 8) | (udp_packet[5])) - 8;

    // now we have to process the payload of UDP packet
    // if it's DNS packet, we will print the info and return
    
    process_udp_payload(src_ip, src_port, dst_ip, dst_port, udp_packet + 8, payload_len);

    //fprintf(stdout, "src: %s:%d, dst: %s:%d\n", src_ip, src_port, dst_ip, dst_port);
    free(src_ip);
    free(dst_ip);
    // we have a UDP packet
    return;
}

void process_udp_payload(char * src_ip, uint16_t src_port, char* dst_ip, uint16_t dst_port, char * buffer, uint16_t len){
    // if we can successfully parse the packet, it's probably DNS packet 
    // and we print information otherwise, we just return
    sdns_context * ctx = sdns_init_context();
    ctx->raw = buffer;
    ctx->raw_len = len;
    int res = sdns_from_wire(ctx);
    if (res == 0){
        // it's a DNS packet
        uint16_t dns_id = ctx->msg->header.id;
        char qr[20];
        if (ctx->msg->header.qr == 0)
            strcpy(qr, "[Q]");
        else
            strcpy(qr, "[R]");
        fprintf(stdout, "%d %s:%d -> %s:%d ---- %s: ", dns_id, src_ip, src_port, dst_ip, dst_port, qr);
        sdns_neat_print_question(ctx);
    }
    ctx->raw = NULL;
    ctx->raw_len = 0;
    sdns_free_context(ctx);
    return;

}
```

You can compile it manually with
```bash
gcc naivewireshark.c -I. sdns.c dns_utils.c dynamic_buffer.c neat_print.c -o naivewireshark
```

Let's break it in piece and explain each part!

```c
int main(int argc, char** argv){
    struct sockaddr saddr;
    int sock_addr_len = sizeof(saddr);
    int sockfd;
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1){
        perror("Can not create RAW socket");
        return 1;
    }
    // create a buffer for incomming data
    char * buffer = (char*) malloc(65535);
    if (NULL == buffer){
        fprintf(stderr, "Can not allocate buffer with malloc()\n");
        return 1;
    }
    ssize_t recv_data;
    do{
        // capture packets, process and repeat
        recv_data = recvfrom(sockfd, buffer, 65535, 0, &saddr, (socklen_t*)&sock_addr_len);
        if (recv_data < 0){
            perror("Error in receiving data");
            break;
        }
        analyze_data(buffer, recv_data);
    }while(1);
    // clean up memory
    free(buffer);
    close(sockfd);
    return 0;
}
```
The _main_ function is pretty much easy to understand. It opens a RAW socket, trying to capture everything in a do...while forever. Since we used *SOCK_RAW*, it means
we need to run the code in superuser mode to be able to listen to raw socket. I am running the code with "sudo" on my machine.

Whenever we receive a packet, we store it in **buffer** and we call another function `analyze_data(buffer, recv_data)` with **buffer** and length of the data we received
from the socket. All the magic is done in `analyze_data()` function.

```c
void analyze_data(char * ethbuffer, ssize_t ethbuffer_len){
    // here the buffer is an EETH packet.
    // ETH packet header is 14 bytes and then we have IP packet
    // in IPv4 packet, 10th byte is the protocol
    // if protocol == 17 => we have UDP packet else drop it!
    if (ethbuffer_len < 24)
        return;
    char * buffer = ethbuffer + 14;
    if ((((uint8_t)buffer[0] >> 4) & 0x0F) != 4)   // return if it's not IPv4
        return;
    if ((uint8_t)buffer[9] != 17)   // drop it as it's not UDP
        return;
    // where is the start of the UDP packet?
    // we have to first get the size of the IP header
    // size of the IP header = IPHL * 4
    // IPHL = lower 4 bits of the first byte of the IP packet
    // IPHL shows the number of 32bits for the header of the IP packet
    // That's why we need to multiply it by 4
    unsigned int iphl = ((uint8_t) buffer[0] & 0x0F) * 4;
    char * udp_packet = buffer + iphl;
    char * src_ip = NULL;
    char * dst_ip = NULL;
    struct in_addr ip_addr;
    in_addr_t ipaddress = (buffer[12] << 24) | (buffer[13] << 16) |
                         (buffer[14] << 8 ) | (buffer[15]);
    ip_addr.s_addr = ipaddress;
    src_ip = strdup(inet_ntoa(ip_addr));
    ipaddress = (buffer[16] << 24) | (buffer[17] << 16) |
                 (buffer[18] << 8 ) | (buffer[19]);
    ip_addr.s_addr = ipaddress;
    dst_ip = strdup(inet_ntoa(ip_addr));
    uint16_t src_port = (udp_packet[0] << 8) | (udp_packet[1]);
    uint16_t dst_port = (udp_packet[2] << 8) | (udp_packet[3]);
    // one of the ports must be 53 otherwise drop the packet (this is an assumption)
    if (src_port != 53 && dst_port != 53){
        free(src_ip);
        free(dst_ip);
        return;
    }
    // calculate the size of the UDP payload
    uint16_t payload_len = ((udp_packet[4] << 8) | (udp_packet[5])) - 8;

    // now we have to process the payload of UDP packet
    // if it's DNS packet, we will print the info and return

    process_udp_payload(src_ip, src_port, dst_ip, dst_port, udp_packet + 8, payload_len);

    //fprintf(stdout, "src: %s:%d, dst: %s:%d\n", src_ip, src_port, dst_ip, dst_port);
    free(src_ip);
    free(dst_ip);
    // we have a UDP packet
    return;
}
```

In `analyze_data()` function, we receive an ether packet. What we are interested in, is the DNS packets so we have to do some filtering first. The first step is to extract
the IP packet from Ether packet. That means we need to skip the first 14 bytes of the Ether packet (header part) to get the ether payload which is the IP packet.

```text  
        # here is what we do in analyze_data() function.
         _______________        _______________        _______________        _______________                                              
        |               |      |               |      |               |      |               |   YES
        | Ether packet  | ---> |   IP packet   | ---> |   UDP packet  | ---> |  DNS packet?  | -------> Print it!
        |_______________|      |_______________|      |_______________|      |_______________|  

(it was really difficult to create this chart)
```

The first 4 bits of the IP packet is the IP version (4 or 6). For IPv4, it's always "4". So we return from the function if this value is not 4. The 10th byte of the IP
packet is the protocol and UDP code is 17. So we only continue if `buffer[9] == 17`. After that, we extract the source and destionation IP address as well as the port
numbers. If one of the source or destination port is 53, we send the rest of the packet to the next function (we assume it's a DNS packet).


```c
void process_udp_payload(char * src_ip, uint16_t src_port, char* dst_ip, uint16_t dst_port, char * buffer, uint16_t len){
    // if we can successfully parse the packet, it's probably DNS packet
    // and we print information otherwise, we just return
    sdns_context * ctx = sdns_init_context();
    ctx->raw = buffer;
    ctx->raw_len = len;
    int res = sdns_from_wire(ctx);
    if (res == 0){
        // it's a DNS packet
        uint16_t dns_id = ctx->msg->header.id;
        char qr[20];
        if (ctx->msg->header.qr == 0)
            strcpy(qr, "[Q]");
        else
            strcpy(qr, "[R]");
        fprintf(stdout, "%d %s:%d -> %s:%d ---- %s: ", dns_id, src_ip, src_port, dst_ip, dst_port, qr);
        sdns_neat_print_question(ctx);
    }
    ctx->raw = NULL;
    ctx->raw_len = 0;
    sdns_free_context(ctx);
    return;

}
```

The last function is the `process_udp_payload()` which receives its payload from `analyze_data()` function. This is where we use sdns_from_wire()
function to convert what we received from the socket to a DNS structure. If we get error from sdns_from_wire() function, we assume that this is not a 
valid DNS packet and we just drop it. Otherwise, we print the question section of the packet along with the DNS ID and address of the sender and the receiver.

In the last line of the function, we use sdns_free_context() to free the memory. However, notice that we set _raw_ pointer to `NULL` before passing the context
to sdns_free_context() (`ctx->raw = NULL;`). The reason is simple but very important: `ctx->raw` refers to the buffer we received as an argument in `process_udp_payload()`
function. This buffer has been created in the `main()` function using `malloc()`. We also free this memory at the very end of the `main()` function. sdns_free_context() tries
to free the raw buffer by calling `free(ctx->raw)` (you can check the source code in sdns.c) and this will result in double free which we can easily avoid just by setting
this pointer to NULL before passing the context to sdns_free_context() function.

Here is what I get on my PC after compiling and running the code:

```text
49902 1.0.2.89:53 -> 19.0.168.255:33137 ---- [R]: 	img-prod-cms-rt-microsoft-com.akamaized.net.	IN	A
53909 53.0.0.127:53 -> 1.0.0.127:61277 ---- [R]: 	img-prod-cms-rt-microsoft-com.akamaized.net.	IN	A
53909 53.0.0.127:53 -> 1.0.0.127:61277 ---- [R]: 	img-prod-cms-rt-microsoft-com.akamaized.net.	IN	A
44504 1.0.2.89:53 -> 19.0.168.255:58445 ---- [R]: 	e13678.dscb.akamaiedge.net.	IN	HTTPS
27081 53.0.0.127:53 -> 1.0.0.127:30296 ---- [R]: 	www.microsoft.com.	IN	HTTPS
27081 53.0.0.127:53 -> 1.0.0.127:30296 ---- [R]: 	www.microsoft.com.	IN	HTTPS
20533 1.0.2.89:53 -> 19.0.168.255:54053 ---- [R]: 	img-prod-cms-rt-microsoft-com.akamaized.net.	IN	HTTPS
58223 19.0.168.255:65445 -> 1.0.2.89:53 ---- [Q]: 	a1449.dscg2.akamai.net.	IN	HTTPS
51281 1.0.2.89:53 -> 19.0.168.255:50754 ---- [R]: 	e40491.dscg.akamaiedge.net.	IN	HTTPS
38503 53.0.0.127:53 -> 1.0.0.127:51459 ---- [R]: 	res.cdn.office.net.	IN	HTTPS
38503 53.0.0.127:53 -> 1.0.0.127:51459 ---- [R]: 	res.cdn.office.net.	IN	HTTPS
14838 1.0.0.127:16392 -> 53.0.0.127:53 ---- [Q]: 	portal.office.com.	IN	A
14838 1.0.0.127:16392 -> 53.0.0.127:53 ---- [Q]: 	portal.office.com.	IN	A
9083 1.0.0.127:38013 -> 53.0.0.127:53 ---- [Q]: 	portal.office.com.	IN	HTTPS
9083 1.0.0.127:38013 -> 53.0.0.127:53 ---- [Q]: 	portal.office.com.	IN	HTTPS
21131 19.0.168.255:48483 -> 1.0.2.89:53 ---- [Q]: 	portal.office.com.	IN	A
53035 19.0.168.255:58716 -> 1.0.2.89:53 ---- [Q]: 	portal.office.com.	IN	HTTPS
27473 1.0.0.127:65420 -> 53.0.0.127:53 ---- [Q]: 	outlook.office.com.	IN	A
27473 1.0.0.127:65420 -> 53.0.0.127:53 ---- [Q]: 	outlook.office.com.	IN	A

```
And now you know my IP address :-)
