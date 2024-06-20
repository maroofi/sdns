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













