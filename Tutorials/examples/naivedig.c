#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "sdns_print.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sdns.h"


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
    int res = sdns_make_query(query_ctx, type_int, sdns_q_class_IN, domain_name, 1);
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
