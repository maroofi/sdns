#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sdns.h>
#include <sdns_api.h>
#include <sdns_utils.h>

//compile:
//gcc -o test test_create_response_from_query sdns.c sdns_utils.c sdns_dynamic_buffer.c sdns_print.c sdns_api.c -I. && valgrind -s --leak-check=full ./test


int test2(void);

int main(int argc, char ** argv){
    assert(test2() == 0);
    fprintf(stdout, "success\n");
    return 0;
}

int test2(){
    // this is 'dig @1.1.1.1 urlabuse.com soa'
    // create context from network data
    char packet_bytes[] = {
      0x1a, 0xf2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01, 0x08, 0x75, 0x72, 0x6c,
      0x61, 0x62, 0x75, 0x73, 0x65, 0x03, 0x63, 0x6f,
      0x6d, 0x00, 0x00, 0x06, 0x00, 0x01, 0xc0, 0x0c,
      0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x07, 0x08,
      0x00, 0x2f, 0x04, 0x61, 0x6e, 0x6e, 0x61, 0x02,
      0x6e, 0x73, 0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64,
      0x66, 0x6c, 0x61, 0x72, 0x65, 0xc0, 0x15, 0x03,
      0x64, 0x6e, 0x73, 0xc0, 0x32, 0x8b, 0xcc, 0x60,
      0xd2, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x09,
      0x60, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x07,
      0x08, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    };

    sdns_context * dns = sdns_from_network(packet_bytes, sizeof(packet_bytes));
    assert(dns != NULL);
    uint16_t dns_id = dns->msg->header.id;
    int err;
    
    sdns_context * response = sdns_create_response_from_query(dns);
    sdns_free_context(dns);

    assert(strncmp("urlabuse.com.", response->msg->question.qname, strlen(response->msg->question.qname)) == 0);
    assert(response->msg->header.qr == 1);

    assert(response->msg->header.id == dns_id);

    sdns_free_context(response);
    return 0;
}
