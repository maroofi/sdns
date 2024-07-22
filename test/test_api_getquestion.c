#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sdns.h>
#include <sdns_api.h>
#include <sdns_utils.h>

//compile:
//gcc -o test test_api_getquestion.c sdns.c sdns_utils.c sdns_dynamic_buffer.c sdns_print.c sdns_api.c -I. && valgrind -s --leak-check=full ./test


int test1(void);
int test2(void);

int main(int argc, char ** argv){
    assert(test1() == 0);
    assert(test2() == 0);
    fprintf(stdout, "success\n");
    return 0;
}

int test1(){
    // create query packet
    sdns_context * dns = sdns_create_query("google.com", "CNAME", "IN");
    assert(dns != NULL);
    
    sdns_question * q = sdns_get_question(dns);

    assert(q != NULL);
    assert(strncmp("google.com.", q->qname, strlen(q->qname)) == 0);
    assert(q->qclass == sdns_q_class_IN);
    assert(q->qtype == sdns_rr_type_CNAME);
    free(q->qname);
    free(q);

    // let's free the context and we are done!
    sdns_free_context(dns);
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
    
    int err;
    sdns_question * q = sdns_get_question(dns);
    assert(q != NULL);
    assert(strncmp("urlabuse.com.", q->qname, strlen(q->qname)) == 0);
    assert(q->qclass == sdns_q_class_IN);
    assert(q->qtype == sdns_rr_type_SOA);
    free(q->qname);
    free(q);
    sdns_free_context(dns);
    return 0;
}
