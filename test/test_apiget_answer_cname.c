#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sdns.h>
#include <sdns_api.h>
#include <sdns_utils.h>

//compile:
//gcc -o test test_apiget_answer_cname.c sdns.c sdns_utils.c sdns_dynamic_buffer.c sdns_print.c sdns_api.c -I. && valgrind -s --leak-check=full ./test


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
    
    // add a record to answer section
    assert(sdns_add_rr_answer_CNAME(dns, "google.com.", 200, "cname.google.com") == 0);
    
    // now we want to get the answer from the context (it's already decoded)
    int err;
    sdns_rr * rr =  sdns_get_answer(dns, &err, 0);
    assert(err == 0);
    assert(rr != NULL);
    assert(strcmp(((sdns_rr_CNAME*)rr->psdns_rr)->CNAME, "cname.google.com") == 0);
    assert(rr->class == sdns_q_class_IN);
    assert(strcmp(rr->name, "google.com.") == 0);
    sdns_free_section(rr);

    // get another one that is NULL
    sdns_rr * rr1 =  sdns_get_answer(dns, &err, 1);
    assert(err == SDNS_ERROR_NO_ANSWER_FOUND);
    assert(rr1 == NULL);

    // let's free the context and we are done!
    sdns_free_context(dns);
    return 0;
}

int test2(){
    // this is 'dig @1.1.1.1 CNAME cname-example.lookup.dog'
    // cname-example.lookup.dog. 3600	IN	CNAME	dns.lookup.dog.
    // create context from network data
    char packet_bytes[] = {
      0xc1, 0x68, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01, 0x0d, 0x63, 0x6e, 0x61,
      0x6d, 0x65, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70,
      0x6c, 0x65, 0x06, 0x6c, 0x6f, 0x6f, 0x6b, 0x75,
      0x70, 0x03, 0x64, 0x6f, 0x67, 0x00, 0x00, 0x05,
      0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01,
      0x00, 0x00, 0x0e, 0x10, 0x00, 0x06, 0x03, 0x64,
      0x6e, 0x73, 0xc0, 0x1a, 0x00, 0x00, 0x29, 0x04,
      0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };


    sdns_context * dns = sdns_from_network(packet_bytes, sizeof(packet_bytes));
    assert(dns != NULL);
    
    int err;

    // get the first answer
    sdns_rr * rr0 = sdns_get_answer(dns, &err, 0);
    assert(rr0 != NULL);
    assert(strcmp(((sdns_rr_CNAME*)rr0->psdns_rr)->CNAME, "dns.lookup.dog.") == 0);
    assert(memcmp(rr0->name, "cname-example.lookup.dog.", strlen(rr0->name)) == 0);
    assert(rr0->ttl == 3600);
    assert(rr0->class == sdns_q_class_IN);
    sdns_free_section(rr0);
    
    // get the one that does not exist
    sdns_rr * rr2 = sdns_get_answer(dns, &err, 4);
    assert(rr2 == NULL);
    assert(err == SDNS_ERROR_NO_ANSWER_FOUND);
    sdns_free_section(rr2);

    sdns_free_context(dns);
    return 0;
}
