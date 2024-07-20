#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sdns.h>
#include <sdns_api.h>
#include <sdns_utils.h>

//compile:
//gcc -o test test_apiget_answer_ns.c sdns.c sdns_utils.c sdns_dynamic_buffer.c sdns_print.c sdns_api.c -I. && valgrind -s --leak-check=full ./test


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
    sdns_context * dns = sdns_create_query("google.com", "TXT", "IN");
    assert(dns != NULL);
    
    // add a record to answer section
    assert(sdns_add_rr_answer_NS(dns, "google.com.", 200, "ns1.google.com") == 0);
    
    // now we want to get the answer from the context (it's already decoded)
    int err;
    sdns_rr * rr =  sdns_get_answer(dns, &err, 0);
    assert(err == 0);
    assert(rr != NULL);
    assert(strcmp(((sdns_rr_NS*)rr->psdns_rr)->NSDNAME, "ns1.google.com") == 0);
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
    // this is google.com dig for ns record. here is the list of ns records in order:
    // ns4.google.com, ns2.google.com, ns3.google.com, ns1.google.com
    // create context from network data
    char packet_bytes[] = {
      0xff, 0xa6, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04,
      0x00, 0x00, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f,
      0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
      0x00, 0x02, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x02,
      0x00, 0x01, 0x00, 0x05, 0x40, 0xdf, 0x00, 0x06,
      0x03, 0x6e, 0x73, 0x34, 0xc0, 0x0c, 0xc0, 0x0c,
      0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x40, 0xdf,
      0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c,
      0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05,
      0x40, 0xdf, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x33,
      0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01,
      0x00, 0x05, 0x40, 0xdf, 0x00, 0x06, 0x03, 0x6e,
      0x73, 0x31, 0xc0, 0x0c, 0x00, 0x00, 0x29, 0x04,
      0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    sdns_context * dns = sdns_from_network(packet_bytes, sizeof(packet_bytes));
    assert(dns != NULL);
    
    int err;

    // get the first answer
    sdns_rr * rr0 = sdns_get_answer(dns, &err, 0);
    assert(rr0 != NULL);
    assert(strcmp(((sdns_rr_NS*)rr0->psdns_rr)->NSDNAME, "ns4.google.com.") == 0);
    assert(memcmp(rr0->name, "google.com.", strlen(rr0->name)) == 0);
    sdns_free_section(rr0);
    
    // get the second answer
    sdns_rr * rr1 = sdns_get_answer(dns, &err, 1);
    assert(rr1 != NULL);
    assert(strcmp(((sdns_rr_NS*)rr1->psdns_rr)->NSDNAME, "ns2.google.com.") == 0);
    assert(memcmp(rr1->name, "google.com.", strlen(rr1->name)) == 0);
    sdns_free_section(rr1);


    // get the one that does not exist
    sdns_rr * rr2 = sdns_get_answer(dns, &err, 4);
    assert(rr2 == NULL);
    assert(err == SDNS_ERROR_NO_ANSWER_FOUND);
    sdns_free_section(rr2);

    sdns_free_context(dns);
    return 0;
}
