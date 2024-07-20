#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sdns.h>
#include <sdns_api.h>
#include <sdns_utils.h>

//compile:
//gcc -o test test_apiget_answer_mx.c sdns.c sdns_utils.c sdns_dynamic_buffer.c sdns_print.c sdns_api.c -I. && valgrind -s --leak-check=full ./test


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
    sdns_context * dns = sdns_create_query("google.com", "mx", "IN");
    assert(dns != NULL);
    
    // add a record to answer section
    assert(sdns_add_rr_answer_MX(dns, "urlabuse.com.", 200, 10, "mx.google.com") == 0);
    
    // now we want to get the answer from the context (it's already decoded)
    int err;
    sdns_rr * rr =  sdns_get_answer(dns, &err, 0);
    assert(err == 0);
    assert(rr != NULL);
    assert(strcmp(((sdns_rr_MX*)rr->psdns_rr)->exchange, "mx.google.com") == 0);
    assert(rr->class == sdns_q_class_IN);
    assert(strcmp(rr->name, "urlabuse.com.") == 0);
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
    // this is google.com dig for mx record. here is the list of mx records in order:
    // 10 mx.zoho.eu, 20 mx2.zoho.eu, 50 mx3.zoho.eu
    // create context from network data
    char packet_bytes[] = {
      0x4b, 0x9e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03,
      0x00, 0x00, 0x00, 0x01, 0x08, 0x75, 0x72, 0x6c,
      0x61, 0x62, 0x75, 0x73, 0x65, 0x03, 0x63, 0x6f,
      0x6d, 0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0, 0x0c,
      0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c,
      0x00, 0x0e, 0x00, 0x0a, 0x02, 0x6d, 0x78, 0x04,
      0x7a, 0x6f, 0x68, 0x6f, 0x02, 0x65, 0x75, 0x00,
      0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00,
      0x01, 0x2c, 0x00, 0x08, 0x00, 0x14, 0x03, 0x6d,
      0x78, 0x32, 0xc0, 0x2f, 0xc0, 0x0c, 0x00, 0x0f,
      0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x08,
      0x00, 0x32, 0x03, 0x6d, 0x78, 0x33, 0xc0, 0x2f,
      0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00
    };

    sdns_context * dns = sdns_from_network(packet_bytes, sizeof(packet_bytes));
    assert(dns != NULL);
    
    int err;

    // get the first answer
    sdns_rr * rr0 = sdns_get_answer(dns, &err, 0);
    assert(rr0 != NULL);
    assert(strcmp(((sdns_rr_MX*)rr0->psdns_rr)->exchange, "mx.zoho.eu.") == 0);
    assert(((sdns_rr_MX*)rr0->psdns_rr)->preference == 10);
    assert(memcmp(rr0->name, "urlabuse.com.", strlen(rr0->name)) == 0);
    sdns_free_section(rr0);
    
    // get the second answer
    sdns_rr * rr1 = sdns_get_answer(dns, &err, 1);
    assert(rr1 != NULL);
    assert(strcmp(((sdns_rr_MX*)rr1->psdns_rr)->exchange, "mx2.zoho.eu.") == 0);
    assert(((sdns_rr_MX*)rr1->psdns_rr)->preference == 20);
    assert(memcmp(rr1->name, "urlabuse.com.", strlen(rr1->name)) == 0);
    sdns_free_section(rr1);

    // get the second answer
    sdns_rr * rr2 = sdns_get_answer(dns, &err, 2);
    assert(rr2 != NULL);
    assert(strcmp(((sdns_rr_MX*)rr2->psdns_rr)->exchange, "mx3.zoho.eu.") == 0);
    assert(((sdns_rr_MX*)rr2->psdns_rr)->preference == 50);
    assert(memcmp(rr2->name, "urlabuse.com.", strlen(rr2->name)) == 0);
    sdns_free_section(rr2);

    // get the one that does not exist
    sdns_rr * rr3 = sdns_get_answer(dns, &err, 10);
    assert(rr3 == NULL);
    assert(err == SDNS_ERROR_NO_ANSWER_FOUND);
    sdns_free_section(rr3);

    sdns_free_context(dns);
    return 0;
}
