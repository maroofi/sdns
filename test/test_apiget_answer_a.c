#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sdns.h>
#include <sdns_api.h>
#include <sdns_utils.h>

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
    sdns_context * dns = sdns_create_query("google.com", "A", "IN");
    assert(dns != NULL);
    
    // add a record to answer section
    assert(sdns_add_rr_answer_A(dns, "google.com", 3000, "1.2.3.4") == 0);
    
    // now we want to get the answer from the context (it's already decoded)
    int err;
    sdns_rr * rr =  sdns_get_answer(dns, &err, 0);
    assert(err == 0);
    assert(rr != NULL);

    // let's print the A record
    
    char ip[20] = {0x00};
    cipv4_uint_to_str(((sdns_rr_A*)rr->psdns_rr)->address, ip);
    assert(memcmp("1.2.3.4", ip, strlen("1.2.3.4")) == 0);

    // get another one that is NULL
    sdns_rr * rr1 =  sdns_get_answer(dns, &err, 1);
    assert(err == SDNS_ERROR_NO_ANSWER_FOUND);
    assert(rr1 == NULL);


    // we have to free the section we got
    free(rr->name);
    sdns_free_rr_A(rr->psdns_rr);
    free(rr);

    // let's print the packet
    // sdns_neat_print_dns(dns);

    // let's free the context and we are done!
    sdns_free_context(dns);

    return 0;
}

int test2(){
    // this is yahoo dig for A record. here is the list of A records in order:
    // 74.6.231.20, 98.137.11.163, 98.137.11.164, 74.6.143.25, 74.6.231.21, 74.6.143.26
    char packet_bytes[] = {
      0x04, 0xa0, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06,
      0x00, 0x00, 0x00, 0x01, 0x05, 0x79, 0x61, 0x68,
      0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
      0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x04, 0x4a,
      0x06, 0xe7, 0x14, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x04, 0x62,
      0x89, 0x0b, 0xa3, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x04, 0x62,
      0x89, 0x0b, 0xa4, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x04, 0x4a,
      0x06, 0x8f, 0x19, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x04, 0x4a,
      0x06, 0xe7, 0x15, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x68, 0x00, 0x04, 0x4a,
      0x06, 0x8f, 0x1a, 0x00, 0x00, 0x29, 0x04, 0xd0,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // create context from network data
    sdns_context * dns = sdns_from_network(packet_bytes, sizeof(packet_bytes));
    assert(dns != NULL);
    
    int err;
    char ip[20] = {0x00};

    // get the first answer
    sdns_rr * rr0 = sdns_get_answer(dns, &err, 0);
    assert(rr0 != NULL);
    cipv4_uint_to_str(((sdns_rr_A*)rr0->psdns_rr)->address, ip);
    assert(memcmp(ip, "74.6.231.20", strlen("74.6.231.20")) == 0);
    assert(memcmp(rr0->name, "yahoo.com.", strlen(rr0->name)) == 0);
    sdns_free_section(rr0);
    
    // get the second answer
    sdns_rr * rr1 = sdns_get_answer(dns, &err, 1);
    assert(rr1 != NULL);
    cipv4_uint_to_str(((sdns_rr_A*)rr1->psdns_rr)->address, ip);
    assert(memcmp(ip, "98.137.11.163", strlen("98.137.11.163")) == 0);
    assert(memcmp(rr1->name, "yahoo.com.", strlen(rr1->name)) == 0);
    sdns_free_section(rr1);

    // get the third answer
    sdns_rr * rr2 = sdns_get_answer(dns, &err, 2);
    assert(rr2 != NULL);
    cipv4_uint_to_str(((sdns_rr_A*)rr2->psdns_rr)->address, ip);
    assert(memcmp(ip, "98.137.11.164", strlen("98.137.11.164")) == 0);
    assert(memcmp(rr2->name, "yahoo.com.", strlen(rr2->name)) == 0);
    sdns_free_section(rr2);


    // get the 4th answer
    sdns_rr * rr3 = sdns_get_answer(dns, &err, 3);
    assert(rr3 != NULL);
    cipv4_uint_to_str(((sdns_rr_A*)rr3->psdns_rr)->address, ip);
    assert(memcmp(ip, "74.6.143.25", strlen("74.6.143.25")) == 0);
    assert(memcmp(rr3->name, "yahoo.com.", strlen(rr3->name)) == 0);
    sdns_free_section(rr3);

    // get 5th answer
    sdns_rr * rr4 = sdns_get_answer(dns, &err, 4);
    assert(rr4 != NULL);
    cipv4_uint_to_str(((sdns_rr_A*)rr4->psdns_rr)->address, ip);
    assert(memcmp(ip, "74.6.231.21", strlen("74.6.231.21")) == 0);
    assert(memcmp(rr4->name, "yahoo.com.", strlen(rr4->name)) == 0);
    sdns_free_section(rr4);
    
    // get the last one (6th)
    sdns_rr * rr5 = sdns_get_answer(dns, &err, 5);
    assert(rr5 != NULL);
    cipv4_uint_to_str(((sdns_rr_A*)rr5->psdns_rr)->address, ip);
    assert(memcmp(ip, "74.6.143.26", strlen("74.6.143.26")) == 0);
    assert(memcmp(rr5->name, "yahoo.com.", strlen(rr5->name)) == 0);
    sdns_free_section(rr5);

    sdns_free_context(dns);
    return 0;
}
