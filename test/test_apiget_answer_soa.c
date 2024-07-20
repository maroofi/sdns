#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sdns.h>
#include <sdns_api.h>
#include <sdns_utils.h>

//compile:
//gcc -o test test_apiget_answer_soa.c sdns.c sdns_utils.c sdns_dynamic_buffer.c sdns_print.c sdns_api.c -I. && valgrind -s --leak-check=full ./test


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
    assert(sdns_add_rr_answer_SOA(dns, "google.com", 200, "m.google.com", "r.google.net", 100, 200, 300, 400, 500000) == 0);
        
    // now we want to get the answer from the context (it's already decoded)
    int err;
    sdns_rr * rr =  sdns_get_answer(dns, &err, 0);
    assert(err == 0);
    assert(rr != NULL);
    assert(strcmp(((sdns_rr_SOA*)rr->psdns_rr)->mname, "m.google.com") == 0);
    assert(strcmp(((sdns_rr_SOA*)rr->psdns_rr)->rname, "r.google.net") == 0);
    assert(rr->class == sdns_q_class_IN);
    assert(strcmp(rr->name, "google.com") == 0);
    assert(((sdns_rr_SOA*)rr->psdns_rr)->serial == 500000);
    
    assert(((sdns_rr_SOA*)rr->psdns_rr)->expire == 100);
    assert(((sdns_rr_SOA*)rr->psdns_rr)->minimum == 200);
    assert(((sdns_rr_SOA*)rr->psdns_rr)->refresh == 300);
    assert(((sdns_rr_SOA*)rr->psdns_rr)->retry == 400);
    assert(rr->ttl == 200);
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
    // urlabuse.com. 1800 IN SOA anna.ns.cloudflare.com. dns.cloudflare.com. 2345427154 10000 2400 604800 1800
    // create context from network data
    char packet_bytes[] = {
      0x3b, 0x99, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
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

    // get the first answer
    sdns_rr * rr0 = sdns_get_answer(dns, &err, 0);
    assert(rr0 != NULL);
    assert(strcmp(((sdns_rr_SOA*)rr0->psdns_rr)->rname, "dns.cloudflare.com.") == 0);
    assert(memcmp(rr0->name, "urlabuse.com.", strlen(rr0->name)) == 0);
    assert(strcmp(((sdns_rr_SOA*)rr0->psdns_rr)->mname, "anna.ns.cloudflare.com.") == 0);
    assert(((sdns_rr_SOA*)rr0->psdns_rr)->serial == 2345427154);
    sdns_free_section(rr0);
    

    // get the one that does not exist
    sdns_rr * rr2 = sdns_get_answer(dns, &err, 4);
    assert(rr2 == NULL);
    assert(err == SDNS_ERROR_NO_ANSWER_FOUND);
    sdns_free_section(rr2);

    sdns_free_context(dns);
    return 0;
}
