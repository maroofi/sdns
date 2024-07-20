#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include <sdns.h>
#include <sdns_api.h>
#include <sdns_utils.h>

//compile:
//gcc -o test test_apiget_answer_txt.c sdns.c sdns_utils.c sdns_dynamic_buffer.c sdns_print.c sdns_api.c -I. && valgrind -s --leak-check=full ./test


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
    assert(sdns_add_rr_answer_TXT(dns, "google.com", 200, "sour\0ena", 8) == 0);
    // now we want to get the answer from the context (it's already decoded)
    int err;
    sdns_rr * rr =  sdns_get_answer(dns, &err, 0);
    assert(err == 0);
    assert(rr != NULL);
    assert(memcmp(((sdns_rr_TXT*)rr->psdns_rr)->character_string.content, "sour\0ena", 8) == 0);
    assert(rr->class == sdns_q_class_IN);
    assert(strcmp(rr->name, "google.com") == 0);
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
    // this is urlabuse.com dig for TXT record. here is the list of TXT records in order:
    // google-site-verification=wGLZMNWYv3IiNCZ9zxM0hfZlzqGloyAQ_y2r7OV_vJ8 (len=68)
    // v=spf1 include:zoho.eu ~all (len=27)
    // create context from network data
    char packet_bytes[] = {
      0x89, 0x68, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02,
      0x00, 0x00, 0x00, 0x01, 0x08, 0x75, 0x72, 0x6c,
      0x61, 0x62, 0x75, 0x73, 0x65, 0x03, 0x63, 0x6f,
      0x6d, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c,
      0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c,
      0x00, 0x45, 0x44, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
      0x65, 0x2d, 0x73, 0x69, 0x74, 0x65, 0x2d, 0x76,
      0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
      0x69, 0x6f, 0x6e, 0x3d, 0x77, 0x47, 0x4c, 0x5a,
      0x4d, 0x4e, 0x57, 0x59, 0x76, 0x33, 0x49, 0x69,
      0x4e, 0x43, 0x5a, 0x39, 0x7a, 0x78, 0x4d, 0x30,
      0x68, 0x66, 0x5a, 0x6c, 0x7a, 0x71, 0x47, 0x6c,
      0x6f, 0x79, 0x41, 0x51, 0x5f, 0x79, 0x32, 0x72,
      0x37, 0x4f, 0x56, 0x5f, 0x76, 0x4a, 0x38, 0xc0,
      0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01,
      0x2c, 0x00, 0x1c, 0x1b, 0x76, 0x3d, 0x73, 0x70,
      0x66, 0x31, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
      0x64, 0x65, 0x3a, 0x7a, 0x6f, 0x68, 0x6f, 0x2e,
      0x65, 0x75, 0x20, 0x7e, 0x61, 0x6c, 0x6c, 0x00,
      0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00
    };

    sdns_context * dns = sdns_from_network(packet_bytes, sizeof(packet_bytes));
    assert(dns != NULL);
    
    int err;

    // get the first answer
    sdns_rr * rr0 = sdns_get_answer(dns, &err, 0);
    assert(rr0 != NULL);
    char t1[] = "google-site-verification=wGLZMNWYv3IiNCZ9zxM0hfZlzqGloyAQ_y2r7OV_vJ8";
    assert(memcmp(((sdns_rr_TXT*)rr0->psdns_rr)->character_string.content, t1, strlen(t1)) == 0);
    assert(memcmp(rr0->name, "urlabuse.com.", strlen(rr0->name)) == 0);
    sdns_free_section(rr0);
    
    // get the second answer
    sdns_rr * rr1 = sdns_get_answer(dns, &err, 1);
    assert(rr1 != NULL);
    char t2[] = "v=spf1 include:zoho.eu ~all";
    assert(memcmp(((sdns_rr_TXT*)rr1->psdns_rr)->character_string.content, t2, 27) == 0);
    assert(memcmp(rr1->name, "urlabuse.com.", strlen(rr1->name)) == 0);
    sdns_free_section(rr1);


    // get the one that does not exist
    sdns_rr * rr2 = sdns_get_answer(dns, &err, 2);
    assert(rr2 == NULL);
    assert(err == SDNS_ERROR_NO_ANSWER_FOUND);
    sdns_free_section(rr2);

    sdns_free_context(dns);
    return 0;
}
