/**
 * This file test the creation of a DNS packet with NSID enabled
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdns.h>
#include <sdns_api.h>
#include <assert.h>
//#include <send_udp.h>


int main(){
    
    // create a query packet for 'urlabuse.com IN A'
    sdns_context * dns = sdns_create_query("urlabuse.com", "A", "IN");
    assert(dns != NULL);
    
    assert(sdns_add_nsid(dns, NULL) == 0);

    int err;
    unsigned short int buff_len;
    char * buff = sdns_to_network(dns, &err, &buff_len);
    assert(buff != NULL);
    assert(err == 0);
    assert(buff_len != 0);
    
    char expected[] = {
      0xb0, 0xf2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x08, 0x75, 0x72, 0x6c,
      0x61, 0x62, 0x75, 0x73, 0x65, 0x03, 0x63, 0x6f,
      0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x04, 0x00, 0x03, 0x00, 0x00
    };
    assert(memcmp(expected, buff, buff_len) == 0);
    free(buff);
    sdns_free_context(dns);


    //perform_lookup_udp(buff, buff_len);
    
    fprintf(stdout, "success\n");

    return 0;
}
