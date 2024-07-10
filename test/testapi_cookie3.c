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
#include <sdns_utils.h>

// asking for client cookie from a packet which has ends0+cookie but it's malformed


int main(){


    char packet_bytes[] = {
      0x54, 0x0f, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x08, 0x75, 0x72, 0x6c,
      0x61, 0x62, 0x75, 0x73, 0x65, 0x03, 0x63, 0x6f,
      0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0a, 0x00,
      0x08, 0xa4, 0xf9, 0x81, 0x85, 0xd9, 0xa8,// 0x79,
                                               // here we just removed the seventh byte of the cookie
                                               // so the option_length is still 8 but the actual packet misses one bytes
      0xa8
    };

       

    sdns_context * dns = sdns_from_network(packet_bytes, sizeof(packet_bytes));
    assert(dns != NULL);
    
    // check all the header values
    assert(dns->msg->header.id == 0x540f);
    assert(dns->msg->header.qr == 0);
    assert(dns->msg->header.opcode == 0);
    assert(dns->msg->header.aa == 0);
    assert(dns->msg->header.tc == 0);
    assert(dns->msg->header.rd == 1);
    assert(dns->msg->header.ra == 0);
    assert(dns->msg->header.z == 0);
    assert(dns->msg->header.AD == 1);
    assert(dns->msg->header.CD == 0);
    assert(dns->msg->header.rcode == 0);
    assert(dns->msg->header.ancount == 0);
    assert(dns->msg->header.qdcount == 1);
    assert(dns->msg->header.arcount == 1);
    assert(dns->msg->header.nscount == 0);

    // check all the question parts
    assert(strcmp(dns->msg->question.qname, "urlabuse.com.") == 0);
    assert(dns->msg->question.qtype == 1);
    assert(dns->msg->question.qclass == 1);
    
    // additional section is encoded
    assert(dns->msg->additional->decoded == 0);
    
    int err = 0;
    char * cookie = sdns_get_value_cookie_client(dns, &err);
    assert(cookie == NULL);
    assert(err == SDNS_ERROR_RR_SECTION_MALFORMED);
    // free the memory for checking with valgrind
    sdns_free_context(dns);

    //perform_lookup_udp(buff, buff_len);
    
    // necessary output for the test
    fprintf(stdout, "success\n");
    return 0;
}
