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

// asking for NSID from a packet which has ends0+ede+nsid
// and nsid has null character in it!


int main(){
    char packet_bytes[] = {
      0x75, 0x10, 0x81, 0x82, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x0d, 0x64, 0x6e, 0x73,
      0x73, 0x65, 0x63, 0x2d, 0x66, 0x61, 0x69, 0x6c,
      0x65, 0x64, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00,
      0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x0f,
      0x00, 0x35, 0x00, 0x09, 0x6e, 0x6f, 0x20, 0x53,
      0x45, 0x50, 0x20, 0x6d, 0x61, 0x74, 0x63, 0x68,
      0x69, 0x6e, 0x67, 0x20, 0x74, 0x68, 0x65, 0x20,
      0x44, 0x53, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64,
      0x20, 0x66, 0x6f, 0x72, 0x20, 0x64, 0x6e, 0x73,
      0x73, 0x65, 0x63, 0x2d, 0x66, 0x61, 0x69, 0x6c,
      0x65, 0x64, 0x2e, 0x6f, 0x72, 0x67, 0x2e, 0x00,
      0x03, 0x00, 0x07, 0x36, 0x33, 0x36, 0x6d, 0x32,
      0x00, 0x36
    };

    sdns_context * dns = sdns_from_network(packet_bytes, sizeof(packet_bytes));
    assert(dns != NULL);
    
    // check all the header values
    assert(dns->msg->header.id == 0x7510);
    assert(dns->msg->header.qr == 1);
    assert(dns->msg->header.opcode == 0);
    assert(dns->msg->header.aa == 0);
    assert(dns->msg->header.tc == 0);
    assert(dns->msg->header.rd == 1);
    assert(dns->msg->header.ra == 1);
    assert(dns->msg->header.z == 0);
    assert(dns->msg->header.AD == 0);
    assert(dns->msg->header.CD == 0);
    assert(dns->msg->header.rcode == 2);
    assert(dns->msg->header.ancount == 0);
    assert(dns->msg->header.qdcount == 1);
    assert(dns->msg->header.arcount == 1);
    assert(dns->msg->header.nscount == 0);

    // check all the question parts
    assert(strcmp(dns->msg->question.qname, "dnssec-failed.org.") == 0);
    assert(dns->msg->question.qtype == 1);
    assert(dns->msg->question.qclass == 1);
    
    // additional section is encoded
    assert(dns->msg->additional->decoded == 0);
    
    int err = 0;
    uint16_t len = 0;
    char * nsid = sdns_get_value_nsid(dns, &err, &len);
    assert(nsid != NULL);
    assert(err == 0);
    assert(len != 0);
    char expeted_nsid[] = {0x36, 0x33, 0x36, 0x6d, 0x32, 0x00, 0x36};     // "636m2\0006"
    assert(memcmp(expeted_nsid, nsid, len) == 0);
    free(nsid);
    // free the memory for checking with valgrind
    sdns_free_context(dns);

    //perform_lookup_udp(buff, buff_len);

    fprintf(stdout, "success\n");
    return 0;
}
