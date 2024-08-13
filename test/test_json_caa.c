#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdns.h>
#include <sdns_print.h>
#include <sdns_json.h>
#include <time.h>
#include <assert.h>

// compile with:
// gcc -g -Werror test_json_caa.c ../src/sdns.c ../src/sdns_dynamic_buffer.c ../src/sdns_utils.c  ../src/sdns_json.c -I. -I../include -o test && valgrind -s --leak-check=full ./test

/**
 * Domain Name System (response)
 *   Transaction ID: 0x8f72
 *   Flags: 0x8500 Standard query response, No error
 *       1... .... .... .... = Response: Message is a response
 *       .000 0... .... .... = Opcode: Standard query (0)
 *       .... .1.. .... .... = Authoritative: Server is an authority for domain
 *       .... ..0. .... .... = Truncated: Message is not truncated
 *       .... ...1 .... .... = Recursion desired: Do query recursively
 *       .... .... 0... .... = Recursion available: Server can't do recursive queries
 *       .... .... .0.. .... = Z: reserved (0)
 *       .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
 *       .... .... ...0 .... = Non-authenticated data: Unacceptable
 *       .... .... .... 0000 = Reply code: No error (0)
 *   Questions: 1
 *   Answer RRs: 1
 *   Authority RRs: 0
 *   Additional RRs: 1
 *   Queries
 *       fakedomain.fake: type CAA, class IN
 *           Name: fakedomain.fake
 *           [Name Length: 15]
 *           [Label Count: 2]
 *           Type: CAA (257) (Certification Authority Restriction)
 *           Class: IN (0x0001)
 *   Answers
 *       fakedomain.fake: type CAA, class IN
 *           Name: fakedomain.fake
 *           Type: CAA (257) (Certification Authority Restriction)
 *           Class: IN (0x0001)
 *           Time to live: 3600 (1 hour)
 *           Data length: 55
 *           CAA Flags: 0x01
 *               0... .... = Issuer Critical: Not critical
 *           Issue Wildcard: filovirid.com; name=sourena;lastname=maroofi
 *               Tag length: 9
 *               Tag: issuewild
 *               Value: filovirid.com; name=sourena;lastname=maroofi
 *   Additional records
 *       <Root>: type OPT
 *           Name: <Root>
 *           Type: OPT (41)
 *           UDP payload size: 1232
 *           Higher bits in extended RCODE: 0x00
 *           EDNS0 version: 0
 *           Z: 0x0000
 *               0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
 *               .000 0000 0000 0000 = Reserved: 0x0000
 *           Data length: 28
 *           Option: COOKIE
 *               Option Code: COOKIE (10)
 *               Option Length: 24
 *               Option Data: 3fa42a379de73aad0100000066bb488b7d2e0ab2fd4ac926
 *               Client Cookie: 3fa42a379de73aad
 *               Server Cookie: 0100000066bb488b7d2e0ab2fd4ac926
 *   [Request In: 3]
 *   [Time: 0.000468169 seconds]
**/

int main(int argc, char ** argv){
    srand(time(NULL));
    sdns_context * dns_ctx = sdns_init_context();
    if (NULL == dns_ctx){
        fprintf(stderr, "Can not initialize the DNS context...\n");
        return 1;
    }
    char packet_bytes[] = {
      0x8f, 0x72, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01, 0x0a, 0x66, 0x61, 0x6b,
      0x65, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x04,
      0x66, 0x61, 0x6b, 0x65, 0x00, 0x01, 0x01, 0x00,
      0x01, 0xc0, 0x0c, 0x01, 0x01, 0x00, 0x01, 0x00,
      0x00, 0x0e, 0x10, 0x00, 0x37, 0x01, 0x09, 0x69,
      0x73, 0x73, 0x75, 0x65, 0x77, 0x69, 0x6c, 0x64,
      0x66, 0x69, 0x6c, 0x6f, 0x76, 0x69, 0x72, 0x69,
      0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x3b, 0x20, 0x6e,
      0x61, 0x6d, 0x65, 0x3d, 0x73, 0x6f, 0x75, 0x72,
      0x65, 0x6e, 0x61, 0x3b, 0x6c, 0x61, 0x73, 0x74,
      0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x6d, 0x61, 0x72,
      0x6f, 0x6f, 0x66, 0x69, 0x00, 0x00, 0x29, 0x04,
      0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00,
      0x0a, 0x00, 0x18, 0x3f, 0xa4, 0x2a, 0x37, 0x9d,
      0xe7, 0x3a, 0xad, 0x01, 0x00, 0x00, 0x00, 0x66,
      0xbb, 0x48, 0x8b, 0x7d, 0x2e, 0x0a, 0xb2, 0xfd,
      0x4a, 0xc9, 0x26
    };

    dns_ctx->raw = packet_bytes;
    dns_ctx->raw_len = sizeof(packet_bytes);
    int res = sdns_from_wire(dns_ctx);
    assert(res == 0);
    char *dmp = sdns_json_dns_string(dns_ctx);
    fprintf(stdout, "%s\n", dmp);
    free(dmp);
    dns_ctx->raw = NULL;
    sdns_free_context(dns_ctx);
    return 0;
}