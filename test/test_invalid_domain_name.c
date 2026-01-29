#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdns.h>
#include <sdns_print.h>
#include <sdns_json.h>
#include <time.h>
#include <assert.h>


int main(int argc, char ** argv){
    srand(time(NULL));
    sdns_context * dns_ctx = sdns_init_context();
    if (NULL == dns_ctx){
        fprintf(stderr, "Can not initialize the DNS context...\n");
        return 1;
    }
    /* Invalid domain name query: label length = 64 (must fail), ID = 48880 (0xbef0)
     *
     * This packet tests enforcement of the DNS label length limit.
     *
     * RFC 1035, Section 2.3.4:
     *   - Maximum label length is 63 octets.
     *
     * This QNAME starts with a label length byte of 64 (0x40),
     * which is INVALID, even though enough bytes follow.
     *
     * Packet properties:
     * - 1 question
     * - no answers
     * - recursion desired
     * - no compression
     *
     * Expected result: parser MUST reject this packet.
     */
    char packet_bytes[] = {
        /* ================= DNS HEADER ================= */
        0xbe, 0xf0,             /* ID = 0xbef0 = 48880 */
        0x01, 0x00,             /* Flags: RD */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x00,             /* ANCOUNT = 0 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */

        /* ================= QUESTION ================= */
        0x40,                   /* INVALID label length = 64 (max allowed is 63) */
        'a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a',

        0x00,                   /* Root label (never reached if parser is correct) */

        0x00, 0x01,             /* QTYPE = A */
        0x00, 0x01              /* QCLASS = IN */
    };
   
    dns_ctx->raw = packet_bytes;
    dns_ctx->raw_len = sizeof(packet_bytes);
    int res = sdns_from_wire(dns_ctx);
    assert(res != 0);
    char * err_string = NULL;
    sdns_error_string(res, & err_string);
    fprintf(stdout, "%s\n", err_string);
    free(err_string);
    //char * dmp = sdns_json_dns_string(dns_ctx);
    //fprintf(stdout, "%s\n", dmp);
    //free(dmp);
    dns_ctx->raw = NULL;
    sdns_free_context(dns_ctx);
    return 0;
}
