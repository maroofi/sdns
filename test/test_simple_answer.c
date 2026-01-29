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
    /*  Simple response: example.com A with ID = 4660 (0x1234)
         *
         * Standard DNS response with:
         * - 1 question
         * - 1 answer
         * - no compression used
         * - TTL = 60 seconds
         *
         * Answer contains IPv4 address 93.184.216.34.
     */
    char packet_bytes[] = {
        0x12, 0x34,             /* ID = 4660 */
        0x81, 0x80,             /* Flags: QR, RD, RA, NOERROR */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x01,             /* ANCOUNT = 1 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */

        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00,                   /* QNAME */
        0x00, 0x01,             /* QTYPE = A */
        0x00, 0x01,             /* QCLASS = IN */

        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00,                   /* NAME (no compression) */
        0x00, 0x01,             /* TYPE = A */
        0x00, 0x01,             /* CLASS = IN */
        0x00, 0x00, 0x00, 0x3c, /* TTL = 60 */
        0x00, 0x04,             /* RDLENGTH = 4 */
        0x5d, 0xb8, 0xd8, 0x22  /* RDATA = 93.184.216.34 */
    };
   
    dns_ctx->raw = packet_bytes;
    dns_ctx->raw_len = sizeof(packet_bytes);
    int res = sdns_from_wire(dns_ctx);
    assert(res == 0);
    char * dmp = sdns_json_dns_string(dns_ctx);
    fprintf(stdout, "%s\n", dmp);
    free(dmp);
    dns_ctx->raw = NULL;
    sdns_free_context(dns_ctx);
    return 0;
}
