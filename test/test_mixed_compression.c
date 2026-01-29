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
    /* Response with mixed label + compression pointer, ID = 1 (0x0001)
     *
     * Answer name is:
     *   www.example.com
     *
     * Encoded as:
     *   03 'www' + pointer to example.com
     *
     * This tests correct handling of mixed label and pointer names.
     */
    char packet_bytes[] = {
        0x00, 0x01,             /* ID = 1 */
        0x81, 0x80,             /* Flags: QR, RD, RA */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x01,             /* ANCOUNT = 1 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */

        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00,                   /* QNAME = example.com. */
        0x00, 0x01,             /* QTYPE = A */
        0x00, 0x01,             /* QCLASS = IN */

        0x03, 'w','w','w',
        0xc0, 0x0c,             /* pointer to example.com */
        0x00, 0x01,             /* TYPE = A */
        0x00, 0x01,             /* CLASS = IN */
        0x00, 0x00, 0x00, 0x3c, /* TTL = 60 */
        0x00, 0x04,             /* RDLENGTH = 4 */
        0x01, 0x02, 0x03, 0x04  /* RDATA */
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
