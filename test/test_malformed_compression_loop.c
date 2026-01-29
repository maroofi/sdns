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
        0xaa, 0xbb,             /* ID = 43707 */
        0x81, 0x80,             /* Flags: QR */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x00,             /* ANCOUNT = 0 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */

        0xc0, 0x0c,             /* QNAME = pointer to itself */
        0x00, 0x01,             /* QTYPE = A */
        0x00, 0x01              /* QCLASS = IN */
    };
    dns_ctx->raw = packet_bytes;
    dns_ctx->raw_len = sizeof(packet_bytes);
    int res = sdns_from_wire(dns_ctx);
    assert(res != 0);
    char *err_code = NULL;
    sdns_error_string(res, &err_code);
    fprintf(stdout, "%s\n", err_code);
    free(err_code);
    dns_ctx->raw = NULL;
    sdns_free_context(dns_ctx);
    return 0;
}
