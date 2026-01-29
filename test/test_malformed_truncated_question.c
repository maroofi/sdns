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
    /* Malformed packet: truncated question, ID = 1 (0x0001)
     *
     * Packet ends before QCLASS is fully present.
     * Parser must detect truncation and fail gracefully.
     */
    char packet_bytes[] = {
        0x00, 0x01,             /* ID = 1 */
        0x81, 0x80,             /* Flags */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x01,             /* ANCOUNT = 1 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */

        0x01, 'a', 0x00,        /* QNAME = a. */
        0x00, 0x01,             /* QTYPE = A */
        0x00                    /* QCLASS truncated */
    };
   
    dns_ctx->raw = packet_bytes;
    dns_ctx->raw_len = sizeof(packet_bytes);
    int res = sdns_from_wire(dns_ctx);
    assert(res != 0);
    char * err_string = NULL;
    sdns_error_string(res, &err_string);
    fprintf(stdout, "%s\n", err_string);
    free(err_string);
    dns_ctx->raw = NULL;
    sdns_free_context(dns_ctx);
    return 0;
}
