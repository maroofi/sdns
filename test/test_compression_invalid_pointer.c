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
    /* Invalid packet: compression pointer used as a label length (must fail)
     *
     * ID = 48883 (0xbef3)
     *
     * This packet tests a parser’s handling of invalid pointers:
     *
     * - Wire layout:
     *   * The first byte of the QNAME is a pointer (0xc0 0x0c)
     *   * No preceding label length
     *
     * RFC 1035 rules:
     * - Compression pointer must only appear **after at least one label byte** if not at start?
     *   Actually: pointer can appear anywhere, but must point to a valid name.
     * - This test assumes **parser must reject a pointer used improperly**
     *   as a "label length" (i.e., before a valid name sequence)
     *
     * Expected: parser must reject this packet.
     */
    char packet_bytes[] = {
        /* ================= DNS HEADER ================= */
        0xbe, 0xf3,             /* ID = 0xbef3 = 48883 */
        0x01, 0x00,             /* Flags: RD */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x00,             /* ANCOUNT = 0 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */

        /* ================= QUESTION ================= */
        0xc0, 0x0c,             /* INVALID: compression pointer used as label start */

        0x00, 0x01,             /* QTYPE = A */
        0x00, 0x01              /* QCLASS = IN */
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
