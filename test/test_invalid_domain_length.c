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
    /* Invalid domain name query: total domain length = 256 bytes (must fail)
     *
     * ID = 48881 (0xbef1)
     *
     * This packet tests enforcement of the maximum total DNS name length.
     *
     * RFC 1035, Section 2.3.4:
     *   - The total length of a domain name (including label length octets
     *     and the terminating root label) must not exceed 255 bytes.
     *
     * This QNAME uses:
     * - four labels of 63 bytes each
     * - one label of 62 bytes
     *
     * Wire length calculation:
     *   (63+1) * 4 + (62+1) + 1 = 256 bytes  <-- INVALID
     *
     * All individual labels are valid, but the total name length is not.
     *
     * Expected result: parser MUST reject this packet.
     */
    char packet_bytes[] = {
        /* ================= DNS HEADER ================= */
        0xbe, 0xf1,             /* ID = 0xbef1 = 48881 */
        0x01, 0x00,             /* Flags: RD */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x00,             /* ANCOUNT = 0 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */

        /* ================= QUESTION ================= */

        /* Label 1: length = 63 */
        0x3f,
        'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',

        /* Label 2: length = 63 */
        0x3f,
        'b','b','b','b','b','b','b','b','b','b','b','b','b','b','b','b',
        'b','b','b','b','b','b','b','b','b','b','b','b','b','b','b','b',
        'b','b','b','b','b','b','b','b','b','b','b','b','b','b','b','b',
        'b','b','b','b','b','b','b','b','b','b','b','b','b','b','b',

        /* Label 3: length = 63 */
        0x3f,
        'c','c','c','c','c','c','c','c','c','c','c','c','c','c','c','c',
        'c','c','c','c','c','c','c','c','c','c','c','c','c','c','c','c',
        'c','c','c','c','c','c','c','c','c','c','c','c','c','c','c','c',
        'c','c','c','c','c','c','c','c','c','c','c','c','c','c','c',

        /* Label 4: length = 63 */
        0x3f,
        'd','d','d','d','d','d','d','d','d','d','d','d','d','d','d','d',
        'd','d','d','d','d','d','d','d','d','d','d','d','d','d','d','d',
        'd','d','d','d','d','d','d','d','d','d','d','d','d','d','d','d',
        'd','d','d','d','d','d','d','d','d','d','d','d','d','d','d',

        /* Label 5: length = 62 */
        0x3e,
        'e','e','e','e','e','e','e','e','e','e','e','e','e','e','e','e',
        'e','e','e','e','e','e','e','e','e','e','e','e','e','e','e','e',
        'e','e','e','e','e','e','e','e','e','e','e','e','e','e','e','e',
        'e','e','e','e','e','e','e','e','e','e','e','e','e','e',

        0x00,                   /* Root label */

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
