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
    /* Max-length domain name query with ID = 48879 (0xbeef)
     *
     * This packet tests DNS name length boundaries:
     *
     * - Uses FOUR labels
     *   - label 1: 63 bytes
     *   - label 2: 63 bytes
     *   - label 3: 63 bytes
     *   - label 4: 61 bytes
     *
     * Wire length calculation:
     *   (63+1) + (63+1) + (63+1) + (61+1) + 1(root) = 255 bytes (MAX)
     *
     * This hits:
     * - maximum label length (63)
     * - maximum full domain name length (255)
     *
     * Expected result: successful parse.
     */
    char packet_bytes[] = {
        /* ================= DNS HEADER ================= */
        0xbe, 0xef,             /* ID = 0xbeef = 48879 */
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

        /* Label 4: length = 61 */
        0x3d,
        'd','d','d','d','d','d','d','d','d','d','d','d','d','d','d','d',
        'd','d','d','d','d','d','d','d','d','d','d','d','d','d','d','d',
        'd','d','d','d','d','d','d','d','d','d','d','d','d','d','d','d',
        'd','d','d','d','d','d','d','d','d','d','d','d','d',

        0x00,                   /* Root label */

        0x00, 0x01,             /* QTYPE = A */
        0x00, 0x01              /* QCLASS = IN */
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
