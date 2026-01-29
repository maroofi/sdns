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
    /* Invalid packet: label lengths valid but total name > 255 after compression expansion
     *
     * ID = 48884 (0xbef4)
     *
     * Wire construction:
     * - Label1: 63 bytes ("a"*63)
     * - Label2: 63 bytes ("b"*63)
     * - Label3: 63 bytes ("c"*63)
     * - Label4: pointer to Label1 (offset 12)
     *
     * Wire length < 255 bytes (valid), but expansion repeats Label1+Label2+Label3
     * and exceeds 255 bytes → parser must reject.
     *
     * Expected behavior:
     * - sdns_from_wire() must fail
     * - No partial name should be returned
     * - No memory overflow
     */
    char packet_bytes[] = {
        /* ================= DNS HEADER ================= */
        0xbe, 0xf4,             /* ID = 0xbef4 = 48884 */
        0x01, 0x00,             /* Flags: RD */
        0x00, 0x01,             /* QDCOUNT = 1 */
        0x00, 0x00,             /* ANCOUNT = 0 */
        0x00, 0x00,             /* NSCOUNT = 0 */
        0x00, 0x00,             /* ARCOUNT = 0 */

        /* ================= QUESTION ================= */
        /* Label 1: 63 bytes */
        0x3f,
        'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',
        'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',

        /* Label 2: 63 bytes */
        0x3f,
        'b','b','b','b','b','b','b','b','b','b','b','b','b','b','b','b',
        'b','b','b','b','b','b','b','b','b','b','b','b','b','b','b','b',
        'b','b','b','b','b','b','b','b','b','b','b','b','b','b','b','b',
        'b','b','b','b','b','b','b','b','b','b','b','b','b','b','b',

        /* Label 3: 63 bytes */
        0x3f,
        'c','c','c','c','c','c','c','c','c','c','c','c','c','c','c','c',
        'c','c','c','c','c','c','c','c','c','c','c','c','c','c','c','c',
        'c','c','c','c','c','c','c','c','c','c','c','c','c','c','c','c',
        'c','c','c','c','c','c','c','c','c','c','c','c','c','c','c',

        /* Label 4: pointer to Label1 (offset 12) */
        0xc0, 0x0c,             /* pointer → Label1 again */

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
