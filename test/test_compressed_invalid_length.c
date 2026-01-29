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
    /* Invalid packet: compressed name expands to >255 bytes (must fail)
     *
     * ID = 48882 (0xbef2)
     *
     * This packet tests DNS compression expansion limits:
     *
     * - Wire on the network: perfectly valid length (≤255)
     * - Expansion using pointers exceeds 255 bytes → must fail
     *
     * Construction:
     * - Label1 = 63 bytes ("a"*63)
     * - Label2 = 63 bytes ("b"*63)
     * - Label3 = 63 bytes ("c"*63)
     * - Label4 = pointer to offset 12 (start of Label1)
     *
     * Wire length < 255 bytes, but expansion of pointer creates >255-byte name.
     *
     * Expected: parser MUST reject the packet during expansion.
     */
    char packet_bytes[] = {
        /* ================= DNS HEADER ================= */
        0xbe, 0xf2,             /* ID = 0xbef2 = 48882 */
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

        /* Label 4: pointer to offset 12 (start of Label1) */
        0xc0, 0x0c,             /* compression pointer → Label1 */

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
