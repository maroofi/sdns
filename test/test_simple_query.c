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
    // This simple query must successfully parsed by the parser
    char packet_bytes[] = {
        0x12, 0x34,             /* ID */
        0x01, 0x00,             /* RD */
        0x00, 0x01,             /* QDCOUNT */
        0x00, 0x00,             /* ANCOUNT */
        0x00, 0x00,             /* NSCOUNT */
        0x00, 0x00,             /* ARCOUNT */
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00,
        0x00, 0x01,             /* A */
        0x00, 0x01              /* IN */
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
