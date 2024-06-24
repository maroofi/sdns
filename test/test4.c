#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdns.h>
#include <sdns_utils.h>
#include <sdns_print.h>
#include <sdns_json.h>
#include <time.h>
#include <assert.h>
/*
 * compile: cd .. && make with-json && cd test && gcc -o test test4.c -I../include -L../bin -lsdns -ljansson && ./test
 * this example must be able to create a packet with NSID in edns0 and send.
 */


int main(int argc, char ** argv){
    srand(time(NULL));
    sdns_context * dns_ctx = sdns_init_context();
    if (NULL == dns_ctx){
        fprintf(stderr, "Can not initialize the DNS context...\n");
        return 1;
    }
    int res = 0;
    // we create a edns0-aware packet and then add NSID
    res = sdns_make_query(dns_ctx, sdns_rr_type_A, sdns_q_class_IN, strdup("google.com."), 1);
    assert(res == 0);
    
    // now add NSID. It should overwrite the first one
    sdns_opt_rdata * opt_nsid = sdns_create_edns0_nsid();
    assert(opt_nsid != NULL);

    // add it to the packet
    res = sdns_add_edns(dns_ctx, opt_nsid);
    assert(res == 0);

    res = sdns_to_wire(dns_ctx);
    assert(res == 0);
    
    hex_dump(dns_ctx->raw, 0, dns_ctx->raw_len);

    sdns_context *second = sdns_init_context();
    assert(second != NULL);

    second->raw = dns_ctx->raw;
    second->raw_len = dns_ctx->raw_len;

    res = sdns_from_wire(second);
    assert(res == 0);

    sdns_neat_print_dns(second);
    
    second->raw = NULL;
    char * tmp = sdns_json_dns_string(second);
    fprintf(stdout, "%s\n", tmp);
    free(tmp);
    sdns_free_context(second);
    sdns_free_context(dns_ctx);
    
    return 0;
}
