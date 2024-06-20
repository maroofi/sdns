#include "sdns.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
 
int main(){
    sdns_context * dnsctx = sdns_init_context();
    if (NULL == dnsctx){    // we are done as we can create the context
        fprintf(stderr, "Can not create a DNS context\n");
        return 1;
    }
    char * qname = strdup("google.com");
    int res = sdns_make_query(dnsctx, sdns_rr_type_A, sdns_q_class_IN, qname, 0);
    if (res != 0){  
        // sdns_make_query() failed. The return value can tell us why.
        // we have to call sdns_error_string() with 'res' to know the reason.
        fprintf(stderr, "Can not create the query packet\n");
        sdns_free_context(dnsctx);
        return 1;
    }
    // we are done. Now if we want to get the binary data to send it over the socket
    // we have to call sdns_to_wire() function.
    res = sdns_to_wire(dnsctx);
    if (res != 0){
        fprintf(stderr, "Can not covert to binary data\n");
        sdns_free_context(dnsctx);
        return 1;
    }
    // let's print the hex presentation of the data
    fprintf(stdout, "Raw data ready for the socket:\n");
    for (int i=0; i < dnsctx->raw_len; ++i){
        fprintf(stdout, "%02x ", (unsigned char)dnsctx->raw[i]);
    }
    fprintf(stdout, "\n");
    // let's free the context and we are done
    sdns_free_context(dnsctx);
    return 0;
}
