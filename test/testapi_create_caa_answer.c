#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdns.h>
#include <sdns_print.h>
#include <sdns_json.h>
#include <sdns_api.h>
#include <sdns_utils.h>
#include <time.h>
#include <assert.h>

// this test creates a packet with CAA record
// encode it and decode it to get the result
// compile with:
// gcc -g -Werror test_create_caa_answer.c ../src/sdns.c ../src/sdns_dynamic_buffer.c ../src/sdns_utils.c  ../src/sdns_json.c -I. -I../include -o test && valgrind -s --leak-check=full ./test
int main(int argc, char ** argv){
    srand(time(NULL));
    sdns_context * dns = sdns_create_query("fakedomain.fake", "CAA", "IN");
    assert(dns);
    int res;
    res = sdns_add_rr_answer_CAA(dns, "fakedomain.fake", 3600, 1, "issuewild", "google.com");
    assert(res == 0);
    int error;
    uint16_t buf_len;
    char * data = sdns_to_network(dns, &error, &buf_len);
    sdns_free_context(dns);
    dns = NULL;
    assert(error == 0);
    assert(buf_len != 0);
    // now convert it back to dns packet
    dns = sdns_from_network(data, buf_len);
    assert(dns != NULL);
    sdns_rr_CAA * caa = sdns_decode_rr_CAA(dns, dns->msg->answer);
    assert(caa != NULL);
    assert(caa->flag == 1);
    assert(caa->tag_len == 9);
    assert(caa->value_len == 10);
    assert(strncmp(caa->tag, "issuewild", caa->tag_len) == 0);
    assert(strncmp(caa->value, "google.com", caa->value_len) == 0);
    sdns_free_rr_CAA(caa);
    free(data);
    sdns_free_context(dns);
    fprintf(stdout, "success\n");
    return 0;
}
