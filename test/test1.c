#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdns.h>
#include <sdns_print.h>
#include <sdns_json.h>
#include <time.h>
#include <assert.h>

/**
 * This packet has been generated using: dig +noedns +nocookie A yahoo.com @1.1.1.1
 * and the dig output is:
 * ; <<>> DiG 9.18.24-0ubuntu5-Ubuntu <<>> +noedns +nocookie A yahoo.com @1.1.1.1
 * ;; global options: +cmd
 * ;; Got answer:
 * ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32630
 * ;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 0
 * 
 * ;; QUESTION SECTION:
 * ;yahoo.com.			IN	A
 * 
 * ;; ANSWER SECTION:
 * yahoo.com.		1751	IN	A	74.6.231.21
 * yahoo.com.		1751	IN	A	98.137.11.164
 * yahoo.com.		1751	IN	A	74.6.143.26
 * yahoo.com.		1751	IN	A	74.6.143.25
 * yahoo.com.		1751	IN	A	98.137.11.163
 * yahoo.com.		1751	IN	A	74.6.231.20
 *
 * Wireshark output:
 * Domain Name System (response)
 *    Transaction ID: 0x7f76
 *    Flags: 0x8180 Standard query response, No error
 *        1... .... .... .... = Response: Message is a response
 *        .000 0... .... .... = Opcode: Standard query (0)
 *        .... .0.. .... .... = Authoritative: Server is not an authority for domain
 *        .... ..0. .... .... = Truncated: Message is not truncated
 *        .... ...1 .... .... = Recursion desired: Do query recursively
 *        .... .... 1... .... = Recursion available: Server can do recursive queries
 *        .... .... .0.. .... = Z: reserved (0)
 *        .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
 *        .... .... ...0 .... = Non-authenticated data: Unacceptable
 *        .... .... .... 0000 = Reply code: No error (0)
 *    Questions: 1
 *    Answer RRs: 6
 *    Authority RRs: 0
 *    Additional RRs: 0
 *    Queries
 *        yahoo.com: type A, class IN
 *            Name: yahoo.com
 *            [Name Length: 9]
 *            [Label Count: 2]
 *            Type: A (1) (Host Address)
 *            Class: IN (0x0001)
 *    Answers
 *        yahoo.com: type A, class IN, addr 74.6.231.21
 *            Name: yahoo.com
 *            Type: A (1) (Host Address)
 *            Class: IN (0x0001)
 *            Time to live: 1751 (29 minutes, 11 seconds)
 *            Data length: 4
 *            Address: 74.6.231.21
 *        yahoo.com: type A, class IN, addr 98.137.11.164
 *            Name: yahoo.com
 *            Type: A (1) (Host Address)
 *            Class: IN (0x0001)
 *            Time to live: 1751 (29 minutes, 11 seconds)
 *            Data length: 4
 *            Address: 98.137.11.164
 *        yahoo.com: type A, class IN, addr 74.6.143.26
 *            Name: yahoo.com
 *            Type: A (1) (Host Address)
 *            Class: IN (0x0001)
 *            Time to live: 1751 (29 minutes, 11 seconds)
 *            Data length: 4
 *            Address: 74.6.143.26
 *        yahoo.com: type A, class IN, addr 74.6.143.25
 *            Name: yahoo.com
 *            Type: A (1) (Host Address)
 *            Class: IN (0x0001)
 *            Time to live: 1751 (29 minutes, 11 seconds)
 *            Data length: 4
 *            Address: 74.6.143.25
 *        yahoo.com: type A, class IN, addr 98.137.11.163
 *            Name: yahoo.com
 *            Type: A (1) (Host Address)
 *            Class: IN (0x0001)
 *            Time to live: 1751 (29 minutes, 11 seconds)
 *            Data length: 4
 *            Address: 98.137.11.163
 *        yahoo.com: type A, class IN, addr 74.6.231.20
 *            Name: yahoo.com
 *            Type: A (1) (Host Address)
 *            Class: IN (0x0001)
 *            Time to live: 1751 (29 minutes, 11 seconds)
 *            Data length: 4
 *            Address: 74.6.231.20
 *    [Request In: 152]
 *    [Time: 0.023642522 seconds]
 *
 */

int main(int argc, char ** argv){
    srand(time(NULL));
    sdns_context * dns_ctx = sdns_init_context();
    if (NULL == dns_ctx){
        fprintf(stderr, "Can not initialize the DNS context...\n");
        return 1;
    }
    char packet_bytes[] = {
      0x7f, 0x76, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06,
      0x00, 0x00, 0x00, 0x00, 0x05, 0x79, 0x61, 0x68,
      0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
      0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x06, 0xd7, 0x00, 0x04, 0x4a,
      0x06, 0xe7, 0x15, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x06, 0xd7, 0x00, 0x04, 0x62,
      0x89, 0x0b, 0xa4, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x06, 0xd7, 0x00, 0x04, 0x4a,
      0x06, 0x8f, 0x1a, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x06, 0xd7, 0x00, 0x04, 0x4a,
      0x06, 0x8f, 0x19, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x06, 0xd7, 0x00, 0x04, 0x62,
      0x89, 0x0b, 0xa3, 0xc0, 0x0c, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x06, 0xd7, 0x00, 0x04, 0x4a,
      0x06, 0xe7, 0x14
    };
   
    dns_ctx->raw = packet_bytes;
    dns_ctx->raw_len = sizeof(packet_bytes);
    int res = sdns_from_wire(dns_ctx);
    assert(res == 0);
    char *dmp = sdns_json_dns_string(dns_ctx);
    fprintf(stdout, "%s\n", dmp);
    free(dmp);
    dns_ctx->raw = NULL;
    sdns_free_context(dns_ctx);
    return 0;
}
