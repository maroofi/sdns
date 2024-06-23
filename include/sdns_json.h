#include <jansson.h>
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sdns.h>
#ifndef SDNS_JSON_H
#define SDNS_JSON_H

char * sdns_json_dns_string(sdns_context * ctx);
json_t* sdns_json_header(sdns_context * ctx);
json_t * sdns_json_question(sdns_context * ctx);
json_t * sdns_json_dns(sdns_context*ctx);
json_t * sdns_json_answer(sdns_context * ctx);

json_t * sdns_json_authority(sdns_context * ctx);
json_t * sdns_json_additional(sdns_context * ctx);

json_t * sdns_json_rr(sdns_context * ctx, sdns_rr * rr);

json_t * sdns_json_rr_A(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_AAAA(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_MX(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_NID(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_L32(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_L64(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_LP(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_SOA(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_NS(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_TXT(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_PTR(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_HINFO(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_SRV(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_URI(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_CNAME(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_OPT(sdns_context * ctx, sdns_rr *rr);
json_t * sdns_json_rr_RRSIG(sdns_context * ctx, sdns_rr *rr);









#endif
