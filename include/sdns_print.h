/** @file */
#include "sdns.h"


#ifndef NEAT_PRINT_H
#define NEAT_PRINT_H


/**
 * @brief Prints a DNS packet in a human-readable format (like Dig)
 * @param ctx A pointer to the DNS context created by sdns_init_context()
 *
 * This function and in general all the family of **sdns_neat_print_*()** are very
 * handy in printing the information of a DNS packet.
 */
void sdns_neat_print_dns(sdns_context * ctx);

/** Prints only the header part of a DNS packet */
void sdns_neat_print_header(sdns_context *);

/** Prints a resource record based on its type */
void sdns_neat_print_rr(sdns_context *, sdns_rr *);

/** Prints A resource record */
void sdns_neat_print_rr_A(sdns_context *, sdns_rr *);

/** Prints AAAA resource record */
void sdns_neat_print_rr_AAAA(sdns_context *, sdns_rr *);


/** Prints TXT resource record */
void sdns_neat_print_rr_TXT(sdns_context *, sdns_rr *);

/** Prints SOA resource record */
void sdns_neat_print_rr_SOA(sdns_context *, sdns_rr *);


/** Prints A resource record */
void sdns_neat_print_rr_MX(sdns_context *, sdns_rr *);


/** Prints OPT resource record */
void sdns_neat_print_rr_OPT(sdns_context *, sdns_rr *);


/** Prints NS resource record */
void sdns_neat_print_rr_NS(sdns_context *, sdns_rr *);


/** Prints PTR resource record */
void sdns_neat_print_rr_PTR(sdns_context *, sdns_rr *);


/** Prints CNAME resource record */
void sdns_neat_print_rr_CNAME(sdns_context *, sdns_rr *);


/** Prints RRSIG resource record */
void sdns_neat_print_rr_RRSIG(sdns_context * ctx, sdns_rr * rr);

/** Prints SRV resource record */
void sdns_neat_print_rr_SRV(sdns_context * ctx, sdns_rr * rr);

/** Prints URI resource record */
void sdns_neat_print_rr_URI(sdns_context * ctx, sdns_rr * rr);

/** Prints NID resource record */
void sdns_neat_print_rr_NID(sdns_context * ctx, sdns_rr * rr);


/** Prints L32 resource record */
void sdns_neat_print_rr_L32(sdns_context * ctx, sdns_rr * rr);

/** Prints L64 resource record */
void sdns_neat_print_rr_L64(sdns_context * ctx, sdns_rr * rr);

/** Prints LP resource record */
void sdns_neat_print_rr_LP(sdns_context * ctx, sdns_rr * rr);

/** prints CAA resource record */
void sdns_neat_print_rr_CAA(sdns_context * ctx, sdns_rr * rr);

/** Prints HINFO resource record */
void sdns_neat_print_rr_HINFO(sdns_context * ctx, sdns_rr * rr);


/** Prints the question section of a DNS packet */
void sdns_neat_print_question(sdns_context * ctx);


/** Prints a RR without knowing its type in hex format */
void sdns_neat_print_rr_section(sdns_context *, sdns_rr *);

#endif
