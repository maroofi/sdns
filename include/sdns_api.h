/** @file */

#include <sdns.h>

// mostly high-level functions to do basic stuff, each to check and easy to code wrappers!

#ifndef SDNS_API_H
#define SDNS_API_H


/**
 * @brief Converts the received binary data from the socket to a DNS packet
 * @param buff A pointer to the buffer we received the data from socket
 * @param buff_len an unsigned 16-bit integer showing the size of the buffer
 * 
 * This function is a simple wrapper over sdns_from_wire() function. You can directly
 * use that function but then you need to create and free the context by yourself.
 *
 * This function will handle some of the nasty parts!
 * You can free() the buffer after calling this method. This function will copy the buffer
 * internally so it's safe to free the provided buffer.
 *
 * @return A pointer to ::sdns_context structure on success or NULL on fail
 */
sdns_context * sdns_from_network(char * buff, uint16_t buff_len);


/**
 * @brief Converts the dns packet to the binary form ready to be sent by the socket
 * @param dns a pointer to the ::sdns_context created by sdns_init_context() 
 * @param err A pointer to the variable which receives the error code of the operation.
 * @param buff_len a pointer to a 16bit unsigned integer which will receive the size of the returned buffer.
 *
 * If the operation is successful, the value of the 'err' will be zero and 'buff_len' will be size of the returned buffer.
 *
 * @return a pointer to the network-ready data on success and NULL on fail.
 */
char * sdns_to_network(sdns_context * dns, int * err, uint16_t * buff_len);


/**
 * @brief Adds an A record to the dns context in the answer section.
 * @param dns A pointer to the dns context created by sdns_init_context()
 * @param name the domain name we want to assign an A record to.
 * @param ttl the time to live of the A record
 * param ip the string representation of the IPv4 (e.g., 1.2.3.4)
 *
 * This function is just a wrapper for several functions to make it easy to create an A record.
 *
 * Free the memory of 'name' param since the function creates an internal copy.
 * Free the memory of 'ip' param if needed since the function won't use it.
 *
 * @return 0 on success other values on fail.
 */
int sdns_add_rr_answer_A(sdns_context * dns, char * name, uint32_t ttl, char * ip);

/**
 * @brief Adds A record to the additional section of the DNS packet.
 *
 * Check the documentation of sdns_add_rr_answer_A()
 */
int sdns_add_rr_additional_A(sdns_context * dns, char * name, uint32_t ttl, char * ip);


/**
 * @brief Adds A record to the authority section of the DNS packet.
 *
 * Check the documentation of sdns_add_rr_answer_A()
 */
int sdns_add_rr_authority_A(sdns_context * dns, char * name, uint32_t ttl, char * ip);


/**
 * @brief Adds a NS record to the dns context in the answer section.
 * @param dns A pointer to the dns context created by sdns_init_context()
 * @param name the domain name we want to assign the NS record to.
 * @param ttl the time to live of the NS record
 * param nsname the string representation of the nameserver (e.g., ns1.google.com))
 *
 * This function is just a wrapper for several functions to make it easy to create an A record.
 *
 * @return 0 on success other values on fail.
 */
int sdns_add_rr_answer_NS(sdns_context * dns, char * name, uint32_t ttl, char * nsname);


/**
 * @brief Adds NS record to the additional section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_NS()
 */
int sdns_add_rr_additional_NS(sdns_context * dns, char * name, uint32_t ttl, char * nsname);


/**
 * @brief Adds NS record to the authority section of the DNS packet.
 *
 * Check the documentation of sdns_add_rr_answer_NS()
 */
int sdns_add_rr_authority_NS(sdns_context * dns, char * name, uint32_t ttl, char * nsname);


/**
 * @brief Adds a new TXT record to the DNS packet in answer section.
 * @param dns A pointer to the dns context created by sdns_init_context()
 * @param name the domain name we want to assign the NS record to.
 * @param ttl the time to live of the NS record
 * @param text A pointer to the TXT record you want to add
 * @param text_len a 16bit unsigned integer showing the length of the 'text' value.
 *
 * TXT records can be non-null terminated strings. That's why we have to specify the text_len param.
 * You can free the 'text' param after calling the method as we copy it internally.
 *
 * @return 0 on success, other values for errors
 */
int sdns_add_rr_answer_TXT(sdns_context * dns, char * name, uint32_t ttl, char * text, uint16_t text_len);


/**
 * @brief Adds TXT record to the authority section of the DNS packet.
 *
 * Check the documentation of sdns_add_rr_answer_TXT()
 */
int sdns_add_rr_authority_TXT(sdns_context * dns, char * name, uint32_t ttl, char * text, uint16_t text_len);

/**
 * @brief Adds TXT record to the additional section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_TXT()
 */
int sdns_add_rr_additional_TXT(sdns_context * dns, char * name, uint32_t ttl, char * text, uint16_t text_len);


/**
 * @brief Creates a dns context with the given query and ends0 enabled.
 * @param name the domain name we want to query
 * @param type the type string in a form of "A", "AAAA", ...
 * @param cls the class of query in a form of "IN", "ch"
 * 
 * 
 * All the parameters are copied internally. The caller can free them after calling the method (if it's necessary).
 *
 * @return a pointer to a newly created context on success or NULL on fail
 */
sdns_context * sdns_create_query(char * name, char * type, char * cls);

/**
 * @brief Adds a new SOA record to the DNS packet in answer section.
 * @param dns A pointer to the DNS context.
 * @param name a pointer to the domain name of the section
 * @param ttl the 32bit TTL of the section
 * @param mname primary name server
 * @param rname mailbox of the responsible person
 * @param expire upper bound limit of the authorative zone
 * @param minimum minimum TTL field.
 * @param refresh Interval before zone should be refreshed
 * @param retry Interval before failed refresh should be retried
 * @param serial Version number of the origianl copy of the zone
 *
 * All the parameters that are "char*" will be copied internally so the caller can free them after this function.
 * @return 0 on success other values on failure.
 */
int sdns_add_rr_answer_SOA(sdns_context * dns, char * name, uint32_t ttl,  char * mname, char * rname,
                           uint32_t expire, uint32_t minimum, uint32_t refresh, uint32_t retry, uint32_t serial);



/**
 * @brief Adds SOA record to the authority section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_SOA()
 */
int sdns_add_rr_authority_SOA(sdns_context * dns, char * name, uint32_t ttl,  char * mname, char * rname,
                           uint32_t expire, uint32_t minimum, uint32_t refresh, uint32_t retry, uint32_t serial);

/**
 * @brief Adds SOA record to the additional section of the DNS record.
 *
 * Check the documentation of sdns_add_rr_answer_SOA()
 */
int sdns_add_rr_additional_SOA(sdns_context * dns, char * name, uint32_t ttl,  char * mname, char * rname,
                           uint32_t expire, uint32_t minimum, uint32_t refresh, uint32_t retry, uint32_t serial);

/**
 * @brief Adds a CNAME record to the answer section of the DNS context
 * @param dns a pointer to the DNS context
 * @param name name of the section
 * @param ttl TTL value of the seciton
 * @param cname The canonical name
 * 
 * The caller can free 'cname' param if it's necessary as the function copies the value internally.
 *
 * @return 0 on success other values on fail.
 */
int sdns_add_rr_answer_CNAME(sdns_context * dns, char * name, uint32_t ttl, char * cname);


/**
 * @brief Adds CNAME record to the authority section of the DNS record.
 *
 * Check the documentation of sdns_add_rr_answer_CNAME()
 */
int sdns_add_rr_authority_CNAME(sdns_context * dns, char * name, uint32_t ttl, char * cname);


/**
 * Check the documentation of sdns_add_rr_answer_CNAME()
 */
int sdns_add_rr_additional_CNAME(sdns_context * dns, char * name, uint32_t ttl, char * cname);


/**
 * @brief Adds a MX record to the answer section of the DNS context
 * @param dns a pointer to the DNS context
 * @param name name of the section
 * @param ttl TTL value of the seciton
 * @param preference 16-bit preference value of the MX record
 * @param exchange a pointer to the exchange value of the MX record
 * 
 * The caller can free 'exchange' param if it's necessary as the function copies the value internally.
 *
 * @return 0 on success other values on fail.
 */
int sdns_add_rr_answer_MX(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * exchange);


/**
 * @brief Adds MX record to the additional section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_MX()
 */
int sdns_add_rr_additional_MX(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * exchange);


/**
 * @brief Adds MX record to the authority section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_MX()
 */
int sdns_add_rr_authority_MX(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * exchange);


/**
 * @brief Adds a PTR record to the answer section of the DNS context
 * @param dns a pointer to the DNS context
 * @param name name of the section
 * @param ttl TTL value of the seciton
 * @param ptrdname a pointer to the domain-name value of the PTR record
 * 
 * The caller can free 'ptrdname' param if it's necessary as the function copies the value internally.
 *
 * @return 0 on success other values on fail.
 */
int sdns_add_rr_answer_PTR(sdns_context * dns, char * name, uint32_t ttl, char * ptrdname);


/**
 * @brief Adds PTR record to the authority section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_PTR()
 */
int sdns_add_rr_authority_PTR(sdns_context * dns, char * name, uint32_t ttl, char * ptrdname);

/**
 * @brief Adds PTR record to the additional section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_PTR()
 */
int sdns_add_rr_additional_PTR(sdns_context * dns, char * name, uint32_t ttl, char * ptrdname);


/**
 * @brief Adds a SRV record to the answer section of the DNS context
 * @param dns a pointer to the DNS context
 * @param name name of the section
 * @param ttl TTL value of the seciton
 * @param priority Priority value of the SRV record
 * @param weight Weight value of the SRV record
 * @param port Port of the SRV record
 * @param target Target anme of the SRV record
 * 
 * The caller can free 'target' param if it's necessary since the function copies the value internally.
 *
 * @return 0 on success other values on fail.
 */
int sdns_add_rr_answer_SRV(sdns_context * dns, char * name, uint32_t ttl, 
                           uint16_t priority, uint16_t weight, uint16_t port, char * target);

/**
 * @brief Adds a SRV record to the authority section of the DNS packet.
 *
 * Check the documentation of sdns_add_rr_answer_SRV()
 */
int sdns_add_rr_authority_SRV(sdns_context * dns, char * name, uint32_t ttl, 
                           uint16_t priority, uint16_t weight, uint16_t port, char * target);

/**
 * @brief Add a SRV record to the additional section of the DNS packet.
 *
 * Check the documentation of sdns_add_rr_answer_SRV()
 */
int sdns_add_rr_additional_SRV(sdns_context * dns, char * name, uint32_t ttl, 
                           uint16_t priority, uint16_t weight, uint16_t port, char * target);


int sdns_add_rr_answer_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                             char * os, uint8_t os_len, char * cpu, uint8_t cpu_len);


int sdns_add_rr_authority_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                             char * os, uint8_t os_len, char * cpu, uint8_t cpu_len);


int sdns_add_rr_additional_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                             char * os, uint8_t os_len, char * cpu, uint8_t cpu_len);




/**
 * @brief Adds cookie to DNS packet. 
 * @param client_cookie (mandatory, not NULL) - nul-terminated hex representation of the client cookie
 * @param server_cooke (optional, can be NULL) - nul-terminated hex representation of the server cookie or NULL
 *
 * Client cookie must be present and a C-string in a form of hex. It's exactly 8 bytes and its hex representation will be 16 bytes.
 * 
 * For example:  char client_cookie[] = "AABBCCDDEEFF0011";
 *
 * Server cookie is optional and can be NULL. However, in case of presence, it will be exactly the same format as client cookie
 * and the length can be between 8 to 32 (included).
 *
 * For example, both of the following calls are valid:
 *
 * <pre>int res = sdns_add_cookie(dns, "AABBCCDDEEFF6600", NULL);</pre>
 *
 * <pre>int res = sdns_add_cookie(dns, "1122334455667788", "AABBCC11224455667788")</pre>
 *
 *
 * @return 0 on success, other values on failure.
 */
int sdns_add_cookie(sdns_context * dns, char * client_cookie, char * server_cookie);

/**
 * @brief Adds NSID to the DNS packet.
 * @param nsid a pointer to the hex repsentation of the NSID value or NULL
 *
 * if 'nsid' param is NULL, then the packet will have and empty NSID in ends0. This makes it suitable for 
 * client packets to ask the NSID of the server.
 *
 * if 'nsid' param is not NULL, it must be the hex represantation of the NSID value (A null-terminated C string).
 * 
 * For example:
 *
 * 1. Creating a DNS packet asking for A record of a domain name and enabling NSID.
 *
 * <pre>int res = sdns_add_nsid(dns, NULL);</pre>
 *
 * 2. Creating a packet to send to client with a NSID.
 *
 * <pre>int res = sdns_add_nsid(dns, "AABBCCDD");
 *
 * @return 0 on success, other values on fail
 */
int sdns_add_nsid(sdns_context * dns, char * nsid);

/**
 * @brief Add extended DNS error to the packet
 * @param dns sdns context returned by sdns_init_context(), sdns_create_query() or sdns_from_network()
 * @param ede_code 16-bit unsigned integer for EDE info code field
 * @param ede_text nul-terminated C string for the text description of EDE or NULL
 *
 * The API calculates the length of the 'ede_text' using strlen() function. This means that it must
 * be null-terminated and can not have null character in it. The caller can free the 'ede_text' (if it's necessary)
 * since the library copies the value internally.
 *
 * 'ede_text' is not mandatory in DNS, so you can just pass NULL if you don't want to have a description.
 *
 * @return 0 on success or an appropriate error code
 */
int sdns_add_ede(sdns_context * dns, uint16_t ede_code, char * ede_text);


/**
 * @brief Sets or resets DNSSEC OK bit in EDNS0 part of the DNS packet.
 * @param dns DNS context
 * @param do_bit it can be 0 or 1 to set or reset the DO bit.
 *
 * Before using this function, you need to make sure your DNS packet is edns0 aware.
 * If the packet is not edns0-aware, and you call this function, it returns '1'
 * which means failed to find the edns0 part in the additional section.
 *
 * @return 0 on success, 1 on fail.
 */
int sdns_set_do(sdns_context * dns, uint8_t do_bit);


/**
 * @brief Sets or resets the truncation bit of the DNS header
 * @param dns sdns context
 * @prarm tc_bit can be 0 or 1 to set or reset the TC bit.
 *
 * @param always returns 0
 */
int sdns_set_tc(sdns_context * dns, uint8_t tc_bit);


/**
 * @brief Sets the ID of the DNS header
 * @param dns sdns context created by sdns_init_context() or sdns_from_network() or sdns_create_query() functions.
 * @param dns_id 16bit unsigned ID value.
 *
 * @return always returns 0
 */
int sdns_set_id(sdns_context * dns, uint16_t dns_id);


/**
 * @brief Sets or resets the _recursion desired_ bit of the DNS header
 * @param dns sdns context
 * @prarm rd_bit can be 0 or 1 to set or reset the RD bit.
 *
 * @param always returns 0
 */
int sdns_set_rd(sdns_context * dns, uint8_t rd_bit);


/**
 * @brief Sets or resets the _recursion available_ bit of the DNS header
 * @param dns sdns context
 * @prarm ra_bit can be 0 or 1 to set or reset the RA bit.
 *
 * @param always returns 0
 */
int sdns_set_ra(sdns_context * dns, uint8_t ra_bit);



/**
 * @brief Sets or resets the _athoritative answer_ bit of the DNS header
 * @param dns sdns context
 * @prarm aa_bit can be 0 or 1 to set or reset the AA bit.
 *
 * @param always returns 0
 */
int sdns_set_aa(sdns_context * dns, uint8_t aa_bit);


/**
 * @brief Sets or resets the _check disabled_ bit of the DNS header
 * @param dns sdns context
 * @prarm cd_bit can be 0 or 1 to set or reset the CD bit.
 *
 * @param always returns 0
 */
int sdns_set_cd(sdns_context * dns, uint8_t cd_bit);




/**
 * @brief Get NSID value from the DNS context
 * @param dns Pointer to ::sdns_context
 * @param err Pointer to the memory address that receives the error code
 * @param nsid_len A pointer to the memory address that receives the length of the NSID
 *
 * The returned result must be freed by the caller.
 * In case the packet does not contain any NSID value, the returned value is NULL and err shows
 * the appropriate error code.
 *
 * The NSID can contain NULL character in it. That's why you should not treat the returned pointer
 * as a nul-terminated string but you should use the 'nsid_len' to read the returned memory.
 *
 * We can only call this method after calling sdns_from_network() when the DNS packet already decoded successfully.
 *
 * @return A pointer to the memory the NSID is stored or NULL in case of error
 */
char * sdns_get_value_nsid(sdns_context * dns, int * err, uint16_t *nsid_len);


/**
 * @brief Returns the client cookie of the packet (if there is any)
 * @param dns pointer to ::sdns_context
 * @param Pointer to the memory address that receives the error code
 *
 * The retured result is a pointer to the client cookie which must be freed by the caller.
 * In case the packet does not contain any cookie, the returned value is NULL and err contains
 * the appropriate error code.
 *
 * We can only call this method after calling sdns_from_network() (when the DNS packet is already decoded).
 *
 * Note: Client cookie length is always 8 bytes. So if the return pointer is not NULL, you should exactly 
 * read 8 bytes from it.
 *
 * @return A pointer to the memory the client cookie is stored or NULL in case of error.
 */
char * sdns_get_value_cookie_client(sdns_context * dns, int * err);





#endif
