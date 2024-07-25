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
 * @param ip the string representation of the IPv4 (e.g., 1.2.3.4)
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
 * @param nsname the string representation of the nameserver (e.g., ns1.google.com))
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



/**
 * @brief Adds a HINFO record to the answer section of the DNS context
 * @param dns a pointer to the DNS context
 * @param name name of the section
 * @param ttl TTL value of the seciton
 * @param os Pointer to the OS name
 * @param os_len 8bit length of the OS string
 * @param cpu Pointer to the CPU label
 * @param cpu_len 8bit length of the CPU string
 *
 * 
 * The caller can free 'cpu' and 'os' params if it's necessary since the function copies the value internally.
 *
 * 'cpu' and 'os' string are not necessarily nul-terminated. That's why the length of both must be provided.
 *
 * @return 0 on success other values on fail.
 */
int sdns_add_rr_answer_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                             char * os, uint8_t os_len, char * cpu, uint8_t cpu_len);


/**
 * @brief Add a HINFO record to the authority section of the DNS packet.
 *
 * Check the documentation of sdns_add_rr_answer_HINFO()
 */
int sdns_add_rr_authority_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                             char * os, uint8_t os_len, char * cpu, uint8_t cpu_len);


/**
 * @brief Add a HINFO record to the additional section of the DNS packet.
 *
 * Check the documentation of sdns_add_rr_answer_HINFO()
 */
int sdns_add_rr_additional_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                             char * os, uint8_t os_len, char * cpu, uint8_t cpu_len);



/**
 * @brief Adds cookie to DNS packet. 
 * @param dns pointer to ::sdns_context
 * @param client_cookie (mandatory, not NULL) - nul-terminated hex representation of the client cookie
 * @param server_cookie (optional, can be NULL) - nul-terminated hex representation of the server cookie or NULL
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
 * @param dns ::sdns_context 
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
 * <pre>int res = sdns_add_nsid(dns, "AABBCCDD");</pre>
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
 * @brief Sets the rcode of the DNS context.
 * @param dns DNS context
 * @param rcode the value to set in the DNS context header as the 'rcode'
 *
 * 'rcode' can be between 0 (included) and 16 (excluded).
 * Any value that is not in this range will result in returning ::SDNS_ERROR_WRONG_INPUT_PARAMETER
 *
 * @return 0 on success, other values on fail
 */
int sdns_set_rcode(sdns_context * dns, uint8_t rcode);



/**
 * @brief Sets or resets the _query-response_ bit of the DNS header
 * @param dns sdns context
 * @param qr_bit can be 0 or 1 to set or reset the QR bit.
 *
 * @return always returns 0
 */
int sdns_set_qr(sdns_context * dns, uint8_t qr_bit);

/**
 * @brief Sets or resets the truncation bit of the DNS header
 * @param dns sdns context
 * @param tc_bit can be 0 or 1 to set or reset the TC bit.
 *
 * @return always returns 0
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
 * @param rd_bit can be 0 or 1 to set or reset the RD bit.
 *
 * @return always returns 0
 */
int sdns_set_rd(sdns_context * dns, uint8_t rd_bit);


/**
 * @brief Sets or resets the _recursion available_ bit of the DNS header
 * @param dns sdns context
 * @param ra_bit can be 0 or 1 to set or reset the RA bit.
 *
 * @return always returns 0
 */
int sdns_set_ra(sdns_context * dns, uint8_t ra_bit);



/**
 * @brief Sets or resets the _athoritative answer_ bit of the DNS header
 * @param dns sdns context
 * @param aa_bit can be 0 or 1 to set or reset the AA bit.
 *
 * @return always returns 0
 */
int sdns_set_aa(sdns_context * dns, uint8_t aa_bit);


/**
 * @brief Sets or resets the _check disabled_ bit of the DNS header
 * @param dns sdns context
 * @param cd_bit can be 0 or 1 to set or reset the CD bit.
 *
 * @return always returns 0
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
 * @param err Pointer to the memory address that receives the error code
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


/**
 * @brief Revemos EDNS0 option from a DNS context
 * @param dns the DNS context created by sdns_init_context()
 * 
 * By default, create_query() function adds EDNS0 option to the additional section
 * of the DNS context. If you don't want it, you can remove it using this function.
 * @return 0 on success, other values on failure
*/
int sdns_remove_edns(sdns_context * dns);

/**
 * @brief Returns the answer section of the dns context
 * @param dns the DNS context created by sdns_init_context()
 * @param err A pointer to the place that receives the error/success code of calling this function
 * @param num number of the answer starts from zero.
 * 
 * 'num' parameter is the number of the answer in the DNS packet or DNS context. For example if a DNS packet
 * returns 2 A records in the answer section, the first on is num=0 and for the second one num=1.
 * If you continue asking for the third one, you will get ::SDNS_ERROR_NO_ANSWER_FOUND error code in 'err' param.
 *
 * If there is no answer section in the DNS context, the code will return ::SDNS_ERROR_NO_ANSWER_FOUND
 * which shows there is no answer section in the DNS packet or DNS context passed by the caller.
 *
 * @return a pointer to the link-list of ::sdns_rr structure. 
 */
sdns_rr * sdns_get_answer(sdns_context * dns, int * err, uint16_t num);

/**
 * @brief Returns the authority section of the DNS context
 *
 * For the list of parameters, check sdns_get_answer() function
 */
sdns_rr * sdns_get_authority(sdns_context * dns, int * err, uint16_t num);


/**
 * @brief Returns the additional section of the DNS context
 *  
 * This function can not be used to get the OPT (EDNS0) records from the additional
 * section. To get OPT records (e.g., cookies, NSID, etc), you can use the relevant functions.
 *
 * For the list of parameters, check sdns_get_answer() function
 */
sdns_rr * sdns_get_additional(sdns_context * dns, int * err, uint16_t num);


/**
 * @brief Adds AAAA record to the asnwer section of the DNS context.
 * @param dns a pointer to the DNS context
 * @param name name of the section
 * @param ttl TTL value of the seciton
 * @param ipv6 A pointer to a nul-terminated string representing IPv6 address.
 *
 * The 'ipv6' params must be in a form of ':' seperated hex values representing IPv6 either in compressed
 * or uncompressed way: e.g., ::1 or cd23::5612:32a8:8933:cc3
 *
 * Caller is responsible to free 'ipv6' param if necessary as the library copies the value internally.
 *
 * It's not possible to pass the combination of IPv4 and IPv6 as the internal parser does not support it
 *
 * @return 0 on success, other values on failure
 */
int sdns_add_rr_answer_AAAA(sdns_context * dns, char * name, uint32_t ttl, const char * ipv6);



/**
 * @brief Adds AAAA record to the authority section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_AAAA()
 */
int sdns_add_rr_authority_AAAA(sdns_context * dns, char * name, uint32_t ttl, const char * ipv6);


/**
 * @brief Adds AAAA record to the additional section of the DNS.
 *
 * Check the documentation of sdns_add_rr_answer_AAAA()
 */
int sdns_add_rr_additional_AAAA(sdns_context * dns, char * name, uint32_t ttl, const char * ipv6);



/**
 * @brief Adds NID record to the asnwer section of the DNS context.
 * @param dns a pointer to the DNS context
 * @param name name of the section
 * @param ttl TTL value of the seciton
 * @param preference the 16bit preference value of NID record
 * @param nodeid A pointer to a memory where it has the NID data.
 *
 * The NID pointer must point to a memory which has 8 bytes. The function 
 * exactly copy 8 bytes from this address to its internal memory. The user can free the memory
 * allocated for 'nodeid' (if it's necessary) after calling this function
 *
 * @return 0 on success, other values on failure.
 */
int sdns_add_rr_answer_NID(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * nodeid);


/**
 * @brief Adds NID record to the asnwer section of the DNS context.
 *
 * Check the documentation of the sdns_add_rr_answer_NID() for more info.
 */
int sdns_add_rr_authority_NID(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * nodeid);


/**
 * @brief Adds NID record to the asnwer section of the DNS context.
 *
 * Check the documentation of the sdns_add_rr_answer_NID() for more info.
 */
int sdns_add_rr_additional_NID(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * nodeid);

/**
 * @brief Returns a copy of the question section of the DNS context
 * @param dns an instance of ::sdns_context
 *
 * Caller is responsible to free the returned memory address.
 *
 * @return a pointer to a memory address which stores the structure of ::sdns_question or NULL on failure
 */
sdns_question * sdns_get_question(sdns_context * dns);

/**
 * @brief Creates a response DNS context from the query packet.
 * @param the query packet which is an instance of ::sdns_context
 *
 * This function is effectively a combination of other functions to create
 * a new context to send as a response to the received query.
 *
 * It will create a new packet by calling sdns_create_query() and copy the question
 * section of the 'query' context to the new packet. Then calls sdns_set_qr() and sdns_set_id()
 * to make the packet of type response. if the 'query' context is edns0-aware, the response will be 
 * also edns0-aware. Other sections are all empty.
 *
 *
 * @return a new ::sdns_context on success or NULL on failure
 */
sdns_context * sdns_create_response_from_query(sdns_context * query);




#endif
