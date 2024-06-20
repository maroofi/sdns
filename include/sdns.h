/** @file */
#include <stdint.h>

#ifndef __SDNS_H
#define __SDNS_H

#define TO_OUTPUT(A,B) do{if (NULL == A) {fprintf(stdout, B);}else{strcpy(A,B);}}while(0);

#define UDP_PAYLOAD_SIZE 1232   ///< Default UDP payload size for EDNS0
#define DNS_HEADER_LENGTH 12    ///< Standard DNS Header length

// define some error code constant
#define SDNS_ERROR_MEMORY_ALLOC_FAILD -1                ///< memory allocation using malloc() failed
#define SDNS_ERROR_BUFFER_TOO_SHORT -2                  ///< DNS packet length is shorter than expectedd
#define SDNS_ERROR_QNAME_IS_NULL -3                     ///< Qname of the question section can not be null
#define SDNS_ERROR_HOSTNAME_TOO_LONG -4                 ///< Hostname can not be more than 255 characters
#define SDNS_ERROR_WRONG_LABEL_SPECIFIED -5             ///< Label name is too long or malformed
#define SDNS_ERROR_BUFFER_IS_NULL -6                    ///< passed buffer to the function is NULL
#define SDNS_ERROR_BUFFER_IS_SMALL -7                   ///< buffer is shorter than expected
#define SDNS_ERROR_INVALID_DNS_PACKET -8                ///< The packet is not a valid DNS packet
#define SDNS_ERROR_MORE_THAN_ONE_QUESTION_FOUND -9      ///< Each DNS packet must have exactly one question section
#define SDNS_ERROR_RR_NULL -10
// these two are success code for encoding label
#define SDNS_ERROR_ELSIMPLE -11                         ///< Success code for simple encoding of the name
#define SDNS_ERROR_ELCOMPRESSED -12                     ///< Success code for compressed encoding of the name

#define SDNS_ERROR_LABEL_MAX_63 -13                     ///< each part of the name must be <= 63 characters
/** In some cases like RRSIG, the name can not be compressed (e.g., signer's name in RRSIG).
 *  So if we found a compressed name in those sections, we return this error*/
#define SDNS_ERROR_ILLEGAL_COMPRESSION -14              ///< Compressed label found when it's illegal
#define SDNS_ERROR_RR_SECTION_MALFORMED -15


/** The list of opcodes can be found at:
 *  http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
 */
typedef enum{
    sdns_opcode_Query=0,                ///< RFC1035
    sdns_opcode_IQuery=1,               ///< RFC1035
    sdns_opcode_Status=2,               ///< RFC1035
    sdns_opcode_Notify=4,               ///< RFC1996
    sdns_opcode_Update=5,               ///< RFC2136
    sdns_opcode_DSO=6                   ///< RFC8490
} sdns_opcode;



/**
 * The list of standard error codes for DNS can be found at:
 * http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
 */
typedef enum{
    sdns_rcode_NoError=0,           ///< RFC1035
    sdns_rcode_FormErr=1,           ///< RFC1035
    sdns_rcode_ServFail=2,          ///< RFC1035
    sdns_rcode_NXDomain=3,          ///< RFC1035
    sdns_rcode_NotImp=4,            ///< RFC1035
    sdns_rcode_Refused=5,           ///< RFC1035
    sdns_rcode_YXDomain=6,          ///< RFC2136
    sdns_rcode_YXRRSet=7,           ///< RFC2136
    sdns_rcode_NXRRSet=8,           ///< RFC2136
    sdns_rcode_NotAuth=9,           ///< RFC2136, RFC8945
    sdns_rcode_NotZone=10,          ///< RFC2136
    sdns_rcode_DSOTYPENI=11,        ///< RFC8490
    sdns_rcode_BADVERS=16,          ///< 
    sdns_rcode_BADSIG=16,           ///<
    sdns_rcode_BADKEY=17,           ///<
    sdns_rcode_BADTIME=18,          ///<
    sdns_rcode_BADMODE=19,          ///<
    sdns_rcode_BADNAME=20,          ///<
    sdns_rcode_BADALG=21,           ///<
    sdns_rcode_BADTRUNC=22,         ///<
    sdns_rcode_BADCOOKIE=23,        ///<
    sdns_rcode_Reserved=65535       ///<
} sdns_rcode;

/**
 * The structure of the question section of a DNS packet from <a href="https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2">Section4.1.2 RFC1035</a>
 * <pre>
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                                               |
 *   /                     QNAME                     /
 *   /                                               /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     QTYPE                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     QCLASS                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * </pre>
 */
typedef struct {
    char * qname;                   ///< RFC1035 - the domain name
    uint16_t qtype;                 ///< RFC1035 - two octet, type of the query
    uint16_t qclass;                ///< RFC1035 - two octet, class of the query
} sdns_question;


/**
 * The rdata part of the OPT section has the following format
 * based on <a href="https://datatracker.ietf.org/doc/html/rfc2671#section-4.4">RFC2671 Section 4.4</a>
 *
 * <pre>
 *                 +0 (MSB)                            +1 (LSB)
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 0: |                          OPTION-CODE                          |
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 2: |                         OPTION-LENGTH                         |
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 4: |                                                               |
 *    /                          OPTION-DATA                          /
 *    /                                                               /
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 * </pre>
 *
 *
 *
 */
struct _sdns_opt_rdata{
    uint16_t option_code;
    uint16_t option_length;
    char * option_data;
    struct _sdns_opt_rdata * next;
};

/** See ::_sdns_opt_rdata structure for detail. */
typedef struct _sdns_opt_rdata sdns_opt_rdata;



/** TTL option in OPT type of the RR has the following 
 * structure based on <a href="https://datatracker.ietf.org/doc/html/rfc2671#section-4.6">RFC2671 Section 4.6</a>:
 *
 * <pre>
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *  0: |         EXTENDED-RCODE        |            VERSION            |
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *  2: |                               Z                               |
 *     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * </pre>
 */
typedef struct{
    uint32_t extended_rcode :8;
    uint32_t version        :8;
    uint32_t DO             :1;
    uint32_t Z              :15;
} sdns_opt_ttl;


/**
 * Each resource record of a DNS packet has the following format.
 * This is the standard format of **answer** section, **authority** section 
 * and **additional** section of a DNS packet (<a href="https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3">RFC1035#Section4.3.1</a>).
 * 
 * <pre>
 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                                               |
 *   /                                               /
 *   /                      NAME                     /
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      TYPE                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     CLASS                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      TTL                      |
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   RDLENGTH                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *   /                     RDATA                     /
 *   /                                               /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * </pre>
 * 
 * 1. **NAME** is always has the same meaning for all the sections and RRs.
 * 2. **TYPE** is always the same and shows the type of the RR.
 * 3. **CLASS** is one the values of ::sdns_rr_class or ::sdns_q_class. However,
 * when **TYPE** is ::sdns_rr_type_OPT (41), then **CLASS** is the size of the 
 * UDP packet. This behaviour defined in <a href="https://datatracker.ietf.org/doc/html/rfc2671#section-4.3">RFC2671</a>
 * 
 * 4. **TTL** is either a 32 bit value showing the time to live of the record (RFC1035) or 
 * a 32bit structure of ::sdns_opt_ttl.
 *
 * 5. **rdlength** always contains the length of the data part of the RR.
 *
 * NOTE: Three fields of this structure are not RFC standard and are only
 * used here as helpers.
 * 
 * 1. **decoded**: This binary field is either 0 or 1 and it tells the user
 * if the _rdata_ part is decoded or not. When the _rdata_ part is decoded (decoded=1),
 * then we can use **psdns_rr** pointer and cast it to the correct structure and use it.
 * when the _rdata_ is not decoded (decoded=0), we should treat it as a pointer to char*.
 * 2. **next**: a pointer to the same structure for creating a link-list of RRs.
 *
 */
struct _sdns_rr{
    char * name;                     ///< RFC1035 - domain name
    uint16_t type;                  ///< RFC1035 - RR type code
    union {
        uint16_t class;             ///< RFC1035 - class of the data in rdata
        uint16_t udp_size;
    };
    union {
        uint32_t ttl;
        sdns_opt_ttl opt_ttl;
    };
    uint16_t rdlength;              ///< RFC1035 - length of the RDATA field
    union {
        char * rdata;               ///< resource record data (for all RRs except for OPT)
        sdns_opt_rdata * opt_rdata;
        void * psdns_rr;   ///< this is not DNS-RFC. It's just a reference for our library
    };
    uint8_t decoded;       ///< this is not DNS-RFC. it's just a flag to know if the rdata is decoded or not
    struct _sdns_rr * next;
};

/** See ::_sdns_rr for more information */
typedef struct _sdns_rr sdns_rr;

/**
 * Here is the list of possible RR types reitrieved from:
 * https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
 */
typedef enum {
    sdns_rr_type_A=1,               ///< RFC1035 - A record
    sdns_rr_type_NS=2,              ///< RFC1035 - NS record
    sdns_rr_type_MD=3,              ///< RFC1035 - mail destination record
    sdns_rr_type_MF=4,              ///< RFC1035 - mail forwarder record
    sdns_rr_type_CNAME=5,           ///< RFC1035 - canonical name
    sdns_rr_type_SOA=6,             ///< RFC1035 - start of a zone of authority
    sdns_rr_type_MB=7,              ///< RFC1035 - mailbox domain name
    sdns_rr_type_MG=8,              ///< RFC1035 - mail group member
    sdns_rr_type_MR=9,              ///< RFC1035 - mail rename domain name
    sdns_rr_type_NULL=10,           ///< RFC1035 - a null RR
    sdns_rr_type_WKS=11,            ///< RFC1035 - a well known service description
    sdns_rr_type_PTR=12,            ///< RFC1035 - a domain name pointer
    sdns_rr_type_HINFO=13,          ///< RFC1035 - host information
    sdns_rr_type_MINFO=14,          ///< RFC1035 - mailbox or mail list information
    sdns_rr_type_MX=15,             ///< RFC1035 - mail exchange
    sdns_rr_type_TXT=16,            ///< RFC1035 - text strings
    sdns_rr_type_RP=17,
    sdns_rr_type_AFSDB=18,
    sdns_rr_type_X25=19,
    sdns_rr_type_ISDN=20,
    sdns_rr_type_RT=21,
    sdns_rr_type_NSAP=22,
    sdns_rr_type_NSAP_PTR=23,
    sdns_rr_type_SIG=24,
    sdns_rr_type_KEY=25,
    sdns_rr_type_PX=26,
    sdns_rr_type_GPOS=27,
    sdns_rr_type_AAAA=28,           ///< RFC3596 - AAAA record
    sdns_rr_type_LOC=29,
    sdns_rr_type_NXT=30,
    sdns_rr_type_EID=31,
    sdns_rr_type_NIMLOC=32,
    sdns_rr_type_SRV=33,
    sdns_rr_type_ATMA=34,
    sdns_rr_type_NAPTR=35,
    sdns_rr_type_KX=36,
    sdns_rr_type_CERT=37,
    sdns_rr_type_A6=38,
    sdns_rr_type_DNAME=39,
    sdns_rr_type_SINK=40,
    sdns_rr_type_OPT=41,            ///< RFC6891 - option RR for ends
    sdns_rr_type_APL=42,
    sdns_rr_type_DS=43,
    sdns_rr_type_SSHFP=44,
    sdns_rr_type_IPSECKEY=45,
    sdns_rr_type_RRSIG=46,
    sdns_rr_type_NSEC=47,
    sdns_rr_type_DNSKEY=48,
    sdns_rr_type_DHCID=49,
    sdns_rr_type_NSEC3=50,
    sdns_rr_type_NSEC3PARAM=51,
    sdns_rr_type_TLSA=52,
    sdns_rr_type_SMIMEA=53,
    sdns_rr_type_HIP=55,
    sdns_rr_type_NINFO=56,
    sdns_rr_type_RKEY=57,
    sdns_rr_type_TALINK=58,
    sdns_rr_type_CDS=59,
    sdns_rr_type_CDNSKEY=60,
    sdns_rr_type_OPENPGPKEY=61,
    sdns_rr_type_CSYNC=62,
    sdns_rr_type_ZONEMD=63,
    sdns_rr_type_SVCB=64,
    sdns_rr_type_HTTPS=65,
    sdns_rr_type_SPF=99,
    sdns_rr_type_UINFO=100,
    sdns_rr_type_UID=101,
    sdns_rr_type_GID=102,
    sdns_rr_type_UNSPEC=103,
    sdns_rr_type_NID=104,
    sdns_rr_type_L32=105,
    sdns_rr_type_L64=106,
    sdns_rr_type_LP=107,
    sdns_rr_type_EUI48=108,
    sdns_rr_type_EUI64=109,
    sdns_rr_type_TKEY=249,
    sdns_rr_type_TSIG=250,
    sdns_rr_type_IXFR=251,
    sdns_rr_type_AXFR=252,          ///< RFC1035 - request for transfer of entire zone
    sdns_rr_type_MAILB=253,         ///< RFC1035 - request for mailbox related records
    sdns_rr_type_MAILA=254,         ///< RFC1035 - request for mail agent RRs
    sdns_rr_type_star=255,          ///< RFC1035 - request for all records
    sdns_rr_type_URI=256,
    sdns_rr_type_CAA=257,
    sdns_rr_type_AVC=258,
    sdns_rr_type_DOA=259,
    sdns_rr_type_AMTRELAY=260,
    sdns_rr_type_RESINFO=261,
    sdns_rr_type_TA=32768,
    sdns_rr_type_DLV=32769
} sdns_rr_type;


/**
 * Possible valid values for the __option code__ of EDNS0
 * https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
 */
typedef enum{
   sdns_edns0_option_code_Reserved0=0,
   sdns_edns0_option_code_LLQ=1,
   sdns_edns0_option_code_Update_Lease=2,
   sdns_edns0_option_code_NSID=3,
   sdns_edns0_option_code_Reserved4=4,
   sdns_edns0_option_code_DAU=5,
   sdns_edns0_option_code_DHU=6,
   sdns_edns0_option_code_N3U=7,
   sdns_edns0_option_code_edns_client_subnet=8,
   sdns_edns0_option_code_EDNS_EXPIRE=9,
   sdns_edns0_option_code_COOKIE=10,
   sdns_edns0_option_code_edns_tcp_keepalive=11,
   sdns_edns0_option_code_Padding=12,
   sdns_edns0_option_code_CHAIN=13,
   sdns_edns0_option_code_edns_key_tag=14,
   sdns_edns0_option_code_Extended_DNS_Error=15,
   sdns_edns0_option_code_EDNS_Client_Tag=16,
   sdns_edns0_option_code_EDNS_Server_Tag=17,
   sdns_edns0_option_code_Report_Channel=18,
   sdns_edns0_option_code_Umbrella_Ident=20292,
   sdns_edns0_option_code_DeviceID=26946
} sdns_edns0_option_code;

/**
 * Possible values for the __CLASS__ field of a Resource Record
 */
typedef enum{
    sdns_rr_class_IN=1,           ///< RFC1035 - the Internet
    sdns_rr_class_CS=2,           ///< RFC1035 - the CSNET
    sdns_rr_class_CH=3,           ///< RFC1035 - the CHAOS class
    sdns_rr_class_HS=4            ///< RFC1035 - Hesiod
} sdns_rr_class;


/**
 * Possible values for the __CLASS__ field of a question section
 */
typedef enum{
    sdns_q_class_IN=1,           ///< RFC1035 - the Internet
    sdns_q_class_CS=2,           ///< RFC1035 - the CSNET
    sdns_q_class_CH=3,           ///< RFC1035 - the CHAOS class
    sdns_q_class_HS=4,           ///< RFC1035 - Hesiod
    sdns_q_class_STAR=255        ///< RFC1035 - any class
} sdns_q_class;


/**
 * Structure of the DNS packet header based on <a href="https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1">RFC1035 Section 4.1.1</a>
 * <pre>
 *                                     1  1  1  1  1  1
 *     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      ID                       |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    QDCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ANCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    NSCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ARCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * </pre>
 * The header is exactly 12 bytes and it's always the same.
 *
 * Although **QDCOUNT** can be > 1 but most DNS resolvers return FormError if
 * **QDCOUNT** > 1
 *
 */
typedef struct {
    uint16_t id;              ///< RFC1035: 16-bit identifier
    uint8_t qr        :1;     ///< RFC1035: one bit if the msg is query(0) or response(1)
    uint8_t opcode    :4;     ///< RFC1035: 4-bit specifies the kind of query in the message
    uint8_t aa        :1;     ///< RFC1035: 1-bit if this is an authorative answer
    uint8_t tc        :1;     ///< RFC1035: 1-bit TrunCation
    uint8_t rd        :1;     ///< RFC1035: Recursion Desired
    uint8_t ra        :1;     ///< RFC1035: Recursion Available
    uint8_t z         :1;     ///< RFC1035: Reserved for future use
    uint8_t AD        :1;     ///< RFC2535: Section 6.1: authentic data
    uint8_t CD        :1;     ///< RFC2535: Section 6.1: checking disabled
    uint8_t rcode:4;          ///< RFC1035: Response code
    uint16_t qdcount;         ///< RFC1035: Number of entries in question section
    uint16_t ancount;         ///< RFC1035: Number of entries in answer section
    uint16_t nscount;         ///< RFC1035: Number of entries in authority section
    uint16_t arcount;         ///< RFC1035: Number of entries in additional section
} sdns_header;

/**
 * List of known value for Extended DNS Errors (EDE).
 * The full list is available in <a href="https://www.rfc-editor.org/rfc/rfc8914">RFC 8914</a>
 */
typedef enum {
    sdns_ede_code_Other_Error=0,
    sdns_ede_code_Unsupported_DNSKEY_Algorithm=1,
    sdns_ede_code_Unsupported_DS_Digest_Type=2,
    sdns_ede_code_Stale_Answer=3,
    sdns_ede_code_Forged_Answer=4,
    sdns_ede_code_DNSSEC_Indeterminate=5,
    sdns_ede_code_DNSSEC_Bogus=6,
    sdns_ede_code_Signature_Expired=7,
    sdns_ede_code_Signature_Not_Yet_Valid=8,
    sdns_ede_code_DNSKEY_Missing=9,
    sdns_ede_code_RRSIGs_Missing=10,
    sdns_ede_code_No_Zone_Key_Bit_Set=11,
    sdns_ede_code_NSEC_Missing=12,
    sdns_ede_code_Cached_Error=13,
    sdns_ede_code_Not_Ready=14,
    sdns_ede_code_Blocked=15,
    sdns_ede_code_Censored=16,
    sdns_ede_code_Filtered=17,
    sdns_ede_code_Prohibited=18,
    sdns_ede_code_Stale_NXDomain_Answer=19,
    sdns_ede_code_Not_Authoritative=20,
    sdns_ede_code_Not_Supported=21,
    sdns_ede_code_No_Reachable_Authority=22,
    sdns_ede_code_Network_Error=23,
    sdns_ede_code_Invalid_Data=24,
    sdns_ede_code_Signature_Expired_before_Valid=25,
    sdns_ede_code_Too_Early=26,
    sdns_ede_code_Unsupported_NSEC3_Iterations_Value=27,
    sdns_ede_code_Unable_to_conform_to_policy=28,
    sdns_ede_code_Synthesized=29
}sdns_ede_code;

/** This is the structure of a DNS packet. */
typedef struct {
    sdns_header header;
    sdns_question question;
    sdns_rr *answer;
    sdns_rr *authority;
    sdns_rr *additional;
} sdns_message;

/** Structure to hold the data of RR type */
typedef struct {
    uint32_t address;           ///< IPv4 address (only one address)
} sdns_rr_A;

/** Structure to hold the data of RR type AAAA */
typedef struct {
    char * address;
} sdns_rr_AAAA;

/**
 * Structure to hold the data of RR type TXT.
 * The data part of a TXT RR has one bytes of length
 * and a sequence of bytes. This means that TXT records 
 * that are longer than 255 characters, will be broken to several parts
 * each less than 255 characters.
 */
typedef struct {
    uint8_t len;
    char * content;
} txt_data;

/** The structure of a TXT record */
struct _sdns_rr_TXT {
   txt_data character_string;
   struct _sdns_rr_TXT * next;
};

/** check the definition of ::_sdns_rr_TXT. */
typedef struct _sdns_rr_TXT sdns_rr_TXT;


/** The structure of SOA RR based on RFC1035 */
typedef struct {
    char * mname;           ///< Primary name server
    char * rname;           ///< mailbox of the responsible person
    uint32_t serial;        ///< version number of the original copy of the zone
    uint32_t refresh;       ///< time interval before the zone should be refreshed
    uint32_t retry;         ///< elapse before a failed refresh should be retried
    uint32_t expire;        ///< upper limit on the time interval that can elapse before the zone is no longer authoritative
    uint32_t minimum;       ///< minimum TTL field that should be exported with any RR from this zone
} sdns_rr_SOA;


/** structure of MX RR */
typedef struct {
    uint16_t preference;
    char * exchange;
}sdns_rr_MX;

/** structure of NS RRs */
typedef struct{
    char * NSDNAME;
}sdns_rr_NS;


/** structure of ptr RRs */
typedef struct{
    char * PTRDNAME;
}sdns_rr_PTR;

/** structure of CNAME RRs */
typedef struct{
    char * CNAME;
}sdns_rr_CNAME;

/** This structure keeps the Extended DNS Errors (EDE with option-code 15) of OPT RRs. */
typedef struct {                
    uint16_t inf_code;          ///< One of the values in ::sdns_ede_code
    char * extra_text;          ///< Section 2, RFC8914 says this is null-terminated but MUST NOT be assumed to be.
    uint16_t extra_text_len;    ///< Section 2, RFC8914: the length MUST be derived from the OPTION-LENGTH field
}sdns_rr_OPT_EDE;

/**
 * The structure of the RRSIG RR based on <a href="https://datatracker.ietf.org/doc/html/rfc4034#section-3.1">RFC4034Sec3.1</a>.
 * <pre>
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Type Covered           |  Algorithm    |     Labels    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Original TTL                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Signature Expiration                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Signature Inception                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Key Tag            |                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  /                                                               /
 *  /                            Signature                          /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * </pre>
 * */
typedef struct{
    uint16_t type_covered;
    uint8_t algorithm;
    uint8_t labels;
    uint32_t original_ttl;
    uint32_t signature_expiration;
    uint32_t signature_inception;
    uint16_t key_tag;
    char * signers_name;
    char * signature;
    uint16_t signature_len;     ///< This is just a helper not an RFC standard field.
}sdns_rr_RRSIG;


/**
 * This is the structure of the SRV RR. This is from RFC2782 and needs more testing
 * as the RFC is not clear as previous ones....
 */
typedef struct{
    uint16_t Priority;
    uint16_t Weight;
    uint16_t Port;
    char * Target;             ///< RFC2782: the name compression can not be applied to this name
}sdns_rr_SRV;

/**
 * Structure of URL RR based on RFC rfc7553
 */
typedef struct{
    uint16_t Priority;
    uint16_t Weight;
    char * Target;          ///< I didn't find any text in RFC saying this must be a human-readable string!
    uint16_t target_len;
} sdns_rr_URI;

/**
 * This is the structure of the NID RR based on RFC 6742
 */
typedef struct{
    uint16_t Preference;        ///< indicates the owner name's relative preference
    char * NodeId;              ///< NodeID field is an unsigned 64-bit value in network byte order (len=8bytes)
} sdns_rr_NID;

/**
 * This is the structure of the HINFO RR based on RFC 1035
 */
typedef struct{
    uint8_t cpu_len;
    char * cpu;
    uint8_t os_len;
    char * os;
}sdns_rr_HINFO;

/**
 * this is the structure of the L32 RR based on RFC 6742
 */
typedef struct{
    uint16_t Preference;
    uint32_t Locator32;
}sdns_rr_L32;


/**
 * this is the structure of the L64 RR based on RFC 6742
 */
typedef struct{
    uint16_t Preference;    ///< a 16-bit Preference field
    char * Locator64;       ///< Locator64 is exactly 64 bit (8bytes)
}sdns_rr_L64;


/**
 * this is the structure of the LP RR based on RFC 6742
 */
typedef struct{
    uint16_t Preference;    ///< a 16-bit Preference field
    char * FQDN;            ///< FQDN is a variable length field contains the DNS target name that is used to reference L32 and/or L64 records.
}sdns_rr_LP;

/**
 * The main structure of library.
 *
 * This is structure is used to parse a sequence of bytes to a DNS packet and vice versa.
 * **raw_len** and **cursor** are used internally and should not be used by callers.
 */
typedef struct {
    sdns_message * msg;         ///< This is the DNS packet
    char * raw;                 ///< The raw bytes we received from socket
    uint16_t raw_len;           ///< Length of the raw data we received from socket
    char * cursor;              // This cursor keeps the position of the pointer in raw data
    int err;                    ///< This shows the last error code after any operation on the context
}sdns_context;



// list of function declarations

/**
 * @brief Creates a DNS question query.
 * @param ctx A pointer to the ::sdns_context structure created by sdns_init_context()
 * @param qtype one of the possible values of ::sdns_rr_type
 * @param cls one of the possible values of ::sdns_q_class
 * @param qname a pointer to the question name.
 * @param enable_edns0 a value of 0 or 1 specifying if the packet is EDNS0 aware or not.
 *
 * **qname** pointer must be a pointer to char* and not a local buffer. when you call sdns_free_context(),
 * the function try to free() the **qname**.
 *
 * In case the function returns a value other than 0, you can call sdns_error_string() to get 
 * the description of the error code.
 * 
 * @return A successfull call to this function will return 0 and other values indicate errors.
 *
 * @code
 * char *error = NULL;
 * sdns_context * ctx = sdns_init_context();
 * if (NULL == ctx)
 *     return 1;
 * // Let's make the most trivial and basic DNS packet. (google.com IN A)
 * // notice how I use strdup to pass a heap-allocated pointer to the function.
 * int res = sdns_make_query(ctx, sdns_rr_type_A, sdns_q_class_IN, strdup("google.com"), 1);
 * if (res != 0){
 *     sdns_error_string(res, &error);
 *     fprintf(stderr, "%s\n", error);
 *     free(error);
 *     sdns_free_context(ctx);
 *     return 1;
 * }
 * // the packet has been created successfully. We can convert it to wire format and send it.
 * res = sdns_to_wire(ctx);
 * if (res != sdns_rcode_NoError){
 *     sdns_error_string(res, &error);
 *     fprintf(stderr, "%s\n", error);
 *     free(error);
 *     sdns_free_context(ctx);
 *     return 1;
 * }
 * // ctx->raw is ready for the socket and ctx->raw_len is its length.
 * // ctx->raw and ctx->raw_len can be used in sendto() function.
 * // after we are done, we need to free the context.
 * sdns_free_context(ctx);
 * @endcode
 */
int sdns_make_query(sdns_context * ctx, sdns_rr_type qtype,
                     sdns_q_class cls, char * qname, int enable_edns0);



/**
 * @brief Coverts a DNS context to binary format.
 * @param ctx A pointer to DNS context created by sdns_init_context().
 *
 * @return 0 on success other values for failure.
 *
 * This is one of the main APIs provided by this library. Whenever you want
 * to send data to the socket, you must call this function first to create 
 * the binary data.
 *
 * Look at the privided example for sdns_make_query() for more info.
 */
int sdns_to_wire(sdns_context * ctx);


/**
 * @brief Converts the raw data received from socket (bytes) to a DNS packet.
 * @param ctx A pointer to DNS context created by sdns_init_context().
 *
 * A description of all error codes returned by this method can be
 * retrieved by calling sdns_error_string() function.
 *
 * @return 0 on success, other values in case of failure.
 *
 * @code
 * char * buff = (char*)malloc(1024);
 * ssize_t received = recvfrom(socketfd, buff, 1024, ......)
 * // assume that we received "received" bytes from socket stored in "buff"
 * // here is how we can convert it to DNS packet.
 * sdns_context * ctx = sdns_init_context();
 * // I am not doing error checks but you must always make sure ctx is not NULL
 * // After you are done with error checks....
 * ctx->raw = buff;
 * ctx->raw_len = received;
 * int res = sdns_from_wire(ctx);
 * if (res != 0){
 *      // we need to handle the error, we can call sdns_error_string
 * }
 * // we have a parsed DNS packet in ctx->msg
 * sdns_neat_print_dns(ctx);
 * @endcode
 *
 */
int sdns_from_wire(sdns_context * ctx);


/**
 * @brief Coverts error codes to a string
 * @param err the error code you received from one of the functions or any DNS defined error.
 * @param err_buff A double pointer to the buffer to receive the string. if it's NULL, we will allocate memory.
 *
 * The **err_buff** parameter must be large enough to cover all possible error codes.
 * Currently, no error string is larger than 256. Hence, 256 bytes of buffer is large enough and safe.
 * 
 * check the source code example in sdns_make_query() for more information.
 */
void sdns_error_string(int err, char ** err_buff);



/**
 * @brief Initialize and create a new DNS context
 *
 * This function is responsible for creating a new context for DNS.
 *
 * For each DNS packet, you must create a new context. This function does nothing
 * more than creating a structure and allocating the necessary memories.
 */
sdns_context * sdns_init_context(void);


/**
 * @brief Frees the context allocated by sdns_init_context().
 * @param ctx A pointer to the context.
 *
 * To prevent memory leak, you must free the context all the time.
 * 
 * This function will call all other __sdns_free_*()__ functions recursively to free the whole memory.
 */
void sdns_free_context(sdns_context* ctx);


/**
 * @brief Creates an answer section for the DNS packet
 * @param ctx A pointer to the DNS context crteated by sdns_init_context().
 * @param rr A pointer to the sdns_rr structure we want to add.
 *
 * @return 0 on success and other values on failure (call sdns_error_string() to get the error string)
 *
 * @code
 * // let's create a new context
 * sdns_context * dns_ctx = sdns_init_context();
 * if (NULL == dns_ctx){
 *     fprintf(stderr, "Can not initialize the DNS context...\n");
 *     return 1;
 * }
 * // let's make a query (gogole.com. IN TXT with EDNS0 enabled)
 * int res = sdns_make_query(dns_ctx, sdns_rr_type_TXT, sdns_q_class_IN, strdup("google.com"), 1);
 * if (res != 0){
 *     // handle errors and return
 * } 
 * // let's add an answer section for TXT record
 * // first we have to create a TXT structure using sdns_init_rr_TXT() function.
 * sdns_rr_TXT * txt = sdns_init_rr_TXT(strdup("Thisisatxtrecord"), 16);
 * // then we create a new section by calling sdns_init_rr() function.
 * sdns_rr * rr = sdns_init_rr(strdup("google.com"), sdns_rr_type_TXT, sdns_rr_class_IN, 86400, 0, 1, (void*)txt);
 * if (rr == NULL){
 *     // handle errors and exit
 * }
 * // finally, we add the newly created section to our context.
 * res = sdns_add_answer_section(dns_ctx, rr);
 * if (res != 0){
 *     // handle errors and exit
 * }
 * // let's print the final packet to see if works.
 * sdns_neat_print_dns(dns_ct void sdns_free_context(sdns_context *ctx)                                                           
 * sdns_free_context(dns_ctx);
 * @endcode
 *
 */
int sdns_add_answer_section(sdns_context * ctx, sdns_rr * rr);


/**
 * @brief Adds a new RR to the authority section of the DNS packet
 * @param ctx A pointer to DNS context created by sdns_init_context()
 * @param rr A pointer to the RR we want to add.
 *
 * @return 0 on success and other values on failure (call sdns_error_string() to get the error string)
 *
 * This function is exactly the same as sdns_add_answer_section() but adds the new record to
 * authority section of the DNS packet instead of the answer section.
 * 
 * For more info, check the provided example in sdns_add_answer_section() function.
 */
int sdns_add_authority_section(sdns_context * ctx, sdns_rr * rr);



/**
 * @brief Adds a new RR to the additional section of the DNS packet
 * @param ctx A pointer to DNS context created by sdns_init_context()
 * @param rr A pointer to the RR we want to add.
 *
 * @return 0 on success and other values on failure (call sdns_error_string() to get the error string)
 *
 * This function is exactly the same as sdns_add_answer_section() but adds the new record to
 * additional section of the DNS packet instead of the answer section.
 * 
 * For more info, check the provided example in sdns_add_answer_section() function.
 *
 * **NOTE**: We don't use this function to add EDNS0 options. Instead,
 * we use sdns_add_edns() function.
 *
 */
int sdns_add_additional_section(sdns_context * ctx, sdns_rr * rr);



int sdns_create_edns_option(uint16_t, uint16_t, char *, sdns_opt_rdata**);
int sdns_add_edns(sdns_context * ctx, sdns_opt_rdata * opt);
sdns_opt_rdata * sdns_create_edns0_ede(uint16_t info_code, char * extra_text, uint16_t extra_text_len);

// add whatever function you want to ends0 section
int sdns_ends0_option_code_to_text(sdns_edns0_option_code oc, char * buffer);
sdns_opt_rdata * sdns_create_edns0_cookie(char * client_cookie, char * server_cookie, uint8_t server_cookie_len);

int check_if_qtype_is_valid(uint16_t qtype);
int check_if_rrtype_is_valid(uint16_t qtype);
int check_if_qclass_is_valid(uint16_t qclass);
int check_if_rrclass_is_valid(uint16_t qclass);


sdns_message * sdns_init_message(void);
sdns_rr * sdns_init_rr(char * name, uint16_t type, uint16_t class, uint32_t ttl,
                       uint16_t rdlength, uint8_t decoded, void * rdata);


void * decode_rr_section(sdns_context *, sdns_rr *);
sdns_rr_A * sdns_decode_rr_A(sdns_context *, sdns_rr *);
sdns_rr_AAAA * sdns_decode_rr_AAAA(sdns_context *, sdns_rr *);
sdns_rr_TXT * sdns_decode_rr_TXT(sdns_context *, sdns_rr *);
sdns_rr_SOA * sdns_decode_rr_SOA(sdns_context *, sdns_rr *);
sdns_rr_MX * sdns_decode_rr_MX(sdns_context *, sdns_rr *);
sdns_rr_NS * sdns_decode_rr_NS(sdns_context * ctx, sdns_rr * rr);
sdns_rr_PTR * sdns_decode_rr_PTR(sdns_context * ctx, sdns_rr * rr);
sdns_rr_CNAME* sdns_decode_rr_CNAME(sdns_context * ctx, sdns_rr * rr);  
sdns_rr_RRSIG * sdns_decode_rr_RRSIG(sdns_context * ctx, sdns_rr * rr);
sdns_rr_SRV * sdns_decode_rr_SRV(sdns_context * ctx, sdns_rr * rr);
sdns_rr_HINFO * sdns_decode_rr_HINFO(sdns_context * ctx, sdns_rr * rr);
sdns_rr_URI * sdns_decode_rr_URI(sdns_context * ctx, sdns_rr* rr);
sdns_rr_NID * sdns_decode_rr_NID(sdns_context * ctx, sdns_rr* rr);
sdns_rr_L32 * sdns_decode_rr_L32(sdns_context * ctx, sdns_rr* rr);
sdns_rr_L64 * sdns_decode_rr_L64(sdns_context * ctx, sdns_rr* rr);
sdns_rr_LP * sdns_decode_rr_LP(sdns_context * ctx, sdns_rr* rr);


sdns_rr_A* sdns_init_rr_A(uint32_t ipaddress);
sdns_rr_AAAA* sdns_init_rr_AAAA(char * aaaa);
sdns_rr_TXT* sdns_init_rr_TXT(char *, uint16_t);
sdns_rr_MX * sdns_init_rr_MX(uint16_t, char *);
sdns_rr_NS * sdns_init_rr_NS(char * nsdname);
sdns_rr_PTR * sdns_init_rr_PTR(char * ptrdname);
sdns_rr_CNAME * sdns_init_rr_CNAME(char * cname);
sdns_rr_NID * sdns_init_rr_NID(uint16_t preference, char * nodid);
sdns_rr_L32 * sdns_init_rr_L32(uint16_t preference, uint32_t locator32);
sdns_rr_L64 * sdns_init_rr_L64(uint16_t preference, char * locator64);
sdns_rr_LP * sdns_init_rr_LP(uint16_t preference, char * fqdn);
sdns_rr_SRV * sdns_init_SRV(uint16_t, uint16_t, uint16_t, char *);
sdns_rr_URI * sdns_init_rr_URI(uint16_t, uint16_t, char *, uint16_t);
sdns_rr_RRSIG * sdns_init_rr_RRSIG(uint16_t, uint8_t, uint8_t, uint32_t, uint32_t, uint32_t, uint8_t, char *, char *, uint16_t);
sdns_rr_HINFO * sdns_init_rr_HINFO(uint8_t cpu_len, char * cpu, uint8_t os_len, char * os);
sdns_rr_SOA * sdns_init_rr_SOA(char * mname, char * rname, uint32_t expire, uint32_t minimum,
                               uint32_t refresh, uint32_t retry, uint32_t serial);

void sdns_free_rr_A(sdns_rr_A *);
void sdns_free_rr_MX(sdns_rr_MX *);
void sdns_free_rr_TXT(sdns_rr_TXT *);
void sdns_free_rr_AAAA(sdns_rr_AAAA *);
void sdns_free_rr_SOA(sdns_rr_SOA *);
void sdns_free_rr_NS(sdns_rr_NS*);
void sdns_free_rr_PTR(sdns_rr_PTR*);
void sdns_free_rr_CNAME(sdns_rr_CNAME*);
void sdns_free_rr_RRSIG(sdns_rr_RRSIG*);
void sdns_free_rr_SRV(sdns_rr_SRV*);
void sdns_free_rr_HINFO(sdns_rr_HINFO * hinfo);
void sdns_free_rr_URI(sdns_rr_URI * uri);
void sdns_free_rr_NID(sdns_rr_NID * nid);
void sdns_free_rr_L32(sdns_rr_L32 * l32);
void sdns_free_rr_L64(sdns_rr_L64 * l64);
void sdns_free_rr_LP(sdns_rr_LP * lp);


int sdns_create_edns_option(uint16_t, uint16_t, char *, sdns_opt_rdata**);
int sdns_add_edns(sdns_context * ctx, sdns_opt_rdata * opt);
sdns_opt_rdata * sdns_create_edns0_ede(uint16_t info_code, char * extra_text, uint16_t extra_text_len);

// add whatever function you want to ends0 section
int sdns_ends0_option_code_to_text(sdns_edns0_option_code oc, char * buffer);
sdns_opt_rdata * sdns_create_edns0_cookie(char * client_cookie, char * server_cookie, uint8_t server_cookie_len);

/** 
 * @brief Gets the string represantation of the **TYPE** tp in to _buffer_
 * @param tp A 16bit integer, one of the possible values of ::sdns_rr_type
 * @param buffer A pointer to the user-provided buffer
 *
 * The _buffer_ must be long enough to cover all types.
 *
 * Currently, a buffer of length 20 is enough.
 */
void sdns_rr_type_to_string(uint16_t t, char * buff);


/** 
 * @brief Gets the string represantation of the **CLASS** cls in to _buffer_
 * @param cls A 16bit integer, one of the possible values of ::sdns_rr_class or ::sdns_q_class
 * @param buffer A pointer to the user-provided buffer
 *
 * The _buffer_ must be long enough to cover all classes.
 *
 * Currently, a buffer of length 20 is enough.
 */
void sdns_class_to_string(uint16_t cls, char * buff);

#endif
