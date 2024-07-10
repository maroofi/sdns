#include <sdns_api.h>
#include <sdns.h>
#include <string.h>
#include <sdns_utils.h>
#include <stdlib.h>


sdns_context * sdns_from_network(char * buff, uint16_t buff_len){
    if (buff == NULL || buff_len == 0)
        return NULL;
    sdns_context * dns = sdns_init_context();
    if (dns == NULL)
        return NULL;
    dns->raw = mem_copy(buff, buff_len);
    if (NULL == dns->raw){
        sdns_free_context(dns);
        return NULL;
    }
    dns->raw_len = buff_len;
    int res = sdns_from_wire(dns);
    if (res != 0){
        fprintf(stderr, "result of decoding is: %d\n", res);
        sdns_free_context(dns);
        return NULL;
    }
    return dns;
}


char * sdns_to_network(sdns_context * dns, int * err, uint16_t * buff_len){
    *err = 0;
    *buff_len = 0;
    if (dns == NULL){
        *err = SDNS_ERROR_BUFFER_IS_NULL;
        *buff_len = 0;
        return NULL;
    }
    int res = sdns_to_wire(dns);
    if (res != 0){
        *err = res;
        *buff_len = 0;
        return NULL;
    }
    char * new_buffer = mem_copy(dns->raw, dns->raw_len);
    // we don't need this anymore
    free(dns->raw);
    dns->raw = NULL;

    if (NULL == new_buffer){
        *err = SDNS_ERROR_MEMORY_ALLOC_FAILD;
        *buff_len = 0;
        return NULL;
    }
    // we are successful
    *err  = 0;
    *buff_len = dns->raw_len;
    dns->raw_len = 0;
    return new_buffer;
}


int sdns_add_rr_answer_A(sdns_context * dns, char * name, uint32_t ttl, char * ip){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (ip == NULL)
        return 100;     // invalid IP
    if (cipv4_is_ip_valid(ip) == 0)     // zero means invalid IPv4
        return 100;     // invalid IP
    uint32_t ipaddress = cipv4_str_to_uint(ip);
    sdns_rr_A * a  = sdns_init_rr_A(ipaddress);
    if (NULL == a)
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_A, sdns_q_class_IN, ttl, 0, 1, (void*) a);
    if (NULL == rr){
        free(section_name);
        sdns_free_rr_A(a);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        free(a);
        return res;
    }
    return 0;   //success
}


int sdns_add_rr_additional_A(sdns_context * dns, char * name, uint32_t ttl, char * ip){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (ip == NULL)
        return 100;     // invalid IP
    if (cipv4_is_ip_valid(ip) == 0)     // zero means invalid IPv4
        return 100;     // invalid IP
    uint32_t ipaddress = cipv4_str_to_uint(ip);
    sdns_rr_A * a  = sdns_init_rr_A(ipaddress);
    if (NULL == a)
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_A, sdns_q_class_IN, ttl, 0, 1, (void*) a);
    if (NULL == rr){
        free(section_name);
        sdns_free_rr_A(a);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        free(a);
        return res;
    }
    return 0;   //success
}

int sdns_add_rr_authority_A(sdns_context * dns, char * name, uint32_t ttl, char * ip){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (ip == NULL)
        return 100;     // invalid IP
    if (cipv4_is_ip_valid(ip) == 0)     // zero means invalid IPv4
        return 100;     // invalid IP
    uint32_t ipaddress = cipv4_str_to_uint(ip);
    sdns_rr_A * a  = sdns_init_rr_A(ipaddress);
    if (NULL == a)
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_A, sdns_q_class_IN, ttl, 0, 1, (void*) a);
    if (NULL == rr){
        free(section_name);
        sdns_free_rr_A(a);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        free(a);
        return res;
    }
    return 0;   //success
}


int sdns_add_rr_answer_NS(sdns_context * dns, char * name, uint32_t ttl, char * nsname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_name = NULL;
    if (nsname != NULL)
        new_name = strdup(nsname);
    sdns_rr_NS * ns  = sdns_init_rr_NS(new_name);
    if (NULL == ns)
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NS, sdns_q_class_IN, ttl, 0, 1, (void*) ns);
    if (NULL == rr){
        free(section_name);
        sdns_free_rr_NS(ns);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        free(ns->NSDNAME);
        free(ns);
        return res;
    }
    return 0;   //success
}

int sdns_add_rr_authority_NS(sdns_context * dns, char * name, uint32_t ttl, char * nsname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_name = NULL;
    if (nsname != NULL)
        new_name = strdup(nsname);
    sdns_rr_NS * ns  = sdns_init_rr_NS(new_name);
    if (NULL == ns)
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NS, sdns_q_class_IN, ttl, 0, 1, (void*) ns);
    if (NULL == rr){
        sdns_free_rr_NS(ns);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        free(ns->NSDNAME);
        free(ns);
        return res;
    }
    return 0;   //success
}

int sdns_add_rr_additional_NS(sdns_context * dns, char * name, uint32_t ttl, char * nsname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_name = NULL;
    if (nsname != NULL)
        new_name = strdup(nsname);
    sdns_rr_NS * ns  = sdns_init_rr_NS(new_name);
    if (NULL == ns)
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NS, sdns_q_class_IN, ttl, 0, 1, (void*) ns);
    if (NULL == rr){
        sdns_free_rr_NS(ns);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        free(ns->NSDNAME);
        free(ns);
        return res;
    }
    return 0;   //success
}


int sdns_add_rr_answer_TXT(sdns_context * dns, char * name, uint32_t ttl, char * text, uint16_t text_len){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_txt = NULL;
    if (text_len > 0 && text != NULL){
        new_txt = mem_copy(text, text_len);
        if (new_txt == NULL){
            return SDNS_ERROR_MEMORY_ALLOC_FAILD;
        }
    }
    sdns_rr_TXT * txt = sdns_init_rr_TXT(new_txt, text_len);
    if (txt == NULL){
        free(new_txt);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_TXT, sdns_q_class_IN, ttl, 0, 1, (void*) txt);
    if (NULL == rr){
        free(section_name);
        sdns_free_rr_TXT(txt);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_TXT(txt);
        return res;
    }
    return 0;  //success
}


int sdns_add_rr_authority_TXT(sdns_context * dns, char * name, uint32_t ttl, char * text, uint16_t text_len){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_txt = NULL;
    if (text_len > 0 && text != NULL){
        new_txt = mem_copy(text, text_len);
        if (new_txt == NULL){
            return SDNS_ERROR_MEMORY_ALLOC_FAILD;
        }
    }
    sdns_rr_TXT * txt = sdns_init_rr_TXT(new_txt, text_len);
    if (txt == NULL){
        free(new_txt);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_TXT, sdns_q_class_IN, ttl, 0, 1, (void*) txt);
    if (NULL == rr){
        sdns_free_rr_TXT(txt);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_TXT(txt);
        return res;
    }
    return 0;  //success

}


int sdns_add_rr_additional_TXT(sdns_context * dns, char * name, uint32_t ttl, char * text, uint16_t text_len){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_txt = NULL;
    if (text_len > 0 && text != NULL){
        new_txt = mem_copy(text, text_len);
        if (new_txt == NULL){
            return SDNS_ERROR_MEMORY_ALLOC_FAILD;
        }
    }
    sdns_rr_TXT * txt = sdns_init_rr_TXT(new_txt, text_len);
    if (txt == NULL){
        free(new_txt);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_TXT, sdns_q_class_IN, ttl, 0, 1, (void*) txt);
    if (NULL == rr){
        sdns_free_rr_TXT(txt);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_TXT(txt);
        return res;
    }
    return 0;  //success
}


sdns_context * sdns_create_query(char * name, char * type, char * cls){
    if (name == NULL || type == NULL || cls == NULL)
        return NULL;
    int new_type = sdns_convert_type_to_int(type);
    int new_class = sdns_convert_class_to_int(cls);
    if (new_type < 0 || new_class < 0)
        return NULL;
    
    sdns_context * dns = sdns_init_context();
    if (NULL == dns)
        return NULL;
    
    int res = sdns_make_query(dns, new_type, new_class, strdup(name), 1);
    if (res != 0){
        sdns_free_context(dns);
        return NULL;
    }
    return dns;
}


int sdns_add_rr_answer_SOA(sdns_context * dns, char * name, uint32_t ttl,  char * mname, char * rname, uint32_t expire,
                           uint32_t minimum, uint32_t refresh, uint32_t retry, uint32_t serial){
    if (dns == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (NULL == name)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_mname = mname == NULL?NULL:strdup(mname);
    char * new_rname = rname == NULL?NULL:strdup(rname);
    
    sdns_rr_SOA * soa = sdns_init_rr_SOA(new_mname, new_rname, expire, minimum, refresh, retry, serial);
    if (NULL == soa){
        free(new_rname);
        free(new_mname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SOA, sdns_q_class_IN, ttl, 0, 1, (void*) soa);
    if (NULL == rr){
        free(section_name);
        sdns_free_rr_SOA(soa);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_SOA(soa);
        return res;
    }
    return 0;  // success
}


int sdns_add_rr_authority_SOA(sdns_context * dns, char * name, uint32_t ttl,  char * mname, char * rname, uint32_t expire,
                           uint32_t minimum, uint32_t refresh, uint32_t retry, uint32_t serial){
    if (dns == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (NULL == name)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_mname = mname == NULL?NULL:strdup(mname);
    char * new_rname = rname == NULL?NULL:strdup(rname);
    
    sdns_rr_SOA * soa = sdns_init_rr_SOA(new_mname, new_rname, expire, minimum, refresh, retry, serial);
    if (NULL == soa){
        free(new_rname);
        free(new_mname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SOA, sdns_q_class_IN, ttl, 0, 1, (void*) soa);
    if (NULL == rr){
        sdns_free_rr_SOA(soa);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_SOA(soa);
        return res;
    }
    return 0;  // success
}

int sdns_add_rr_additional_SOA(sdns_context * dns, char * name, uint32_t ttl,  char * mname, char * rname, uint32_t expire,
                           uint32_t minimum, uint32_t refresh, uint32_t retry, uint32_t serial){
    if (dns == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (NULL == name)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_mname = mname == NULL?NULL:strdup(mname);
    char * new_rname = rname == NULL?NULL:strdup(rname);
    
    sdns_rr_SOA * soa = sdns_init_rr_SOA(new_mname, new_rname, expire, minimum, refresh, retry, serial);
    if (NULL == soa){
        free(new_rname);
        free(new_mname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SOA, sdns_q_class_IN, ttl, 0, 1, (void*) soa);
    if (NULL == rr){
        sdns_free_rr_SOA(soa);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_SOA(soa);
        return res;
    }
    return 0;  // success
}



int sdns_add_rr_answer_CNAME(sdns_context * dns, char * name, uint32_t ttl, char * cname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_cname = cname == NULL?NULL:strdup(cname);
    sdns_rr_CNAME * cn = sdns_init_rr_CNAME(new_cname);
    if (NULL == cn){
        free(new_cname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_CNAME, sdns_q_class_IN, ttl, 0, 1, (void*) cn);
    if (NULL == rr){
        sdns_free_rr_CNAME(cn);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        sdns_free_rr_CNAME(cn);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;  //success
}

int sdns_add_rr_authority_CNAME(sdns_context * dns, char * name, uint32_t ttl, char * cname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_cname = cname == NULL?NULL:strdup(cname);
    sdns_rr_CNAME * cn = sdns_init_rr_CNAME(new_cname);
    if (NULL == cn){
        free(new_cname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_CNAME, sdns_q_class_IN, ttl, 0, 1, (void*) cn);
    if (NULL == rr){
        sdns_free_rr_CNAME(cn);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        sdns_free_rr_CNAME(cn);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;  //success
}


int sdns_add_rr_additional_CNAME(sdns_context * dns, char * name, uint32_t ttl, char * cname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_cname = cname == NULL?NULL:strdup(cname);
    sdns_rr_CNAME * cn = sdns_init_rr_CNAME(new_cname);
    if (NULL == cn){
        free(new_cname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_CNAME, sdns_q_class_IN, ttl, 0, 1, (void*) cn);
    if (NULL == rr){
        sdns_free_rr_CNAME(cn);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        sdns_free_rr_CNAME(cn);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;  //success
}


int sdns_add_rr_answer_MX(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * exchange){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_exchange = safe_strdup(exchange);
    sdns_rr_MX * mx = sdns_init_rr_MX(preference, new_exchange);
    if (NULL ==  mx){
        free(new_exchange);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_MX, sdns_q_class_IN, ttl, 0, 1, (void*) mx);
    if (NULL == rr){
        sdns_free_rr_MX(mx);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        sdns_free_rr_MX(mx);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0; // success
}


int sdns_add_rr_authority_MX(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * exchange){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_exchange = safe_strdup(exchange);
    sdns_rr_MX * mx = sdns_init_rr_MX(preference, new_exchange);
    if (NULL ==  mx){
        free(new_exchange);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_MX, sdns_q_class_IN, ttl, 0, 1, (void*) mx);
    if (NULL == rr){
        sdns_free_rr_MX(mx);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        sdns_free_rr_MX(mx);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0; // success
}


int sdns_add_rr_additional_MX(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * exchange){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_exchange = safe_strdup(exchange);
    sdns_rr_MX * mx = sdns_init_rr_MX(preference, new_exchange);
    if (NULL ==  mx){
        free(new_exchange);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_MX, sdns_q_class_IN, ttl, 0, 1, (void*) mx);
    if (NULL == rr){
        sdns_free_rr_MX(mx);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        sdns_free_rr_MX(mx);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0; // success
}


int sdns_add_rr_answer_PTR(sdns_context * dns, char * name, uint32_t ttl, char * ptrdname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_ptrdname = safe_strdup(ptrdname);
    sdns_rr_PTR * ptr = sdns_init_rr_PTR(new_ptrdname);
    if (NULL == ptr){
        free(new_ptrdname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_PTR, sdns_q_class_IN, ttl, 0, 1, (void*)ptr);
    if (NULL == rr){
        sdns_free_rr_PTR(ptr);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        sdns_free_rr_PTR(ptr);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}


int sdns_add_rr_authority_PTR(sdns_context * dns, char * name, uint32_t ttl, char * ptrdname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_ptrdname = safe_strdup(ptrdname);
    sdns_rr_PTR * ptr = sdns_init_rr_PTR(new_ptrdname);
    if (NULL == ptr){
        free(new_ptrdname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_PTR, sdns_q_class_IN, ttl, 0, 1, (void*)ptr);
    if (NULL == rr){
        sdns_free_rr_PTR(ptr);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        sdns_free_rr_PTR(ptr);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}


int sdns_add_rr_additional_PTR(sdns_context * dns, char * name, uint32_t ttl, char * ptrdname){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_ptrdname = safe_strdup(ptrdname);
    sdns_rr_PTR * ptr = sdns_init_rr_PTR(new_ptrdname);
    if (NULL == ptr){
        free(new_ptrdname);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_PTR, sdns_q_class_IN, ttl, 0, 1, (void*)ptr);
    if (NULL == rr){
        sdns_free_rr_PTR(ptr);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        sdns_free_rr_PTR(ptr);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_answer_SRV(sdns_context * dns, char * name, uint32_t ttl, 
                           uint16_t priority, uint16_t weight, uint16_t port, char * target){
    
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_target = safe_strdup(target);
    sdns_rr_SRV * srv = sdns_init_rr_SRV(priority, weight, port, new_target);
    if (NULL == srv){
        free(new_target);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SRV, sdns_q_class_IN, ttl, 0, 1, (void*)srv);
    if (NULL == rr){
        sdns_free_rr_SRV(srv);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        sdns_free_rr_SRV(srv);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_authority_SRV(sdns_context * dns, char * name, uint32_t ttl, 
                           uint16_t priority, uint16_t weight, uint16_t port, char * target){
    
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_target = safe_strdup(target);
    sdns_rr_SRV * srv = sdns_init_rr_SRV(priority, weight, port, new_target);
    if (NULL == srv){
        free(new_target);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SRV, sdns_q_class_IN, ttl, 0, 1, (void*)srv);
    if (NULL == rr){
        sdns_free_rr_SRV(srv);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        sdns_free_rr_SRV(srv);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_additional_SRV(sdns_context * dns, char * name, uint32_t ttl, 
                           uint16_t priority, uint16_t weight, uint16_t port, char * target){
    
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_target = safe_strdup(target);
    sdns_rr_SRV * srv = sdns_init_rr_SRV(priority, weight, port, new_target);
    if (NULL == srv){
        free(new_target);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SRV, sdns_q_class_IN, ttl, 0, 1, (void*)srv);
    if (NULL == rr){
        sdns_free_rr_SRV(srv);
        free(section_name);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        sdns_free_rr_SRV(srv);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}


int sdns_add_cookie(sdns_context * dns, char * client_cookie, char * server_cookie){
    uint16_t client_len = client_cookie == NULL?0:strlen(client_cookie);
    uint16_t server_len = server_cookie == NULL?0:strlen(server_cookie);
    char * server_mem = NULL;
    char * client_mem = NULL;
    if (client_len != 16){
        return SDNS_ERROR_WRONG_INPUT_PARAMETER;
    }
    client_mem = hex2mem(client_cookie);
    if (client_mem == NULL){
        return SDNS_ERROR_INVALID_HEX_VALUE;
    }
    if (server_cookie != NULL){
        server_mem = hex2mem(server_cookie);
        if (server_mem == NULL){
            free(client_mem);
            return SDNS_ERROR_INVALID_HEX_VALUE;
        }
    }
    sdns_opt_rdata * opt = sdns_create_edns0_cookie(client_mem, server_mem, (int)(server_len/2));
    if (opt == NULL){
        free(server_mem);
        free(client_mem);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_edns(dns, opt);
    // free memory as the library copy them internally
    free(client_mem);
    free(server_mem);
    if (res == 0){
        return res;
    }
    // we failed, clean the fuckin memory
    sdns_free_opt_rdata(opt);
    return res;     // failed
}

int sdns_add_nsid(sdns_context * dns, char * nsid){
    uint16_t  nsid_len = nsid == NULL?0:strlen(nsid);
    if (nsid == NULL){
        // this is just an NSID-aware packet
        sdns_opt_rdata * nsid_opt = sdns_create_edns0_nsid(NULL, 0);
        if (NULL == nsid_opt)
            return SDNS_ERROR_MEMORY_ALLOC_FAILD;
        int res = sdns_add_edns(dns, nsid_opt);
        return res;
    }
    // we have some value for NSID!
    // this case is usually for servers sending their nsid back to the client
    // so nsid can not be empty string
    if (nsid_len == 0)
        return SDNS_ERROR_INVALID_HEX_VALUE;
    //if it's not even->it's not valid
    if (nsid_len % 2 != 0)
        return SDNS_ERROR_INVALID_HEX_VALUE;
    char * nsid_data = hex2mem(nsid);
    if (NULL == nsid_data)
        return SDNS_ERROR_INVALID_HEX_VALUE;
    sdns_opt_rdata * nsid_opt = sdns_create_edns0_nsid(nsid_data, (int)(nsid_len/2));
    if (NULL == nsid_opt){
        free(nsid_data);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    int res = sdns_add_edns(dns, nsid_opt);
    if (res == 0)
        return 0;  // success
    // we failed, we should free the memory
    sdns_free_opt_rdata(nsid_opt);
    return res;     // failed
}


int sdns_set_do(sdns_context * dns, uint8_t do_bit){
    if (NULL == dns || dns->msg == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    // you can only set do if edns0 is enabled
    if (dns->msg->additional == NULL)
        return 1;
    sdns_rr * additional = dns->msg->additional;
    while (additional){
        if (additional->type == sdns_rr_type_OPT){
            additional->opt_ttl.DO = do_bit == 0?0:1;
            return 0;
        }
        additional = additional->next;
    }
    return 1;   //success
}

int sdns_set_tc(sdns_context * dns, uint8_t tc_bit){
    if (NULL == dns || dns->msg == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    dns->msg->header.tc = tc_bit == 0?0:1;
    return 0;   //success
}

int sdns_set_id(sdns_context * dns, uint16_t dns_id){
    if (NULL == dns || dns->msg == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    dns->msg->header.id = dns_id;
    return 0;   //success
}

int sdns_set_rd(sdns_context * dns, uint8_t rd_bit){
    if (NULL == dns || dns->msg == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    dns->msg->header.rd = rd_bit == 0?0:1;
    return 0;   //success
}

int sdns_set_ra(sdns_context * dns, uint8_t ra_bit){
    if (NULL == dns || dns->msg == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    dns->msg->header.ra = ra_bit == 0?0:1;
    return 0;   //success
}

int sdns_set_aa(sdns_context * dns, uint8_t aa_bit){
    if (NULL == dns || dns->msg == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    dns->msg->header.aa = aa_bit == 0?0:1;
    return 0;   //success
}

int sdns_set_cd(sdns_context * dns, uint8_t cd_bit){
    if (NULL == dns || dns->msg == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    dns->msg->header.CD = cd_bit == 0?0:1;
    return 0;   //success
}


int sdns_add_ede(sdns_context * dns, uint16_t ede_code, char * ede_text){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * text_mem = NULL;
    if (ede_text != NULL){
        text_mem = mem_copy(ede_text, strlen(ede_text));
        if (NULL == text_mem){
            return SDNS_ERROR_MEMORY_ALLOC_FAILD;
        }
    }
    sdns_opt_rdata * opt = sdns_create_edns0_ede(ede_code, text_mem, ede_text == NULL?0:strlen(ede_text));
    if (NULL == opt){
        free(text_mem);
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    }
    free(text_mem);
    int res = sdns_add_edns(dns, opt);
    if (res != 0){
        sdns_free_opt_rdata(opt);
        return res;
    }
    return 0;   // success
}

char * sdns_get_value_nsid(sdns_context * dns, int * err, uint16_t *nsid_len){
    *nsid_len = 0;
    if (NULL == dns){
        *err = SDNS_ERROR_BUFFER_IS_NULL;
        return NULL;
    }
    // nsid must appear in the edns0 section of the additional section in DNS packet.
    if (dns->msg->header.arcount == 0){
        *err = SDNS_ERROR_NSID_NOT_FOUND;
        return NULL;
    }
    *err = SDNS_ERROR_NSID_NOT_FOUND;
    char * result = NULL;   // this is what we return

    sdns_rr * tmp = dns->msg->additional;
    do{
        if (tmp->type != sdns_rr_type_OPT){ // only interested in OPT type
            tmp = tmp->next;
            continue;
        }
        // we found OPT type
        if (tmp->rdlength == 0)     // there is nothing to decode!
            break;
        sdns_opt_rdata * opt = NULL;
        if (tmp->decoded)
            opt = tmp->opt_rdata;
        else
            opt = sdns_decode_rr_OPT(dns, tmp);
        if (opt == NULL){
            *err = dns->err == 0?SDNS_ERROR_NSID_NOT_FOUND:dns->err;
            break;
        }
        // we are here-> we successfully get opt pointer
        sdns_opt_rdata * tmp_opt = opt;
        while (tmp_opt){
           if (tmp_opt->option_code != sdns_edns0_option_code_NSID){
                tmp_opt = tmp_opt->next;
                continue;
           }
           // tmp_opt referes to NSID
           result = tmp_opt->option_data == NULL?NULL:mem_copy(tmp_opt->option_data, tmp_opt->option_length);
           *err = tmp_opt->option_data == NULL?SDNS_ERROR_NSID_NOT_FOUND:0;
           *nsid_len = tmp_opt->option_data == NULL?0:tmp_opt->option_length;
           break;
        }
       if (tmp->decoded == 0)
           sdns_free_opt_rdata(opt);
        // we can have only one OPT in a DNS packet, so we have to return
        break;
    }while(tmp);
    return result;
}


char * sdns_get_value_cookie_client(sdns_context * dns, int * err){
    if (NULL == dns){
        *err = SDNS_ERROR_BUFFER_IS_NULL;
        return NULL;
    }
    // client cookie must appear in the edns0 section of the additional section in DNS packet.
    if (dns->msg->header.arcount == 0){
        *err = SDNS_ERROR_CLIENT_COOKIE_NOT_FOUND;
        return NULL;
    }
    *err = SDNS_ERROR_CLIENT_COOKIE_NOT_FOUND;
    char * result = NULL;   // this is what we return

    sdns_rr * tmp = dns->msg->additional;
    do{
        if (tmp->type != sdns_rr_type_OPT){ // only interested in OPT type
            tmp = tmp->next;
            continue;
        }
        // we found OPT type
        if (tmp->rdlength == 0)     // there is nothing to decode!
            break;
        sdns_opt_rdata * opt = NULL;
        if (tmp->decoded)
            opt = tmp->opt_rdata;
        else
            opt = sdns_decode_rr_OPT(dns, tmp);
        if (opt == NULL){
            *err = dns->err == 0?SDNS_ERROR_CLIENT_COOKIE_NOT_FOUND:dns->err;
            break;
        }
        // we are here-> we successfully get opt pointer
        sdns_opt_rdata * tmp_opt = opt;
        while (tmp_opt){
           if (tmp_opt->option_code != sdns_edns0_option_code_COOKIE){
                tmp_opt = tmp_opt->next;
                continue;
           }
           // tmp_opt referes to cookie
           if (tmp_opt->option_length < 8){
                // we don't have (a valid!) client cookie
                break;
           }
           result = tmp_opt->option_data == NULL?NULL:mem_copy(tmp_opt->option_data, 8);    // exactly 8 bytes
           *err = tmp_opt->option_data == NULL?SDNS_ERROR_CLIENT_COOKIE_NOT_FOUND:0;
           break;
        }
       if (tmp->decoded == 0)
           sdns_free_opt_rdata(opt);
        // we can have only one OPT in a DNS packet, so we have to return
        break;
    }while(tmp);
    return result;

}

