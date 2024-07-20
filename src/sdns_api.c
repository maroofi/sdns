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
    char * section_name = safe_strdup(name); 
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_A, sdns_q_class_IN, ttl, 0, 1, (void*) a);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_A, sdns_q_class_IN, ttl, 0, 1, (void*) a);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_A, sdns_q_class_IN, ttl, 0, 1, (void*) a);
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
    char * new_name = safe_strdup(nsname);
    sdns_rr_NS * ns  = sdns_init_rr_NS(new_name);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NS, sdns_q_class_IN, ttl, 0, 1, (void*) ns);
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
    char * new_name = safe_strdup(nsname);
    sdns_rr_NS * ns  = sdns_init_rr_NS(new_name);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NS, sdns_q_class_IN, ttl, 0, 1, (void*) ns);
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
    char * new_name = safe_strdup(nsname);
    sdns_rr_NS * ns  = sdns_init_rr_NS(new_name);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NS, sdns_q_class_IN, ttl, 0, 1, (void*) ns);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_TXT, sdns_q_class_IN, ttl, 0, 1, (void*) txt);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_TXT, sdns_q_class_IN, ttl, 0, 1, (void*) txt);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_TXT, sdns_q_class_IN, ttl, 0, 1, (void*) txt);
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_TXT(txt);
        return res;
    }
    return 0;  //success
}

int sdns_remove_edns(sdns_context * dns){
    // this function remove edns0 (type OPT) from a packet if exists
    if (dns == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    sdns_rr* additional = dns->msg->additional;
    if (NULL == additional)    // there is nothing to remove
        return 0;
    sdns_rr * tmp = additional;
    int found = 0;
    while(additional){
        if (additional->type == sdns_rr_type_OPT){
            found = 1;
            break;
        }
        if (tmp != additional){
            tmp = additional;
        }
        additional = additional->next;
    }
    if (found == 1){
        // we have found an OPT record and 'additional' points to it. 
        // 'tmp' points to the previous rr of additional section
        // link previous to next one
        tmp->next = additional->next;
        if (tmp == additional){
            // this is the first record
            dns->msg->additional = tmp->next;
        }
        // now we need to free additional
        free(additional->name);
        additional->next = NULL;
        // we need to reduce the arcount  in the header as well
        dns->msg->header.arcount -= 1;
        if (additional->decoded == 1){
            sdns_opt_rdata * opt = additional->opt_rdata;
            sdns_opt_rdata * tmpopt = opt;
            while (opt){
                free(opt->option_data);
                tmpopt = opt->next;
                free(opt);
                opt = tmpopt;
            }
            free(additional);
        }else{
            free(additional->rdata);
            free(additional);
        }
    }else{
        // we don't have OPT record. Let's return
        return 0;
    }
    return 0;  // success
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
    char * new_mname = safe_strdup(mname);
    char * new_rname = safe_strdup(rname);
    
    sdns_rr_SOA * soa = sdns_init_rr_SOA(new_mname, new_rname, expire, minimum, refresh, retry, serial);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SOA, sdns_q_class_IN, ttl, 0, 1, (void*) soa);
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
    char * new_mname = safe_strdup(mname);
    char * new_rname = safe_strdup(rname);
    
    sdns_rr_SOA * soa = sdns_init_rr_SOA(new_mname, new_rname, expire, minimum, refresh, retry, serial);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SOA, sdns_q_class_IN, ttl, 0, 1, (void*) soa);
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
    char * new_mname = safe_strdup(mname);
    char * new_rname = safe_strdup(rname);
    
    sdns_rr_SOA * soa = sdns_init_rr_SOA(new_mname, new_rname, expire, minimum, refresh, retry, serial);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SOA, sdns_q_class_IN, ttl, 0, 1, (void*) soa);
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
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_CNAME, sdns_q_class_IN, ttl, 0, 1, (void*) cn);
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
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_CNAME, sdns_q_class_IN, ttl, 0, 1, (void*) cn);
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
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_CNAME, sdns_q_class_IN, ttl, 0, 1, (void*) cn);
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        sdns_free_rr_CNAME(cn);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;  //success
}

int sdns_add_rr_answer_NID(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * nodeid){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (nodeid == NULL){
        return SDNS_ERROR_BUFFER_IS_NULL;
    }
    char * new_nodeid = mem_copy(nodeid, 8);
    sdns_rr_NID * nid = sdns_init_rr_NID(preference, new_nodeid);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NID, sdns_q_class_IN, ttl, 0, 1, (void*) nid);
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        sdns_free_rr_NID(nid);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_authority_NID(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * nodeid){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (nodeid == NULL){
        return SDNS_ERROR_BUFFER_IS_NULL;
    }
    char * new_nodeid = mem_copy(nodeid, 8);
    sdns_rr_NID * nid = sdns_init_rr_NID(preference, new_nodeid);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NID, sdns_q_class_IN, ttl, 0, 1, (void*) nid);
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        sdns_free_rr_NID(nid);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_additional_NID(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * nodeid){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (nodeid == NULL){
        return SDNS_ERROR_BUFFER_IS_NULL;
    }
    char * new_nodeid = mem_copy(nodeid, 8);
    sdns_rr_NID * nid = sdns_init_rr_NID(preference, new_nodeid);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_NID, sdns_q_class_IN, ttl, 0, 1, (void*) nid);
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        sdns_free_rr_NID(nid);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_answer_MX(sdns_context * dns, char * name, uint32_t ttl, uint16_t preference, char * exchange){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_exchange = safe_strdup(exchange);
    sdns_rr_MX * mx = sdns_init_rr_MX(preference, new_exchange);
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_MX, sdns_q_class_IN, ttl, 0, 1, (void*) mx);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_MX, sdns_q_class_IN, ttl, 0, 1, (void*) mx);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_MX, sdns_q_class_IN, ttl, 0, 1, (void*) mx);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_PTR, sdns_q_class_IN, ttl, 0, 1, (void*)ptr);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_PTR, sdns_q_class_IN, ttl, 0, 1, (void*)ptr);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_PTR, sdns_q_class_IN, ttl, 0, 1, (void*)ptr);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SRV, sdns_q_class_IN, ttl, 0, 1, (void*)srv);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SRV, sdns_q_class_IN, ttl, 0, 1, (void*)srv);
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
    char * section_name = safe_strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_SRV, sdns_q_class_IN, ttl, 0, 1, (void*)srv);
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        sdns_free_rr_SRV(srv);
        free(rr->name);
        free(rr);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_answer_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                                 char * os, uint8_t os_len, char* cpu, uint8_t cpu_len){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_os = NULL;
    char * new_cpu = NULL;
    if (os_len > 0 && os == NULL)
        return SDNS_ERROR_WRONG_INPUT_PARAMETER;
    if (cpu_len > 0 && cpu == NULL)
        return SDNS_ERROR_WRONG_INPUT_PARAMETER;
    if (cpu_len > 0 && cpu != NULL)
        new_cpu = mem_copy(cpu, cpu_len);
    if (os_len > 0 && os != NULL)
        new_os = mem_copy(os, os_len);
    
    sdns_rr_HINFO * hinfo  = sdns_init_rr_HINFO(cpu_len, new_cpu, os_len, new_os);
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_HINFO, sdns_q_class_IN, ttl, 0, 1, (void*) hinfo);
    int res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_HINFO(hinfo);
        return res;
    }
    return 0;   //success
}

int sdns_add_rr_authority_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                                 char * os, uint8_t os_len, char* cpu, uint8_t cpu_len){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_os = NULL;
    char * new_cpu = NULL;
    if (os_len > 0 && os == NULL)
        return SDNS_ERROR_WRONG_INPUT_PARAMETER;
    if (cpu_len > 0 && cpu == NULL)
        return SDNS_ERROR_WRONG_INPUT_PARAMETER;
    if (cpu_len > 0 && cpu != NULL)
        new_cpu = mem_copy(cpu, cpu_len);
    if (os_len > 0 && os != NULL)
        new_os = mem_copy(os, os_len);
    
    sdns_rr_HINFO * hinfo  = sdns_init_rr_HINFO(cpu_len, new_cpu, os_len, new_os);
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_HINFO, sdns_q_class_IN, ttl, 0, 1, (void*) hinfo);
    int res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_HINFO(hinfo);
        return res;
    }
    return 0;   //success
}


int sdns_add_rr_additional_HINFO(sdns_context * dns, char * name, uint32_t ttl,
                                 char * os, uint8_t os_len, char* cpu, uint8_t cpu_len){
    if (NULL == dns)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * new_os = NULL;
    char * new_cpu = NULL;
    if (os_len > 0 && os == NULL)
        return SDNS_ERROR_WRONG_INPUT_PARAMETER;
    if (cpu_len > 0 && cpu == NULL)
        return SDNS_ERROR_WRONG_INPUT_PARAMETER;
    if (cpu_len > 0 && cpu != NULL)
        new_cpu = mem_copy(cpu, cpu_len);
    if (os_len > 0 && os != NULL)
        new_os = mem_copy(os, os_len);
    
    sdns_rr_HINFO * hinfo  = sdns_init_rr_HINFO(cpu_len, new_cpu, os_len, new_os);
    if (name == NULL){
        return SDNS_ERROR_BUFFER_IS_NULL;
    }
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_HINFO, sdns_q_class_IN, ttl, 0, 1, (void*) hinfo);
    int res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_HINFO(hinfo);
        return res;
    }
    return 0;   //success
}

int sdns_add_rr_answer_AAAA(sdns_context * dns, char * name, uint32_t ttl, const char * ipv6){
    unsigned char ipv6_parsed[16] = {0x00};
    int res = parse_IPv6(&ipv6, ipv6_parsed);
    if (res == 0){
        return SDNS_ERROR_INVALID_IPv6_FOUND;
    }
    if (name == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr_AAAA * aaaa = sdns_init_rr_AAAA((char*) mem_copy((char*)ipv6_parsed, 16));
    
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_AAAA, sdns_q_class_IN, ttl, 0, 1, (void*)aaaa);
    res = sdns_add_answer_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_AAAA(aaaa);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_authority_AAAA(sdns_context * dns, char * name, uint32_t ttl, const char * ipv6){
    unsigned char ipv6_parsed[16] = {0x00};
    int res = parse_IPv6(&ipv6, ipv6_parsed);
    if (res == 0){
        return SDNS_ERROR_INVALID_IPv6_FOUND;
    }
    if (name == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr_AAAA * aaaa = sdns_init_rr_AAAA((char*) mem_copy((char*)ipv6_parsed, 16));
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_AAAA, sdns_q_class_IN, ttl, 0, 1, (void*)aaaa);
    res = sdns_add_authority_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_AAAA(aaaa);
        return res;
    }
    return 0;   // success
}

int sdns_add_rr_additional_AAAA(sdns_context * dns, char * name, uint32_t ttl, const char * ipv6){
    unsigned char ipv6_parsed[16] = {0x00};
    int res = parse_IPv6(&ipv6, ipv6_parsed);
    if (res == 0){
        return SDNS_ERROR_INVALID_IPv6_FOUND;
    }
    if (name == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    char * section_name = name == NULL?NULL:strdup(name);
    sdns_rr_AAAA * aaaa = sdns_init_rr_AAAA((char*) mem_copy((char*)ipv6_parsed, 16));
    sdns_rr * rr = sdns_init_rr(section_name, sdns_rr_type_AAAA, sdns_q_class_IN, ttl, 0, 1, (void*)aaaa);
    res = sdns_add_additional_section(dns, rr);
    if (res != 0){
        free(rr->name);
        free(rr);
        sdns_free_rr_AAAA(aaaa);
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
    return 0;   //success
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

sdns_rr * sdns_get_answer(sdns_context * dns, int * err, uint16_t num){
    if (dns == NULL){
        *err = SDNS_ERROR_BUFFER_IS_NULL;
        return NULL;
    }
    if (num + 1 > dns->msg->header.ancount || dns->msg->answer == NULL){
        *err = SDNS_ERROR_NO_ANSWER_FOUND;
        return NULL;
    }
    sdns_rr * tmp = NULL;
    sdns_rr * answer = dns->msg->answer;
    uint16_t cnt = 0;
    while(answer){
        tmp = answer;
        if (cnt >= num)
            break;
        cnt++;
        answer = answer->next;
    }
    if (tmp == NULL){  // there is no answer numero 'num+1'
        *err = SDNS_ERROR_NO_ANSWER_FOUND;
        return NULL;
    }
    // tmp points the the right answer
    char * name = safe_strdup(tmp->name);
    sdns_rr * result = sdns_init_rr(name, tmp->type, tmp->class, tmp->ttl, tmp->rdlength, 1, NULL);
    void * rdata = NULL;
    if (tmp->decoded){
        rdata = sdns_copy_rr_section(dns, tmp);
    }else{
        rdata = sdns_decode_rr_section(dns, tmp);
    }
    if (rdata == NULL){
        // we can not decode it
        free(result->name);
        free(result);
        *err = SDNS_ERROR_CAN_NOT_READ_SECTION;
        return NULL;
    }
    result->psdns_rr = rdata;
    *err = sdns_rcode_NoError;
    return result;
}

sdns_rr * sdns_get_authority(sdns_context * dns, int * err, uint16_t num){
    if (dns == NULL){
        *err = SDNS_ERROR_BUFFER_IS_NULL;
        return NULL;
    }
    if (num + 1 > dns->msg->header.nscount || dns->msg->authority == NULL){
        *err = SDNS_ERROR_NO_AUTHORITY_FOUND;
        return NULL;
    }
    sdns_rr * tmp = NULL;
    sdns_rr * authority = dns->msg->authority;
    uint16_t cnt = 0;
    while(authority){
        tmp = authority;
        if (cnt >= num)
            break;
        cnt++;
        authority = authority->next;
    }
    if (tmp == NULL){  // there is no authority numero 'num+1'
        *err = SDNS_ERROR_NO_AUTHORITY_FOUND;
        return NULL;
    }
    // tmp points the the right authority
    char * name = safe_strdup(tmp->name);
    sdns_rr * result = sdns_init_rr(name, tmp->type, tmp->class, tmp->ttl, tmp->rdlength, 1, NULL);
    void * rdata = NULL;
    if (tmp->decoded){
        rdata = sdns_copy_rr_section(dns, tmp);
    }else{
        rdata = sdns_decode_rr_section(dns, tmp);
    }
    if (rdata == NULL){
        // we can not decode it
        free(result->name);
        free(result);
        *err = SDNS_ERROR_CAN_NOT_READ_SECTION;
        return NULL;
    }
    result->psdns_rr = rdata;
    *err = sdns_rcode_NoError;
    return result;
}


sdns_rr * sdns_get_additional(sdns_context * dns, int * err, uint16_t num){
    if (dns == NULL){
        *err = SDNS_ERROR_BUFFER_IS_NULL;
        return NULL;
    }
    if (num + 1 > dns->msg->header.arcount || dns->msg->additional == NULL){
        *err = SDNS_ERROR_NO_ADDITIONAL_FOUND;
        return NULL;
    }
    sdns_rr * tmp = NULL;
    sdns_rr * additional = dns->msg->additional;
    uint16_t cnt = 0;
    while(additional){
        tmp = additional;
        if (cnt >= num)
            break;
        cnt++;
        additional = additional->next;
    }
    if (tmp == NULL){  // there is no additional numero 'num+1'
        *err = SDNS_ERROR_NO_ADDITIONAL_FOUND;
        return NULL;
    }
    // tmp points the the right additional
    char * name = safe_strdup(tmp->name);
    sdns_rr * result = sdns_init_rr(name, tmp->type, tmp->class, tmp->ttl, tmp->rdlength, 1, NULL);
    void * rdata = NULL;
    if (tmp->decoded){
        rdata = sdns_copy_rr_section(dns, tmp);
    }else{
        rdata = sdns_decode_rr_section(dns, tmp);
    }
    if (rdata == NULL){
        // we can not decode it
        free(result->name);
        free(result);
        *err = SDNS_ERROR_CAN_NOT_READ_SECTION;
        return NULL;
    }
    result->psdns_rr = rdata;
    *err = sdns_rcode_NoError;
    return result;
}

