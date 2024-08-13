#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sdns.h>
#include <sdns_json.h>
#include <sdns_utils.h>

char * sdns_json_dns_string(sdns_context * ctx){
    json_t * d = sdns_json_dns(ctx);
    if (NULL == d)
        return NULL;
    char * tmp = json_dumps(d, 0);
    json_decref(d);
    return tmp;
}

json_t * sdns_json_dns(sdns_context * ctx){
    json_t * header = sdns_json_header(ctx);
    if (NULL == header)
        return NULL;
    json_t * question = sdns_json_question(ctx);
    if (NULL == question){
        json_decref(header);
        return NULL;
    }
    json_t * dns = json_object();
    if (json_object_set_new(dns, "header", header) != 0){
        json_decref(header);
        json_decref(question);
        json_decref(dns);
        return NULL;
    }
    if (json_object_set_new(dns, "question", question) != 0){
        json_decref(header);
        json_decref(question);
        json_decref(dns);
        return NULL;
    }
    json_t * answer = sdns_json_answer(ctx);
    if (NULL != answer){
        if(json_object_set_new(dns, "answer", answer) != 0){
            json_decref(header);
            json_decref(question);
            json_decref(answer);
            json_decref(dns);
            return NULL;
        }
    }else{
        if (json_object_set_new(dns, "answer", json_array()) != 0){
            json_decref(header);
            json_decref(question);
            json_decref(dns);
            return NULL;
        }
    }
    json_t * authority = sdns_json_authority(ctx);
    if (NULL != authority){
        if(json_object_set_new(dns, "authority", authority) != 0){
            json_decref(header);
            json_decref(question);
            json_decref(answer);
            json_decref(authority);
            json_decref(dns);
            return NULL;
        }
    }else{
        if (json_object_set_new(dns, "authority", json_array()) != 0){
            json_decref(header);
            json_decref(question);
            json_decref(answer);
            json_decref(dns);
            return NULL;
        }
    }

    json_t * additional = sdns_json_additional(ctx);
    if (NULL != additional){
        if(json_object_set_new(dns, "additional", additional) != 0){
            json_decref(header);
            json_decref(question);
            json_decref(answer);
            json_decref(authority);
            json_decref(additional);
            json_decref(dns);
            return NULL;
        }
    }else{
        if (json_object_set_new(dns, "authority", json_array()) != 0){
            json_decref(header);
            json_decref(question);
            json_decref(answer);
            json_decref(dns);
            json_decref(authority);
            return NULL;
        }
    }
    return dns;
}


json_t * sdns_json_header(sdns_context * ctx){
    /**
     * ID: 45298,  qr: 1,  opcode: 0, "flags": {aa: 0,  tc: 0,  rd: 1,  ra: 1
     * z: 0,  AD: 0,  CD: 0,  rcode: NoError  qdcount: 1,  ancount: 1,  arcount: 0,  nscount: 0
     * {"ID": 6546, "qr": 1, "opcode": 0, "aa": 0, "tc": 0, "rd": 1, "ra": 1,
     *  "z": 0, "ad": 0, "cd": 0, "rcode": "NoError", "qdcount": 1, "ancount": 1, "arcount": 0, "nscount": 0}
     */
    if (NULL == ctx)
        return NULL;
    
    char *error_buffer  = NULL; // we have to free it
    sdns_error_string(ctx->msg->header.rcode, &error_buffer);
    json_t * header = json_object();
    json_t * flags = NULL;
    while(1){
        if (NULL == header){return NULL;}
        if (json_object_set_new(header, "ID", json_integer(ctx->msg->header.id)) != 0)
            break;
        if (json_object_set_new(header, "opcode", json_integer(ctx->msg->header.opcode)) != 0)
            break;
        if (json_object_set_new(header, "rcode", json_string(error_buffer)) != 0)
            break;
        if (json_object_set_new(header, "qdcount", json_integer(ctx->msg->header.qdcount)) != 0)
            break;
        if (json_object_set_new(header, "ancount", json_integer(ctx->msg->header.ancount)) != 0)
            break;
        if (json_object_set_new(header, "arcount", json_integer(ctx->msg->header.arcount)) != 0)
            break;
        if (json_object_set_new(header, "nscount", json_integer(ctx->msg->header.nscount)) != 0)
            break;
        flags = json_object();
        if (NULL == flags)
            break;
        if (json_object_set_new(flags, "qr", json_integer(ctx->msg->header.qr)) != 0)
            break;
        if (json_object_set_new(flags, "aa", json_integer(ctx->msg->header.aa))  != 0)
            break;
        if (json_object_set_new(flags, "tc", json_integer(ctx->msg->header.tc))  != 0)
            break;
        if (json_object_set_new(flags, "rd", json_integer(ctx->msg->header.rd))  != 0)
            break;
        if (json_object_set_new(flags, "ra", json_integer(ctx->msg->header.ra))  != 0)
            break;
        if (json_object_set_new(flags, "z", json_integer(ctx->msg->header.z))  != 0)
            break;
        if (json_object_set_new(flags, "AD", json_integer(ctx->msg->header.AD))  != 0)
            break;
        if (json_object_set_new(flags, "CD", json_integer(ctx->msg->header.CD))  != 0)
            break;
        if (json_object_set_new(header, "flags", flags) != 0)
            break;
        free(error_buffer);
        return header;
    }
    // if we are here there is an error
    json_decref(header);
    if (NULL != flags)
        json_decref(flags);
    free(error_buffer);
    return NULL;
}


json_t* sdns_json_question(sdns_context * ctx){
    /**
     * {"qname": "aaaaaa", "qclass": "", "qtype":""}
     */
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_class_to_string(ctx->msg->question.qclass, buff_class);
    sdns_rr_type_to_string(ctx->msg->question.qtype, buff_type);
    if (NULL == ctx)
        return NULL;
    json_t * question = json_object();
    if (NULL == question)
        return NULL;
    if (json_object_set_new(question, "qname", json_string(ctx->msg->question.qname)) != 0){
        json_decref(question);
        return NULL;
    }
    if (json_object_set_new(question, "qclass", json_string(buff_class)) != 0){
        json_decref(question);
        return NULL;
    }
    if (json_object_set_new(question, "qtype", json_string(buff_type)) != 0){
        json_decref(question);
        return NULL;
    }
    return question;
}

json_t * sdns_json_answer(sdns_context * ctx){
    if (NULL == ctx)
        return NULL;
    json_t * answers = json_array();
    if (NULL == answers)
        return NULL;
    sdns_rr * tmp = ctx->msg->answer;
    if (tmp == NULL){
        return answers;
    }
    char buff_class[20];
    char buff_type[20];
    while (tmp){
        json_t * tmp_answer = json_object();
        if (NULL == tmp_answer)
            return answers;
        
        if (json_object_set_new(tmp_answer, "name", json_string(tmp->name)) != 0){
            json_decref(tmp_answer);
            return answers;
        }
        memset(buff_class, 0, 20);
        memset(buff_type, 0, 20);
        sdns_class_to_string(tmp->class, buff_class);
        sdns_rr_type_to_string(tmp->type, buff_type);
        
        if (json_object_set_new(tmp_answer, "class", json_string(buff_class)) != 0){
            json_decref(tmp_answer);
            return answers;
        }
        if (json_object_set_new(tmp_answer, "type", json_string(buff_type)) != 0){
            json_decref(tmp_answer);
            return answers;
        }
        if (json_object_set_new(tmp_answer, "ttl", json_integer(tmp->ttl)) != 0){
            json_decref(tmp_answer);
            return answers;
        }
        
        if (json_object_set_new(tmp_answer, "rdlength", json_integer(tmp->rdlength)) != 0){
            json_decref(tmp_answer);
            return answers;
        }
        json_t * rdata = sdns_json_rr(ctx, tmp);
        if (rdata != NULL){
            if (json_object_set_new(tmp_answer, "rdata", rdata) != 0){
                json_decref(rdata);
                return answers;
            }
        }
        if (json_array_append_new(answers, tmp_answer) != 0){
            json_decref(tmp_answer);
            return answers;
        }
        tmp = tmp->next;
    }
    return answers;
}

json_t * sdns_json_authority(sdns_context * ctx){
    if (NULL == ctx)
        return NULL;
    json_t * authorities = json_array();
    if (NULL == authorities)
        return NULL;
    sdns_rr * tmp = ctx->msg->authority;
    if (tmp == NULL){
        return authorities;
    }
    char buff_class[20];
    char buff_type[20];
    while (tmp){
        json_t * tmp_authority = json_object();
        if (NULL == tmp_authority)
            return authorities;
        
        if (json_object_set_new(tmp_authority, "name", json_string(tmp->name)) != 0){
            json_decref(tmp_authority);
            return authorities;
        }
        memset(buff_class, 0, 20);
        memset(buff_type, 0, 20);
        sdns_class_to_string(tmp->class, buff_class);
        sdns_rr_type_to_string(tmp->type, buff_type);
        
        if (json_object_set_new(tmp_authority, "class", json_string(buff_class)) != 0){
            json_decref(tmp_authority);
            return authorities;
        }
        if (json_object_set_new(tmp_authority, "type", json_string(buff_type)) != 0){
            json_decref(tmp_authority);
            return authorities;
        }
        if (json_object_set_new(tmp_authority, "ttl", json_integer(tmp->ttl)) != 0){
            json_decref(tmp_authority);
            return authorities;
        }
        
        if (json_object_set_new(tmp_authority, "rdlength", json_integer(tmp->rdlength)) != 0){
            json_decref(tmp_authority);
            return authorities;
        }

        json_t * rdata = sdns_json_rr(ctx, tmp);
        if (rdata != NULL){
            if (json_object_set_new(tmp_authority, "rdata", rdata) != 0){
                json_decref(rdata);
                return authorities;
            }
        }
        if (json_array_append_new(authorities, tmp_authority) != 0){
            json_decref(tmp_authority);
            return authorities;
        }
        tmp = tmp->next;
    }
    return authorities;
}

json_t * sdns_json_additional(sdns_context * ctx){
    if (NULL == ctx)
        return NULL;
    json_t * additionals = json_array();
    if (NULL == additionals)
        return NULL;
    sdns_rr * tmp = ctx->msg->additional;
    if (tmp == NULL){
        return additionals;
    }
    char buff_class[20];
    char buff_type[20];
    while (tmp){
        // we use another method for EDNS0
        if (tmp->type == sdns_rr_type_OPT){
            // json-ize it, append it and continue
            json_t * tmp_additional = sdns_json_rr_OPT(ctx, tmp);
            if (tmp_additional != NULL){
                if (json_array_append_new(additionals, tmp_additional) != 0){
                    json_decref(tmp_additional);
                    return additionals;
                }
                tmp = tmp->next;
                continue;
            }else{
                // for now just continue
                tmp = tmp->next;
                continue;
            }
        }
        // it's a normal RR, so we continue this method
        json_t * tmp_additional = json_object();
        if (NULL == tmp_additional)
            return additionals;

        if (json_object_set_new(tmp_additional, "name", json_string(tmp->name)) != 0){
            json_decref(tmp_additional);
            return additionals;
        }
        memset(buff_class, 0, 20);
        memset(buff_type, 0, 20);
        sdns_class_to_string(tmp->class, buff_class);
        sdns_rr_type_to_string(tmp->type, buff_type);
        
        if (json_object_set_new(tmp_additional, "class", json_string(buff_class)) != 0){
            json_decref(tmp_additional);
            return additionals;
        }
        if (json_object_set_new(tmp_additional, "type", json_string(buff_type)) != 0){
            json_decref(tmp_additional);
            return additionals;
        }
        if (json_object_set_new(tmp_additional, "ttl", json_integer(tmp->ttl)) != 0){
            json_decref(tmp_additional);
            return additionals;
        }
        
        if (json_object_set_new(tmp_additional, "rdlength", json_integer(tmp->rdlength)) != 0){
            json_decref(tmp_additional);
            return additionals;
        }
        json_t * rdata = sdns_json_rr(ctx, tmp);
        if (rdata != NULL){
            if (json_object_set_new(tmp_additional, "rdata", rdata) != 0){
                json_decref(rdata);
                return additionals;
            }
        }
        if (json_array_append_new(additionals, tmp_additional) != 0){
            json_decref(tmp_additional);
            return additionals;
        }
        tmp = tmp->next;
    }
    return additionals;
}

json_t * sdns_json_rr(sdns_context * ctx, sdns_rr * rr){
    if (NULL == rr || ctx == NULL)
        return NULL;
    if (rr->type == sdns_rr_type_A)
        return sdns_json_rr_A(ctx, rr);
    if (rr->type == sdns_rr_type_NS)
        return sdns_json_rr_NS(ctx, rr);
    if (rr->type == sdns_rr_type_PTR)
        return sdns_json_rr_PTR(ctx, rr);
    if (rr->type == sdns_rr_type_CNAME)
        return sdns_json_rr_CNAME(ctx, rr);
    if (rr->type == sdns_rr_type_TXT)
        return sdns_json_rr_TXT(ctx, rr);
    if (rr->type == sdns_rr_type_SOA)
        return sdns_json_rr_SOA(ctx, rr);
    if (rr->type == sdns_rr_type_MX)
        return sdns_json_rr_MX(ctx, rr);
    if (rr->type == sdns_rr_type_NID)
        return sdns_json_rr_NID(ctx, rr);
    if (rr->type == sdns_rr_type_L32)
        return sdns_json_rr_L32(ctx, rr);
    if (rr->type == sdns_rr_type_L64)
        return sdns_json_rr_L64(ctx, rr);
    if (rr->type == sdns_rr_type_LP)
        return sdns_json_rr_LP(ctx, rr);
    if (rr->type == sdns_rr_type_CAA)
        return sdns_json_rr_CAA(ctx, rr);
    if (rr->type == sdns_rr_type_OPT)
        return sdns_json_rr_OPT(ctx, rr);
    if (rr->type == sdns_rr_type_RRSIG)
        return sdns_json_rr_RRSIG(ctx, rr);
    if (rr->type == sdns_rr_type_SRV)
        return sdns_json_rr_SRV(ctx, rr);
    if (rr->type == sdns_rr_type_URI)
        return sdns_json_rr_URI(ctx, rr);
    if (rr->type == sdns_rr_type_HINFO)
        return sdns_json_rr_HINFO(ctx, rr);
    if (rr->type == sdns_rr_type_AAAA)
        return sdns_json_rr_AAAA(ctx, rr);
    //TODO: ADD more json stuff here
    // if it's not implemented, print rr as a general case
    return NULL;
}

json_t * sdns_json_rr_A(sdns_context * ctx, sdns_rr *rr){
    sdns_rr_A * a = NULL;
    if (rr->decoded){
        a = (sdns_rr_A*)rr->psdns_rr;
    }else{
        a = sdns_decode_rr_A(ctx, rr);
    }
    if (NULL == a){return NULL;}
    char ipaddress[20] = {0x00};
    cipv4_uint_to_str(a->address, ipaddress);
    if (rr->decoded == 0)
        sdns_free_rr_A(a);
    json_t * obj = json_object();
    if (obj == NULL)
        return NULL;
    if (json_object_set_new(obj, "address", json_string(ipaddress)) != 0){
        json_decref(obj);
        return NULL;
    }
    return obj;
}

json_t * sdns_json_rr_AAAA(sdns_context * ctx, sdns_rr *rr){
    sdns_rr_AAAA * aaaa = NULL;
    if (rr->decoded)
        aaaa = (sdns_rr_AAAA *) rr->psdns_rr;
    else
        aaaa = sdns_decode_rr_AAAA(ctx, rr);
    if (NULL == aaaa){return NULL;}
    if (NULL == aaaa->address){return NULL;}
    char * ip_str = ipv6_mem_to_str(aaaa->address);
    json_t * addr = json_string(ip_str);
    free(ip_str);
    if (rr->decoded == 0)
        sdns_free_rr_AAAA(aaaa);
    json_t * obj = json_object();
    if (obj == NULL){
        json_decref(addr);
        return NULL;
    }
    if (json_object_set_new(obj, "address", addr) != 0){
        json_decref(obj);
        return NULL;
    }
    return obj;
}

json_t * sdns_json_rr_CNAME(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr)
        return NULL;
    sdns_rr_CNAME * cname = NULL;
    if (rr->decoded)
        cname = rr->psdns_rr;
    else
        cname = sdns_decode_rr_CNAME(ctx, rr);
    if (cname == NULL)
        return NULL;
    json_t * cn = json_string(cname->CNAME);
    if (rr->decoded == 0)
        sdns_free_rr_CNAME(cname);
    json_t * obj = json_object();
    if (obj == NULL){
        json_decref(cn);
        return NULL;
    }
    if (json_object_set_new(obj, "cname", cn) != 0){
        json_decref(cn);
        json_decref(obj);
        return NULL;
    }
    return obj;
}



json_t * sdns_json_rr_MX(sdns_context * ctx, sdns_rr *rr){
    if (ctx == NULL || rr == NULL)
        return NULL;
    sdns_rr_MX * mx = NULL;
    if (rr->decoded)
        mx = (sdns_rr_MX*)rr->psdns_rr;
    else
        mx = sdns_decode_rr_MX(ctx, rr);
    if (NULL == mx)
        return NULL;
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_MX(mx);
        return NULL;
    }
    if (json_object_set_new(obj, "exchange", json_string(mx->exchange)) != 0){
        json_decref(obj);
        if (rr->decoded == 0)
            sdns_free_rr_MX(mx);
        return NULL;
    }
    if (json_object_set_new(obj, "preference", json_integer(mx->preference)) != 0){
        json_decref(obj);
        if (rr->decoded == 0)
            sdns_free_rr_MX(mx);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_MX(mx);
    return obj;
}


json_t * sdns_json_rr_SOA(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_SOA * soa = NULL;
    if (rr->decoded)
        soa = rr->psdns_rr;
    else
        soa = sdns_decode_rr_SOA(ctx, rr);
    if (NULL == soa)
        return NULL;
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_SOA(soa);
        return NULL;
    }
    if (json_object_set_new(obj, "expire", json_integer(soa->expire)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SOA(soa);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "minimum", json_integer(soa->minimum)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SOA(soa);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "refresh", json_integer(soa->refresh)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SOA(soa);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "retry", json_integer(soa->retry)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SOA(soa);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "serial", json_integer(soa->serial)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SOA(soa);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "mname", json_string(soa->mname)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SOA(soa);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "rname", json_string(soa->rname)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SOA(soa);
        json_decref(obj);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_SOA(soa);
    return obj;
}

json_t * sdns_json_rr_NS(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_NS * ns = NULL;
    if (rr->decoded)
        ns = rr->psdns_rr;
    else
        ns = sdns_decode_rr_NS(ctx, rr);
    if (NULL == ns)
        return NULL;
    json_t * name = json_string(ns->NSDNAME);
    if (NULL == name){
        if (rr->decoded == 0)
            sdns_free_rr_NS(ns);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_NS(ns);
    json_t * obj = json_object();
    if (obj == NULL){
        json_decref(name);
        return NULL;
    }
    if (json_object_set_new(obj, "nsdname", name) != 0){
        json_decref(obj);
        json_decref(name);
        return NULL;
    }
    return obj;
}

json_t * sdns_json_rr_HINFO(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_HINFO * hinfo = NULL;
    if (rr->decoded)
        hinfo = rr->psdns_rr;
    else
        hinfo = sdns_decode_rr_HINFO(ctx, rr);
    if (NULL == hinfo)
        return NULL;
    
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_HINFO(hinfo);
        return NULL;
    }
    if (hinfo->cpu != NULL){
        char * cpu = mem2hex(hinfo->cpu, hinfo->cpu_len);
        if (json_object_set_new(obj, "cpu", json_stringn(cpu, hinfo->cpu_len * 2)) != 0){
            if (rr->decoded == 0)
                sdns_free_rr_HINFO(hinfo);
            json_decref(obj);
            free(cpu);
            return NULL;
        }
        free(cpu);
    }else{
        if (json_object_set_new(obj, "cpu", json_string("")) != 0){
            if (rr->decoded == 0)
                sdns_free_rr_HINFO(hinfo);
            json_decref(obj);
            return NULL;
        }
    }
    if (hinfo->os != NULL){
        char * os = mem2hex(hinfo->os, hinfo->os_len);
        if (json_object_set_new(obj, "os", json_stringn(os, hinfo->os_len * 2)) != 0){
            if (rr->decoded == 0)
                sdns_free_rr_HINFO(hinfo);
            json_decref(obj);
            free(os);
            return NULL;
        }
        free(os);
    }else{
        if (json_object_set_new(obj, "os", json_string("")) != 0){
            if (rr->decoded == 0)
                sdns_free_rr_HINFO(hinfo);
            json_decref(obj);
            return NULL;
        }
    }
    if (rr->decoded == 0)
        sdns_free_rr_HINFO(hinfo);
    return obj;
}

json_t * sdns_json_rr_PTR(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_PTR * ptr = NULL;
    if (rr->decoded)
        ptr = rr->psdns_rr;
    else
        ptr = sdns_decode_rr_PTR(ctx, rr);
    if (NULL == ptr)
        return NULL;
    json_t * ptrdname = json_string(ptr->PTRDNAME);
    if (NULL == ptrdname){
        if (rr->decoded == 0)
            sdns_free_rr_PTR(ptr);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_PTR(ptr);
    
    json_t * obj = json_object();
    if (obj == NULL){
        json_decref(ptrdname);
        return NULL;
    }
    if (json_object_set_new(obj, "ptrdname", ptrdname) != 0){
        json_decref(ptrdname);
        json_decref(obj);
        return NULL;
    }
    return obj;
}

json_t * sdns_json_rr_TXT(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_TXT * txt = NULL;
    if (rr->decoded)
        txt = rr->psdns_rr;
    else
        txt = sdns_decode_rr_TXT(ctx, rr);
    if (NULL == txt)
        return NULL;
    
    sdns_rr_TXT * tmp = txt;
    size_t to_allocate = 1;
    while(tmp){
        to_allocate += tmp->character_string.len;
        tmp = tmp->next;
    }
    char * txt_mem = (char*) malloc_or_abort(to_allocate > rr->rdlength?to_allocate:rr->rdlength);
    int cnt = 0;
    tmp = txt;  // reset tmp
    while (tmp){
        for (int i=0; i<tmp->character_string.len; ++i){
            txt_mem[cnt] = tmp->character_string.content[i];
            cnt++;
        }
        tmp = tmp->next;
    }
    if (rr->decoded == 0)
        sdns_free_rr_TXT(txt);
    json_t * t = json_stringn(txt_mem, cnt);
    free(txt_mem);
    if (t == NULL){
        return NULL;
    }

    json_t * obj = json_object();
    if (obj == NULL){
        json_decref(t);
        return NULL;
    }
    if (json_object_set_new(obj, "txtdata", t) != 0){
        json_decref(t);
        json_decref(obj);
        return NULL;
    }
    return obj;
}

json_t * sdns_json_rr_RRSIG(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_RRSIG * rrsig = NULL;
    if (rr->decoded)
        rrsig = rr->psdns_rr;
    else
        rrsig = sdns_decode_rr_RRSIG(ctx, rr);
    if (NULL == rrsig)
        return NULL;
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        return NULL;
    }
    if (json_object_set_new(obj, "algorithm", json_integer(rrsig->algorithm)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "keytag", json_integer(rrsig->key_tag)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "labels", json_integer(rrsig->labels)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "originalttl", json_integer(rrsig->original_ttl)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "expiration", json_integer(rrsig->signature_expiration)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "inception", json_integer(rrsig->signature_inception)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "signaturelen", json_integer(rrsig->signature_len)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "typecovered", json_integer(rrsig->type_covered)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "signersname", json_string(rrsig->signers_name)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        return NULL;
    }
    char * sig = mem2hex(rrsig->signature, rrsig->signature_len);
    if (json_object_set_new(obj, "signature", json_stringn(sig, rrsig->signature_len * 2)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_RRSIG(rrsig);
        json_decref(obj);
        free(sig);
        return NULL;
    }
    free(sig);
    if (rr->decoded == 0)
        sdns_free_rr_RRSIG(rrsig);
    return obj;
}

json_t * sdns_json_rr_NID(sdns_context * ctx, sdns_rr * rr){
    sdns_rr_NID * nid = NULL;
    if (rr->decoded){
        nid = (sdns_rr_NID*)rr->psdns_rr;
    }else{
        nid = sdns_decode_rr_NID(ctx, rr);
    }
    if (NULL == nid){return NULL;}
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_NID(nid);
        return NULL;
    }
    if (json_object_set_new(obj, "preference", json_integer(nid->Preference)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_NID(nid);
        json_decref(obj);
        return NULL;
    }
    char * tmp = mem2hex(nid->NodeId, 8);
    if (tmp != NULL){
        if (json_object_set_new(obj, "nodeid", json_stringn(tmp, 8 * 2)) != 0){
            if (rr->decoded == 0)
                sdns_free_rr_NID(nid);
            json_decref(obj);
            free(tmp);
            return NULL;
        }
        free(tmp);
    }else{
        json_decref(obj);
        if (rr->decoded == 0)
            sdns_free_rr_NID(nid);
        return NULL;
    }
    if (rr->decoded == 00)
        sdns_free_rr_NID(nid);
    return obj;
}

json_t * sdns_json_rr_L32(sdns_context * ctx, sdns_rr * rr){
    sdns_rr_L32 * l32 = NULL;
    if (rr->decoded){
        l32 = (sdns_rr_L32*)rr->psdns_rr;
    }else{
        l32 = sdns_decode_rr_L32(ctx, rr);
    }
    if (NULL == l32){return NULL;}
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_L32(l32);
        return NULL;
    }
    if (json_object_set_new(obj, "preference", json_integer(l32->Preference)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_L32(l32);
        json_decref(obj);
        return NULL;
    }
    char ip[20] = {0x00};
    cipv4_uint_to_str(l32->Locator32, ip);
    if (json_object_set_new(obj, "locator32", json_string(ip)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_L32(l32);
        json_decref(obj);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_L32(l32);
    return obj;
}

json_t * sdns_json_rr_L64(sdns_context * ctx, sdns_rr * rr){
    sdns_rr_L64 * l64 = NULL;
    if (rr->decoded){
        l64 = (sdns_rr_L64*)rr->psdns_rr;
    }else{
        l64 = sdns_decode_rr_L64(ctx, rr);
    }
    if (NULL == l64){return NULL;}
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_L64(l64);
        return NULL;
    }
    if (json_object_set_new(obj, "preference", json_integer(l64->Preference)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_L64(l64);
        json_decref(obj);
        return NULL;
    }
    char * locator64 = mem2hex(l64->Locator64, 8);
    if (locator64 != NULL){
        if (json_object_set_new(obj, "locator64", json_string(locator64)) != 0){
            if (rr->decoded == 0)
                sdns_free_rr_L64(l64);
            free(locator64);
            json_decref(obj);
            return NULL;
        }
        free(locator64);
    }else{
        if (rr->decoded == 0)
            sdns_free_rr_L64(l64);
        free(locator64);
        json_decref(obj);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_L64(l64);
    return obj;
}

json_t * sdns_json_rr_URI(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_URI * uri = NULL;
    if (rr->decoded)
        uri = rr->psdns_rr;
    else
        uri = sdns_decode_rr_URI(ctx, rr);
    if (NULL == uri)
        return NULL;
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_URI(uri);
        return NULL;
    }
    if (json_object_set_new(obj, "priority", json_integer(uri->Priority)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_URI(uri);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "weight", json_integer(uri->Weight)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_URI(uri);
        json_decref(obj);
        return NULL;
    }
    if (uri->Target != NULL){
        if (json_object_set_new(obj, "target", json_stringn(uri->Target, uri->target_len)) != 0){
            if (rr->decoded == 0)
                sdns_free_rr_URI(uri);
            json_decref(obj);
            return NULL;
        }
    }else{
        if (json_object_set_new(obj, "target", json_string("")) != 0){
            if (rr->decoded == 0)
                sdns_free_rr_URI(uri);
            json_decref(obj);
            return NULL;
        }
    }
    if (rr->decoded == 0)
        sdns_free_rr_URI(uri);
    return obj;
}

json_t * sdns_json_rr_LP(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_LP * lp = NULL;
    if (rr->decoded)
        lp = rr->psdns_rr;
    else
        lp = sdns_decode_rr_LP(ctx, rr);
    if (NULL == lp)
        return NULL;
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_LP(lp);
        return NULL;
    }
    if (json_object_set_new(obj, "Preference", json_integer(lp->Preference)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_LP(lp);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "fqdn", json_string(lp->FQDN)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_LP(lp);
        json_decref(obj);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_LP(lp);
    return obj;
}

json_t * sdns_json_rr_CAA(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_CAA * caa = NULL;
    if (rr->decoded)
        caa = rr->psdns_rr;
    else
        caa = sdns_decode_rr_CAA(ctx, rr);
    if (NULL == caa)
        return NULL;
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_CAA(caa);
        return NULL;
    }
    if (json_object_set_new(obj, "flag", json_integer(caa->flag)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_CAA(caa);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "tag", json_stringn(caa->tag, caa->tag_len)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_CAA(caa);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "value", json_stringn(caa->value, caa->value_len)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_CAA(caa);
        json_decref(obj);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_CAA(caa);
    return obj;
}

json_t * sdns_json_rr_SRV(sdns_context * ctx, sdns_rr *rr){
    if (NULL == rr || NULL == ctx)
        return NULL;
    sdns_rr_SRV * srv = NULL;
    if (rr->decoded)
        srv = rr->psdns_rr;
    else
        srv = sdns_decode_rr_SRV(ctx, rr);
    if (NULL == srv)
        return NULL;
    json_t * obj = json_object();
    if (NULL == obj){
        if (rr->decoded == 0)
            sdns_free_rr_SRV(srv);
        return NULL;
    }
    if (json_object_set_new(obj, "port", json_integer(srv->Port)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SRV(srv);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "priority", json_integer(srv->Priority)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SRV(srv);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "weight", json_integer(srv->Weight)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SRV(srv);
        json_decref(obj);
        return NULL;
    }
    if (json_object_set_new(obj, "target", json_string(srv->Target)) != 0){
        if (rr->decoded == 0)
            sdns_free_rr_SRV(srv);
        json_decref(obj);
        return NULL;
    }
    if (rr->decoded == 0)
        sdns_free_rr_SRV(srv);
    return obj;
}

json_t * sdns_json_rr_OPT(sdns_context * ctx, sdns_rr *rr){
    if (rr == NULL || ctx == NULL)
        return NULL;
    sdns_opt_rdata * opt = NULL;
    if (rr->decoded)
        opt = (sdns_opt_rdata*) rr;
    else
        opt = sdns_decode_rr_OPT(ctx, rr);
    if (opt == NULL)
        return NULL;
    sdns_opt_rdata * orig = opt;
    json_t * obj = json_object();
    if (NULL == obj)
        goto exit_clean;
    json_t * rdata = json_array();
    if (NULL == rdata)
        goto exit_clean_obj;
    json_t * ttl = json_object();
    if (ttl == NULL)
        goto exit_clean_arr;
    char * name = rr->name;
    int json_op_result = -1;
    json_op_result = json_object_set_new(obj, "name", name == NULL?json_null():json_string(name));
    if (json_op_result != 0)
        goto exit_clean_ttl;
    json_op_result = json_object_set_new(ttl, "DO", json_integer((rr->ttl >> 15) & 0x01));
    json_op_result += json_object_set_new(ttl, "z", json_integer(rr->ttl & 0x7F));
    json_op_result += json_object_set_new(ttl, "extended_rcode",  json_integer((rr->ttl >> 24) & 0xFF));
    json_op_result += json_object_set_new(ttl, "version", json_integer((rr->ttl >> 16) & 0xFF));
    json_op_result += json_object_set_new(obj, "ttl", ttl);
    json_op_result += json_object_set_new(obj, "udp_size", json_integer(rr->udp_size));
    char buff_type[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    json_op_result += json_object_set_new(obj, "type", json_string(buff_type));
    if (json_op_result != 0)
        goto exit_clean_ttl;
    int enter_loop = 1;
    if (rr->rdlength == 0)      // nasty coding
        enter_loop = 0;
    while(opt && enter_loop){
        json_t * rdata_element = json_object();
        if (NULL == rdata_element)
            goto exit_clean_ttl;
        json_op_result = json_object_set_new(rdata_element, "option_code", json_integer(opt->option_code));
        json_op_result += json_object_set_new(rdata_element, "option_length", json_integer(opt->option_length));
        if (opt->option_data){
            char * to_hex = mem2hex(opt->option_data, opt->option_length);
            if (to_hex == NULL){
                json_decref(rdata_element);
                goto exit_clean_ttl;
            }
            json_op_result += json_object_set_new(rdata_element, "option_data", json_stringn(to_hex, opt->option_length * 2));
            free(to_hex);
        }else{
            json_op_result += json_object_set_new(rdata_element, "option_data", json_null());
        }
        if (json_op_result != 0){
            json_decref(rdata_element);
            goto exit_clean_ttl;
        }
        if(json_array_append_new(rdata, rdata_element) != 0){
            json_decref(rdata_element);
            goto exit_clean_ttl;
        }
        opt = opt->next;
    }
    json_op_result = json_object_set_new(obj, "rdata", rdata);
    if (json_op_result != 0)
        goto exit_clean_ttl;
    goto exit_clean;
exit_clean_ttl:
    json_decref(ttl);
exit_clean_arr:
    json_decref(rdata);
    rdata = NULL;
exit_clean_obj:
    json_decref(obj);
    obj = NULL;
exit_clean:
    if (rr->decoded == 0)
        sdns_free_opt_rdata(orig);
    return obj;
}
