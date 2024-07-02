#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sdns_utils.h"
#include "logger.h"
#include <sdns.h>
#include <sdns_print.h>

void sdns_neat_print_dns(sdns_context * ctx){
    if (NULL == ctx || NULL == ctx->msg)
        return;
    sdns_neat_print_header(ctx);
    fprintf(stdout, "** DNS QUESTION SECTION\n");
    if (ctx->msg->header.qdcount > 0){
        sdns_neat_print_question(ctx);
    }

    fprintf(stdout, "** DNS ANSWER SECTION\n");
    if (ctx->msg->header.ancount > 0){
        sdns_rr * tmp = ctx->msg->answer;
        do{
            sdns_neat_print_rr(ctx, tmp);
            tmp = tmp->next;
        }while(tmp);
    }
    fprintf(stdout, "** DNS AUTHORITY SECTION\n");
    if (ctx->msg->header.nscount > 0){
        sdns_rr * tmp = ctx->msg->authority;
        do{
            sdns_neat_print_rr(ctx, tmp);
            tmp = tmp->next;
        }while(tmp);
    }
    fprintf(stdout, "** DNS ADDITIONAL SECTION\n");
    if (ctx->msg->header.arcount > 0){
        sdns_rr * tmp = ctx->msg->additional;
        do{
            sdns_neat_print_rr(ctx, tmp);
            tmp = tmp->next;
        }while(tmp);
    }
}

void sdns_neat_print_question(sdns_context * ctx){
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(ctx->msg->question.qtype, buff_type);
    sdns_class_to_string(ctx->msg->question.qclass, buff_class);
    fprintf(stdout, "\t%s\t%s\t%s\n", ctx->msg->question.qname, buff_class, buff_type);
}

void sdns_neat_print_header(sdns_context * ctx){
    // this function will print all the fields of the DNS message header
    char *error_buffer  = NULL;   // it will be created by the function, we have to free it
    sdns_error_string(ctx->msg->header.rcode, &error_buffer);
    fprintf(stdout, "** DNS MESSAGE HEADER\n");
    fprintf(stdout, "\tID: %d,",  (uint16_t)ctx->msg->header.id);
    fprintf(stdout, "  qr: %d,", ctx->msg->header.qr);
    fprintf(stdout, "  opcode: %d,", ctx->msg->header.opcode);
    fprintf(stdout, "  aa: %d,", ctx->msg->header.aa);
    fprintf(stdout, "  tc: %d,", ctx->msg->header.tc);
    fprintf(stdout, "  rd: %d,", ctx->msg->header.rd);
    fprintf(stdout, "  ra: %d\n", ctx->msg->header.ra);
    fprintf(stdout, "\tz: %d,", ctx->msg->header.z);
    fprintf(stdout, "  AD: %d,", ctx->msg->header.AD);
    fprintf(stdout, "  CD: %d,", ctx->msg->header.CD);
    fprintf(stdout, "  rcode: %s", error_buffer);
    fprintf(stdout, "  qdcount: %d,", ctx->msg->header.qdcount);
    fprintf(stdout, "  ancount: %d,", ctx->msg->header.ancount);
    fprintf(stdout, "  arcount: %d,", ctx->msg->header.arcount);
    fprintf(stdout, "  nscount: %d\n", ctx->msg->header.nscount);
    free(error_buffer);
}


void sdns_neat_print_rr(sdns_context * ctx, sdns_rr * rr){
    if (NULL == rr)
        return;
    if (rr->type == sdns_rr_type_A)
        return sdns_neat_print_rr_A(ctx, rr);
    if (rr->type == sdns_rr_type_NS)
        return sdns_neat_print_rr_NS(ctx, rr);
    if (rr->type == sdns_rr_type_PTR)
        return sdns_neat_print_rr_PTR(ctx, rr);
    if (rr->type == sdns_rr_type_CNAME)
        return sdns_neat_print_rr_CNAME(ctx, rr);
    if (rr->type == sdns_rr_type_TXT)
        return sdns_neat_print_rr_TXT(ctx, rr);
    if (rr->type == sdns_rr_type_SOA)
        return sdns_neat_print_rr_SOA(ctx, rr);
    if (rr->type == sdns_rr_type_MX)
        return sdns_neat_print_rr_MX(ctx, rr);
    if (rr->type == sdns_rr_type_OPT)
        return sdns_neat_print_rr_OPT(ctx, rr);
    if (rr->type == sdns_rr_type_NID)
        return sdns_neat_print_rr_NID(ctx, rr);
    if (rr->type == sdns_rr_type_L32)
        return sdns_neat_print_rr_L32(ctx, rr);
    if (rr->type == sdns_rr_type_L64)
        return sdns_neat_print_rr_L64(ctx, rr);
    if (rr->type == sdns_rr_type_LP)
        return sdns_neat_print_rr_LP(ctx, rr);
    if (rr->type == sdns_rr_type_RRSIG)
        return sdns_neat_print_rr_RRSIG(ctx, rr);
    if (rr->type == sdns_rr_type_SRV)
        return sdns_neat_print_rr_SRV(ctx, rr);
    if (rr->type == sdns_rr_type_URI)
        return sdns_neat_print_rr_URI(ctx, rr);
    if (rr->type == sdns_rr_type_HINFO)
        return sdns_neat_print_rr_HINFO(ctx, rr);
    if (rr->type == sdns_rr_type_AAAA)
        return sdns_neat_print_rr_AAAA(ctx, rr);
    //TODO: ADD more printing stuff here
    // if it's not implemented, print rr as a general case
    //return sdns_neat_print_rr_section(ctx, rr);
}

void sdns_neat_print_rr_HINFO(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_HINFO * hinfo = NULL;
    if (rr->decoded)
        hinfo = (sdns_rr_HINFO *) rr->psdns_rr;
    else
        hinfo = sdns_decode_rr_HINFO(ctx, rr);
    if (hinfo == NULL){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t",
           rr->name, rr->ttl, buff_class, buff_type);
    fprintf(stdout, "\"");
    for (int i=0; i<hinfo->cpu_len; ++i){
        fprintf(stdout, "%c", hinfo->cpu[i]);
    }
    fprintf(stdout, "\"");
    fprintf(stdout, " ");
    fprintf(stdout, "\"");
    for (int i=0; i<hinfo->os_len; ++i){
        fprintf(stdout, "%c", hinfo->os[i]);
    }
    fprintf(stdout, "\"\n");
    if (rr->decoded == 0)
        sdns_free_rr_HINFO(hinfo);
}


void sdns_neat_print_rr_SRV(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_SRV * srv = NULL;
    if (rr->decoded)
        srv = (sdns_rr_SRV *) rr->psdns_rr;
    else
        srv = sdns_decode_rr_SRV(ctx, rr);
    if (srv == NULL){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t%d %d %u %s\n",
           rr->name, rr->ttl, buff_class, buff_type,
           srv->Priority, srv->Weight, srv->Port, srv->Target);
    if (rr->decoded == 0)
        sdns_free_rr_SRV(srv);
}

void sdns_neat_print_rr_URI(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_URI * uri = NULL;
    if (rr->decoded)
        uri = (sdns_rr_URI *) rr->psdns_rr;
    else
        uri = sdns_decode_rr_URI(ctx, rr);
    if (uri == NULL){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t%d %d ",
           rr->name, rr->ttl, buff_class, buff_type,
           uri->Priority, uri->Weight);
    if (uri->target_len > 0){
        fprintf(stdout, "\"");
        for (int i=0; i<uri->target_len; ++i){
            fprintf(stdout, "%c", uri->Target[i]);
        }
        fprintf(stdout, "\"\n");
    }else{
        fprintf(stdout, "(EMPTY Target)\n");
    }
    if (rr->decoded == 0)
        sdns_free_rr_URI(uri);
}

void sdns_neat_print_rr_AAAA(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_AAAA * aaaa = NULL;
    if (rr->decoded)
        aaaa = (sdns_rr_AAAA*)rr->psdns_rr;
    else
        aaaa = sdns_decode_rr_AAAA(ctx, rr);
    if (NULL == aaaa){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t%s\n",
           rr->name, rr->ttl, buff_class, buff_type, aaaa->address);
    if (rr->decoded == 0)
        sdns_free_rr_AAAA(aaaa);
    
}



void sdns_neat_print_rr_RRSIG(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_RRSIG * rrsig = NULL;
    if (rr->decoded)
        rrsig = (sdns_rr_RRSIG*)rr->psdns_rr;
    else
        rrsig = sdns_decode_rr_RRSIG(ctx, rr);
    if (NULL == rrsig){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    char buff_rrsig_type[20] = {0x00};
    sdns_rr_type_to_string(rrsig->type_covered, buff_rrsig_type);
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t%s %d %u %u %u %u %d %s ",
           rr->name, rr->ttl, buff_class, buff_type,
           buff_rrsig_type, rrsig->algorithm,
           rrsig->labels, rrsig->original_ttl, 
           rrsig->signature_expiration, rrsig->signature_inception,
           rrsig->key_tag, rrsig->signers_name);
    if (rrsig->signature_len > 0){
        for (int i=0; i< rrsig->signature_len; ++i){
            fprintf(stdout, "%02x", (uint8_t)rrsig->signature[i]);
        }
        fprintf(stdout, "\n");
    }
    if (rr->decoded == 0){
        // we have to free the memory allocated
        sdns_free_rr_RRSIG(rrsig);
    }
}

void sdns_neat_print_rr_OPT(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    char buff_type[20] = {0x00};
    char option_code_name[100] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    fprintf(stdout, "\t*********\n");
    fprintf(stdout, "\tName: %s,", rr->name == NULL || strlen(rr->name)==0?"NULL":rr->name);
    fprintf(stdout, "\tType: %s(%d),", buff_type, rr->type);
    fprintf(stdout, "\tUDP Payload size: %d\n", rr->udp_size);
    fprintf(stdout, "\tExtended rcode: %d,", (rr->ttl >> 24) & 0xFF);
    fprintf(stdout, "\tEDNS0 Version: %d,", (rr->ttl >> 16) & 0xFF);
    fprintf(stdout, "\tDO: %d,", (rr->ttl >> 15) & 0x01);
    fprintf(stdout, "\tZ: %d,", rr->ttl & 0x7F);
    fprintf(stdout, "\tRDlength: %d\n", rr->rdlength);
    sdns_opt_rdata * opt = NULL;
    if (rr->decoded)
        opt = rr->opt_rdata;
    else
        opt = sdns_decode_rr_OPT(ctx, rr);
    if (opt == NULL){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    sdns_opt_rdata * orig = opt;
    while (opt){
        sdns_ends0_option_code_to_text(opt->option_code, option_code_name);
        fprintf(stdout, "\tOption Code: %d (%s)\n", opt->option_code, option_code_name);
        fprintf(stdout, "\tOption Length: %d\n", opt->option_length);
        fprintf(stdout, "\tOption Data: ");
        if (opt->option_length == 0){
            fprintf(stdout, "(EMPTY)");
        }else{
            for (int i=0; i< opt->option_length; ++i){
                fprintf(stdout, "0x%02x ", (unsigned char)opt->option_data[i]);
            }
        }
        fprintf(stdout, "\n");
        opt = opt->next;
    }
    if (rr->decoded == 0)
        sdns_free_opt_rdata(orig);
    return;
}

void sdns_neat_print_rr_A(sdns_context * ctx, sdns_rr * rr){
    //prints A record RR section neatly!
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    uint32_t ipaddress = 0x00;
    char ip[16] = {0x00};
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    sdns_rr_A * a = NULL;
    if (rr->decoded)
        a = (sdns_rr_A*) rr->psdns_rr;
    else
        a = sdns_decode_rr_A(ctx, rr);
    if (NULL == a){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    // we just need to print it. No need to decode it
    ipaddress = a->address;
    cipv4_uint_to_str(ipaddress, ip);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t\t%s\n", rr->name, rr->ttl, buff_class, buff_type, ip);
}

void sdns_neat_print_rr_TXT(sdns_context * ctx, sdns_rr * rr){
    // just print TXT exactly like IPv4 except for the rdata part
    // RFC1035: TXT is of type <character-string>: 1byte length + string ....
    // an empty TXT is not allowed!!!!
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    sdns_rr_TXT * txt = NULL;
    if (rr->decoded)
        txt = (sdns_rr_TXT*)rr->psdns_rr;
    else
        txt = sdns_decode_rr_TXT(ctx, rr);
    if (NULL == txt){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t\t", rr->name, rr->ttl, buff_class, buff_type);
    sdns_rr_TXT * tmp = txt;
    while (tmp){
        fprintf(stdout, "\"");
        for (int i=0; i<tmp->character_string.len; ++i){
            if (tmp->character_string.content[i] == '"')
                fprintf(stdout, "\\%c", tmp->character_string.content[i]);
            else
                fprintf(stdout, "%c", tmp->character_string.content[i]);
        }
        fprintf(stdout, "\" ");
        tmp = tmp->next;
    }
    fprintf(stdout, "\n");
    if (rr->decoded == 0)
        sdns_free_rr_TXT(txt);
}

void sdns_neat_print_rr_NS(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_NS * ns = NULL;
    if (rr->decoded)
        ns = (sdns_rr_NS*)rr->psdns_rr;
    else
        ns = sdns_decode_rr_NS(ctx, rr);
    if (NULL == ns){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t%s\n",
           rr->name, rr->ttl, buff_class, buff_type, ns->NSDNAME);
    if (rr->decoded == 0)
        sdns_free_rr_NS(ns);
}

void sdns_neat_print_rr_NID(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_NID * nid = NULL;
    if (rr->decoded)
        nid = (sdns_rr_NID*)rr->psdns_rr;
    else
        nid = sdns_decode_rr_NID(ctx, rr);
    if (NULL == nid){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    char * tmp = mem2hex(nid->NodeId, 8);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t %d %s\n",
           rr->name, rr->ttl, buff_class, buff_type,
           nid->Preference, tmp);
    free(tmp);
    if (rr->decoded == 0)
        sdns_free_rr_NID(nid);
}

void sdns_neat_print_rr_LP(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_LP * lp = NULL;
    if (rr->decoded)
        lp = (sdns_rr_LP*)rr->psdns_rr;
    else
        lp = sdns_decode_rr_LP(ctx, rr);
    if (NULL == lp){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t %d %s\n",
           rr->name, rr->ttl, buff_class, buff_type,
           lp->Preference, lp->FQDN);
    if (rr->decoded == 0)
        sdns_free_rr_LP(lp);
}

void sdns_neat_print_rr_L64(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_L64 * l64 = NULL;
    if (rr->decoded)
        l64 = (sdns_rr_L64*)rr->psdns_rr;
    else
        l64 = sdns_decode_rr_L64(ctx, rr);
    if (NULL == l64){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    char * locator64 = mem2hex(l64->Locator64, 8);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t %d %s\n",
           rr->name, rr->ttl, buff_class, buff_type,
           l64->Preference, locator64);
    free(locator64);
    if (rr->decoded == 0)
        sdns_free_rr_L64(l64);
}

void sdns_neat_print_rr_L32(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_L32 * l32 = NULL;
    if (rr->decoded)
        l32 = (sdns_rr_L32*)rr->psdns_rr;
    else
        l32 = sdns_decode_rr_L32(ctx, rr);
    if (NULL == l32){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    char ip[20] = {0x00};
    cipv4_uint_to_str(l32->Locator32, ip);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t %d %s\n",
           rr->name, rr->ttl, buff_class, buff_type,
           l32->Preference, ip);
    if (rr->decoded == 0)
        sdns_free_rr_L32(l32);
}

void sdns_neat_print_rr_PTR(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_PTR * ptr = NULL;
    if (rr->decoded)
        ptr = (sdns_rr_PTR*)rr->psdns_rr;
    else
        ptr = sdns_decode_rr_PTR(ctx, rr);
    if (NULL == ptr){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t%s\n",
           rr->name, rr->ttl, buff_class, buff_type, ptr->PTRDNAME);
    if (rr->decoded == 0)
        sdns_free_rr_PTR(ptr);
}

void sdns_neat_print_rr_CNAME(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_CNAME * cname = NULL;
    if (rr->decoded)
        cname = (sdns_rr_CNAME*)rr->psdns_rr;
    else
        cname = sdns_decode_rr_CNAME(ctx, rr);
    if (NULL == cname){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;

    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t%s\n",
           rr->name, rr->ttl, buff_class, buff_type, cname->CNAME);
    if (rr->decoded == 0)
        sdns_free_rr_CNAME(cname);
}

void sdns_neat_print_rr_SOA(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_SOA * soa = NULL;
    if (rr->decoded)
        soa = (sdns_rr_SOA*)rr->psdns_rr;
    else
        soa = sdns_decode_rr_SOA(ctx, rr);
    if (NULL == soa){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t%s %s %u %u %u %u %u\n",
           rr->name, rr->ttl, buff_class, buff_type, soa->mname,
           soa->rname, soa->serial, soa->refresh, soa->retry,
           soa->expire, soa->minimum);
    if (rr->decoded == 0){
        // we have to free the memory allocated
        sdns_free_rr_SOA(soa);
    }
}

void sdns_neat_print_rr_MX(sdns_context * ctx, sdns_rr * rr){
    char error_buffer[256] = {0x00};
    char * err = error_buffer;
    sdns_rr_MX * mx = NULL;
    if (rr->decoded)
        mx = (sdns_rr_MX*)rr->psdns_rr;
    else
        mx = sdns_decode_rr_MX(ctx, rr);
    if (NULL == mx){
        if (ctx->err != 0){
            sdns_error_string(ctx->err, &err);
            fprintf(stdout, ";; ERROR: %s\n", err);
        }
        return;
    }
    char buff_type[20] = {0x00};
    char buff_class[20] = {0x00};
    sdns_rr_type_to_string(rr->type, buff_type);
    sdns_class_to_string(rr->class, buff_class);
    fprintf(stdout, "\t%s\t%u\t%s\t%s\t\t%u %s\n", rr->name, rr->ttl, buff_class, buff_type, mx->preference, mx->exchange);
    if (rr->decoded == 0)
        sdns_free_rr_MX(mx);
}


void sdns_neat_print_rr_section(sdns_context * ctx, sdns_rr * rr){
    // this function will print all the fields of the DNS RR section
    // first print answer section
   fprintf(stdout, "\t\t\tName: %s\n", rr->name);
   fprintf(stdout, "\t\t\tType: %d\n", rr->type);
   fprintf(stdout, "\t\t\tClass: %d\n", rr->class);
   fprintf(stdout, "\t\t\tTTL: %d\n", rr->ttl);
   fprintf(stdout, "\t\t\tRDLength: %d\n", rr->rdlength);
   fprintf(stdout, "\t\t\tRData: ");
   char * data = (char*) rr->rdata;
   for (int j=0; j<rr->rdlength; ++j){
       fprintf(stdout, "0x%02x ", (unsigned char)data[j]);
   }
   fprintf(stdout, "0x00");
   fprintf(stdout, "\n");
}


