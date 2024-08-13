#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

#include <sdns.h>
#include <sdns_dynamic_buffer.h>
#include <logger.h>
#include <sdns_utils.h>
#include <sdns_print.h>
//compile: gcc -g -o sdns.o dns_utils.c sdns.c neat_print.c dynamic_buffer.c -I. -DLOG_DEBUG -DLOG_INFO && ./sdns.o

static void sdns_free_message(sdns_message * msg);

/****************end of static functions declaration************/

static int check_if_section_is_valid(sdns_rr * section, int section_type){
    if (section == NULL){
        return SDNS_ERROR_RR_SECTION_MALFORMED;
    }
    if (section_type == DNS_SECTION_ANSWER){
        // OPT can not appear in answer section
        if (section->type == sdns_rr_type_OPT)
            return SDNS_ERROR_RR_SECTION_MALFORMED;
    }
    if (section_type == DNS_SECTION_AUTHORITY){
        // OPT can not appear in answer section
        if (section->type == sdns_rr_type_OPT)
            return SDNS_ERROR_RR_SECTION_MALFORMED;
    }
    if (section_type == DNS_SECTION_QUESTION){
        // OPT can not appear in answer section
        if (section->type == sdns_rr_type_OPT)
            return SDNS_ERROR_RR_SECTION_MALFORMED;
    }
    return 0;
}


// this only able to decode simple labeles (no compression)
// this is important to make sure we have an appropriate error
// if the label is compressed.
static int decode_label_simple(char * label, char * result){
    DEBUG("Starting to decode the name part(simple)...");
    // max length of a label is 255 (is it?)
    char qname_result[256] = {0x00};
    uint32_t to_read = 0;
    int l = 0; // this tracks qname_result position to fill
    char * tmp_buff = label;
    while (1){        // make sure it's not an infinite loop!
        if (strlen(qname_result) > 255){    // name is too long
            ERROR("Qname length is more than 255 character");
            return SDNS_ERROR_HOSTNAME_TOO_LONG;
        }
        to_read = ((uint8_t)tmp_buff[0]) & 0x000000FF;
        tmp_buff += 1;
        DEBUG("to_read = %d:%02x%02x%02x\n", to_read, tmp_buff[0], tmp_buff[1], tmp_buff[2]);
        if (to_read == 0){
            //we are done
            break;
        }
        if (to_read >= 192){       // the first 2bits are 11-> it is compressed
            return SDNS_ERROR_ILLEGAL_COMPRESSION;
        }else if (to_read <= 63){  // no compression as the first 2 bits are 00
            //read one-character at a time and add it to qname buffer
            for (int i=0; i< to_read; ++i){
                if (tmp_buff[i] == 0){
                    ERROR("NULL character found in the middle of qname");
                    return sdns_rcode_FormErr;
                }
                DEBUG("character to write: %c\n", tmp_buff[i]);
                qname_result[l] = tmp_buff[i];
                l++;
            }
            qname_result[l] = '.';
            l++;
            tmp_buff += to_read;
        }else{  // 01 and 10 are not used yet!
            ERROR("Wrong qname encoding specified (01 or 10)");
            return sdns_rcode_FormErr;
        }
    }
    strcpy(result, qname_result);
    INFO("final qname is: %s\n", result);
    return sdns_rcode_NoError;
}

static inline int read_buffer(char * buf, char * upper_bound, uint8_t num_bytes, char * result){
    // this reads num_bytes from buff making sure we don't bypass the upper_bound
    // and store the read data into result
    // return 0 on success otherwise on failure
    if (buf > upper_bound){
        return 1;
    }
    if (buf + num_bytes -1 > upper_bound){
        return 1;
    }
    for (uint8_t i=0; i< num_bytes; ++i)
        result[i] = buf[i];
    return 0;
}


static int decode_name(sdns_context * ctx, char ** decoded_name){
    DEBUG("Starting to decode the name part...");
    unsigned int consumed = ctx->cursor - ctx->raw;
    if (consumed >= ctx->raw_len){  // make sure not consuming more than what exists!
        // there is nothing to decode
        return SDNS_ERROR_BUFFER_TOO_SHORT;
    }
    // max length of a label is 255 (is it?)
    char qname_result[256] = {0x00};
    char * upper_bound = ctx->raw + ctx->raw_len -1;
    uint32_t to_read = 0;
    char bytes[4] = {0x00};
    char * sofar = ctx->cursor;
    char * tmp_buff = ctx->cursor;
    int label_char_count = 0;
    int l = 0; // this tracks qname_result position to fill
    int success_read = 0;    // at the end of the code, after a successful reading this must be 1
    while (consumed <= ctx->raw_len){        // make sure it's not an infinite loop!

        if (strlen(qname_result) > 255){    // name is too long
            ERROR("Qname length is more than 255 character");
            return SDNS_ERROR_HOSTNAME_TOO_LONG;
        }

        to_read = (uint8_t)tmp_buff[0];
        if (read_buffer(tmp_buff, upper_bound, 1, bytes) != 0){
            return SDNS_ERROR_BUFFER_TOO_SHORT;
        }
        to_read = (uint8_t) bytes[0] & 0x000000FF;
        if (tmp_buff >= sofar){      // only increase consume if we read forward in the packet raw data
            consumed += 1;
            sofar += 1;
        }
        tmp_buff += 1;
        if (to_read == 0){        // if we reach NULL, we are done!
            //we are done
            success_read = 1;
            break;
        }
        if (to_read >= 192){       // the first 2bits are 11-> it is compressed
            // as it's compressed, we need to read another bytes for the offset
            if (read_buffer(tmp_buff, upper_bound, 1, bytes) != 0){
                return SDNS_ERROR_BUFFER_TOO_SHORT;
            }
            tmp_buff += 1;
            //to_read = (uint16_t)read_uint16_from_buffer(tmp_buff - 1) & 0x3FFF;
            uint16_t offset = ((((uint8_t)to_read) & 0x3F) << 8) | (((uint8_t) bytes[0]) & 0xFF);
            // what is offset > size of the packet?
            if (offset > ctx->raw_len)          // we don't jump somewhere that does not exist!
                return SDNS_ERROR_BUFFER_TOO_SHORT;
            // forward jump is not allowed!
            if (ctx->raw + offset >= ctx->raw + consumed){
                return SDNS_ERROR_ILLEGAL_COMPRESSION;
            }
            // we are good to jump now
            DEBUG("We need to jump to %d\n", offset);
            if (tmp_buff >= sofar){
                // same-place (loop) is not allowed
                if (ctx->raw + offset + 1 == ctx->raw + consumed){
                    return SDNS_ERROR_ILLEGAL_COMPRESSION;
                }
                consumed += 1;
                sofar += 1;
            }
            tmp_buff = ctx->raw + offset;
            continue;
        }else if (to_read <= 63){  // no compression as the first 2 bits are 00
            //read one-character at a time and add it to qname buffer
            if ((tmp_buff >= consumed + ctx->raw) && (consumed + to_read >= ctx->raw_len)){
                ERROR("The length of the packet does not cover the name decoding...");
                return sdns_rcode_FormErr;
            }
            for (int i=0; i< to_read; ++i){
                if (tmp_buff[i] == 0){
                    ERROR("NULL character found in the middle of qname");
                    return sdns_rcode_FormErr;
                }
                DEBUG("READ one byte: %c\n", tmp_buff[i]);
                qname_result[l] = tmp_buff[i];
                label_char_count++;
                if (label_char_count > 63){  // can 't have a label > 63
                    return sdns_rcode_FormErr;
                }
                l++;
            }
            qname_result[l] = '.';
            label_char_count = 0;
            l++;
            tmp_buff += to_read;
            if (tmp_buff >= sofar){
                consumed += to_read;
                sofar += to_read;
            }
        }else{  // 01 and 10 are not used yet!
            ERROR("Wrong qname encoding specified (01 or 10)");
            return sdns_rcode_FormErr;
        }
    }
    if (success_read != 1){     // we break the while because of the lack of data
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return SDNS_ERROR_RR_SECTION_MALFORMED;
    }
    ctx->cursor = ctx->raw + consumed;
    *decoded_name = strdup(qname_result);
    INFO("final qname is: %s\n", *decoded_name);
    return sdns_rcode_NoError;
}

static int decode_question_from_buffer(sdns_context * ctx){
    DEBUG("Starting to decode question...");
    char * decoded_name = NULL;
    DEBUG("Starting to decode question name...");
    int res = decode_name(ctx, &decoded_name);
    DEBUG("end decode question name...");
    if (res != sdns_rcode_NoError){
        ERROR("We have and error code of %d from decode_name()\n", res);
        return res;
    }
    uint16_t to_read = 0;
    //DEBUG("Qname read from wire: %s", qname);
    ctx->msg->question.qname = decoded_name;
    INFO("Qname read from wire: %s", ctx->msg->question.qname);
    // what about the qtype and qclass?
    //DEBUG("Reading qtype and qclass.....");
    if (ctx->raw_len - (ctx->cursor - ctx->raw) < 4)  // we need four bytes for class and type
        return sdns_rcode_FormErr;
    to_read = read_uint16_from_buffer(ctx->cursor);
    ctx->cursor += 2;
    if (! check_if_qtype_is_valid(to_read)){
        ERROR("The  Qtype is not recognised: %d\n", to_read);
        return sdns_rcode_FormErr;
    }else{
        ctx->msg->question.qtype = to_read;
    }
    to_read = read_uint16_from_buffer(ctx->cursor);
    if (! check_if_qclass_is_valid(to_read)){
        ERROR("The  Qclass is not recognised: %d\n", to_read);
        return sdns_rcode_FormErr;
    }else{
        ctx->msg->question.qclass = to_read;
    }
    ctx->cursor += 2;
    //DEBUG("Qtype is: %u", msg->question.qtype);
    //DEBUG("Qclass is: %u", msg->question.qclass);
    return sdns_rcode_NoError; // success
}

static void _free_unknown_rr(sdns_rr* rr){
    // this will free unknown or incomplete rr sections
    sdns_rr * tmp = rr;
    sdns_rr * ttmp = tmp;
    DEBUG("in free unknown");
    while(tmp){
        free(tmp->name);
        ttmp = tmp->next;
        free(tmp);
        tmp = ttmp;
    }
}


static int decode_rr_from_buffer(sdns_context * ctx, sdns_rr ** result_section, int num_entries){
    if (ctx->raw_len <= (ctx->cursor - ctx->raw)){  // we don't have enough bytes to decode!
        return sdns_rcode_FormErr;
    }
    sdns_rr * tmp_rr_section = NULL;
    sdns_rr *rr_section = sdns_init_rr(NULL, 0, 0, 0, 0, 0, NULL);
    tmp_rr_section = rr_section;
    sdns_rr *tmp_sdns_rr = NULL;
    int an_res;
    // for i in number of answers
    for (int i=0; i< num_entries; ++i){
        if (tmp_rr_section == NULL){
            tmp_rr_section = sdns_init_rr(NULL, 0, 0, 0, 0, 0, NULL);
            tmp_sdns_rr = rr_section;
            while (tmp_sdns_rr->next)
                tmp_sdns_rr = tmp_sdns_rr->next;
            tmp_sdns_rr->next = tmp_rr_section;
            tmp_rr_section->next = NULL;
        }
        DEBUG("Reading answer number #%d\n", i+1);
        char * qname_result;
        an_res = decode_name(ctx, &qname_result);
        if (an_res != sdns_rcode_NoError){
            DEBUG("We got error, let's free the memory.......");
            ERROR("There is an error here");
            _free_unknown_rr(rr_section);
            return an_res;
        }
        tmp_rr_section->name = qname_result;
        INFO("NAME from answer #%d: %s", i+1, qname_result);
        if (ctx->raw_len < (ctx->cursor - ctx->raw + 10)){
            ERROR("we hit here");
            _free_unknown_rr(rr_section);
            return sdns_rcode_FormErr;
        }
        tmp_rr_section->type = read_uint16_from_buffer(ctx->cursor);
        ctx->cursor += 2;
            
        if (! check_if_rrtype_is_valid(tmp_rr_section->type)){
            ERROR("The rr name is: %s\n", tmp_rr_section->name);
            ERROR("The RR type is not recognised: %d\n", tmp_rr_section->type);
            _free_unknown_rr(rr_section);
            return sdns_rcode_FormErr;
        }
        DEBUG("********** Type is: %d\n", tmp_rr_section->type);

        tmp_rr_section->class = read_uint16_from_buffer(ctx->cursor);
        ctx->cursor += 2;
        // class is only valid for non-edns0 records
        if (tmp_rr_section->type != sdns_rr_type_OPT && !check_if_rrclass_is_valid(tmp_rr_section->class)){
            ERROR("The RR class is not recognised: %d\n", tmp_rr_section->class);
            _free_unknown_rr(rr_section);
            return sdns_rcode_FormErr;
        }
        DEBUG("##############Class is: %d\n", tmp_rr_section->class);

        tmp_rr_section->ttl = read_uint32_from_buffer(ctx->cursor);
        ctx->cursor += 4;
        DEBUG("TTL is: %d\n", tmp_rr_section->ttl);

        tmp_rr_section->rdlength = read_uint16_from_buffer(ctx->cursor);
        ctx->cursor += 2;
        DEBUG("RDLEngth is: %d\n", tmp_rr_section->rdlength);
        if (tmp_rr_section->rdlength > 0){
            if (ctx->raw_len >= (ctx->cursor - ctx->raw)){
                tmp_rr_section->rdata = ctx->cursor;
            }else{
                ERROR("we have error here");
                _free_unknown_rr(rr_section);
                return sdns_rcode_FormErr;
            }
        }else{
            tmp_rr_section->rdata = NULL;
        }
        ctx->cursor += tmp_rr_section->rdlength;
        tmp_rr_section = tmp_rr_section->next;
    }
    *result_section = rr_section;
    return sdns_rcode_NoError;
}

static int _encode_label_simple(char * label, char * buffer){
    // encode label to the buffer (user-provided and long enough)
    // return sdns_error_elsimple on success and other values for failure
    DEBUG("encode simple label: %s\n", label);
    char * dotpos = NULL;
    char * tmp = label;
    int i = 0;
    int len = strlen(label);
    DEBUG("length of the actual label is %d", len);
    if (strlen(label) > 255){
        return SDNS_ERROR_HOSTNAME_TOO_LONG;
    }
    while (3){
        dotpos = strchr(tmp, '.');
        if (NULL == dotpos){
            //copy the rest and break
            DEBUG("dotpos is NULL\n")
            buffer[i++] = len - (tmp - label);
            while (*tmp){
                buffer[i++] = (uint8_t)*tmp;
                tmp++;
            }
            buffer[i] = '\0';
            break;
        }
        DEBUG("found a . in %ld\n", dotpos - label);
        if (dotpos - tmp > 63)
            return SDNS_ERROR_LABEL_MAX_63;
        buffer[i++] = (uint8_t)(dotpos - tmp);
        DEBUG("The label length is: %ld", dotpos - tmp);
        while (tmp < dotpos){
            buffer[i++] = (uint8_t)*tmp;
            tmp++;
        }
        if (dotpos - label == len -1){  // the '.' is exactly the last char of the string
            DEBUG("We reached the end of the label");
            buffer[i] = '\0';
            break;
        }
        dotpos++;
        tmp++;
        continue;
    }
    DEBUG("The encoded domain name is: \t");
    for (int x =0;x<i;++x){
        DEBUG("%02x ", (uint8_t)buffer[x]);
    }
    DEBUG("\n");
    DEBUG("end of encode_label_simple()");
    return SDNS_ERROR_ELSIMPLE;
}


// returns 1 and 0 for success
static int _encode_label_compressed(char * label, dyn_buffer * db, char * buffer){
    if (NULL == label){
        buffer[0] = '\0';
        return SDNS_ERROR_ELSIMPLE;
    }
    int len = strlen(label);
    if (len < 3){
        // we don't need compression, just use simple encoding
        return _encode_label_simple(label, buffer);
    }
    char simple[256] = {0x00};
    int res = _encode_label_simple(label, simple);
    if (res != SDNS_ERROR_ELSIMPLE){
        return res;
    }
    char * tmp = simple;
    char * match = NULL;
    int j=0;
    size_t tmp_len = strlen(simple);
    size_t db_max_len = db->cursor < 16383?db->cursor:16383;
    DEBUG("max len for search is %ld", db_max_len);
    DEBUG("tmp_len is: %ld", tmp_len);
    while (2){
        match = (char *)memmem(db->buffer, db_max_len, tmp, tmp_len);
        if (match != NULL){
            // we found a match, we can compress it from here
            DEBUG("We found a match in %ld", match - db->buffer);
            uint16_t offset = 0xc000 | (uint16_t)(match - db->buffer);
            buffer[j++] = (uint8_t)(offset >> 8 & 0xFF);
            buffer[j++] = (uint8_t)(offset & 0xFF);
            return SDNS_ERROR_ELCOMPRESSED;
        }else{
            DEBUG("NO match found");
            // go one label further and start again if the remainig part is > 3
            uint8_t to_read = *tmp;
            DEBUG("let's write %d bytes to the buffer", to_read);
            buffer[j++] = *tmp;
            tmp++;
            for (int i=0;i<to_read; ++i){
                buffer[j++] = *tmp;
                tmp++;
            }
            tmp_len = tmp_len - 1 - to_read;
            DEBUG("tmp_len is: %ld", tmp_len);

            if (tmp_len < 3){  // no need to compress more
                for (int i=0;i< tmp_len;++i){
                    buffer[j++] = *tmp;
                    tmp++;
                }
                return SDNS_ERROR_ELSIMPLE;
            }else{
                continue;
            }
        }
    }
}

static int _encode_write_rr_A(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    char tmp_bytes[10] = {0x00};
    tmp_bytes[1] = 0x04;    // rdlength
    dyn_buffer_append(db, tmp_bytes, 2);
    sdns_rr_A * a = (sdns_rr_A*) tmprr->psdns_rr;
    tmp_bytes[0] = (uint8_t)(a->address >> 24 & 0xFF);
    tmp_bytes[1] = (uint8_t)(a->address >> 16 & 0xFF);
    tmp_bytes[2] = (uint8_t)(a->address >> 8 & 0xFF);
    tmp_bytes[3] = (uint8_t)(a->address & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_NS(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    char buffer[256] = {0x00};
    char tmp_bytes[10] = {0x00};
    sdns_rr_NS * ns = (sdns_rr_NS*) tmprr->psdns_rr;
    int res = _encode_label_compressed(ns->NSDNAME, db, buffer);
    if (res != SDNS_ERROR_ELSIMPLE && res != SDNS_ERROR_ELCOMPRESSED)
        return res;
    uint16_t rdlength = res == SDNS_ERROR_ELSIMPLE?strlen(buffer)+1:strlen(buffer);
    tmp_bytes[0] = (uint8_t) (rdlength >> 8 & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    int to_write = res == SDNS_ERROR_ELSIMPLE?strlen(buffer)+1:strlen(buffer);
    dyn_buffer_append(db, buffer, to_write);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_PTR(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    char buffer[256] = {0x00};
    char tmp_bytes[10] = {0x00};
    sdns_rr_PTR * ptr = (sdns_rr_PTR*) tmprr->psdns_rr;
    int res = _encode_label_compressed(ptr->PTRDNAME, db, buffer);
    if (res != SDNS_ERROR_ELSIMPLE && res != SDNS_ERROR_ELCOMPRESSED)
        return res;
    uint16_t rdlength = res == SDNS_ERROR_ELSIMPLE?strlen(buffer)+1:strlen(buffer);
    tmp_bytes[0] = (uint8_t) (rdlength >> 8 & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    int to_write = res == SDNS_ERROR_ELSIMPLE?strlen(buffer)+1:strlen(buffer);
    dyn_buffer_append(db, buffer, to_write);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_CAA(sdns_context * ctx, dyn_buffer * db, sdns_rr *tmprr){
    sdns_rr_CAA * caa = (sdns_rr_CAA*) tmprr->psdns_rr;
    if (caa->tag == NULL || caa->tag_len == 0){
        return SDNS_ERROR_BUFFER_IS_NULL;
    }
    char tmp_bytes[10] = {0x00};
    // calculates rdlength first.
    // rdlength = flag (1 byte) + tag_len (1 byte) + len(tag) + len(value)
    int rdlength = caa->tag_len + caa->value_len + 2;
    tmp_bytes[0] = (uint8_t) (rdlength >> 8 & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    // flag
    tmp_bytes[0] = caa->flag;
    dyn_buffer_append(db, tmp_bytes, 1);
    tmp_bytes[0] = caa->tag_len;
    dyn_buffer_append(db, tmp_bytes, 1);
    dyn_buffer_append(db, caa->tag, caa->tag_len);
    if (caa->value_len > 0)
        dyn_buffer_append(db, caa->value, caa->value_len);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_CNAME(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    char buffer[256] = {0x00};
    char tmp_bytes[10] = {0x00};
    sdns_rr_CNAME * cname = (sdns_rr_CNAME*) tmprr->psdns_rr;
    int res = _encode_label_compressed(cname->CNAME, db, buffer);
    if (res != SDNS_ERROR_ELSIMPLE && res != SDNS_ERROR_ELCOMPRESSED)
        return res;
    uint16_t rdlength = strlen(buffer);
    tmp_bytes[0] = (uint8_t) (rdlength >> 8 & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    int to_write = res == SDNS_ERROR_ELSIMPLE?strlen(buffer)+1:strlen(buffer);
    dyn_buffer_append(db, buffer, to_write);
    return sdns_rcode_NoError;
}


static int _encode_write_rr_TXT(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    uint16_t rdlength = 0;
    char tmp_bytes[10] = {0x00};
    sdns_rr_TXT * txt = (sdns_rr_TXT*) tmprr->psdns_rr;
    sdns_rr_TXT * tmp = txt;
    while (tmp){
        rdlength += tmp->character_string.len + 1;
        tmp = tmp->next;
    }
    tmp = txt;
    tmp_bytes[0] = (uint8_t) (rdlength >> 8 & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    while (tmp){
        tmp_bytes[0] = (uint8_t)(tmp->character_string.len & 0xFF);
        dyn_buffer_append(db, tmp_bytes, 1);
        dyn_buffer_append(db, tmp->character_string.content, tmp->character_string.len);
        tmp = tmp->next;
    }
    return sdns_rcode_NoError;
}

static int _encode_write_rr_OPT(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    char tmp_bytes[10] = {0x00};
    tmp_bytes[0] = (uint8_t) (tmprr->rdlength >> 8 & 0xFF);
    tmp_bytes[1] = (uint8_t)(tmprr->rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    sdns_opt_rdata * opt = tmprr->opt_rdata;
    if (tmprr->rdlength == 0){  // there is nothing to write
        return sdns_rcode_NoError;
    }
    while (opt){
        // opt-code
        tmp_bytes[0] = (uint8_t) (opt->option_code >> 8 & 0xFF);
        tmp_bytes[1] = (uint8_t)(opt->option_code & 0xFF);
        dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
        // opt-length
        tmp_bytes[0] = (uint8_t) (opt->option_length >> 8 & 0xFF);
        tmp_bytes[1] = (uint8_t)(opt->option_length & 0xFF);
        dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
        // opt-data
        dyn_buffer_append(db, opt->option_data, opt->option_length);
        // repeat
        opt = opt->next;
    }
    return sdns_rcode_NoError;
}

static int _encode_write_rr_MX(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    char buffer[256] = {0x00};
    char tmp_bytes[10] = {0x00};
    sdns_rr_MX * mx = (sdns_rr_MX*) tmprr->psdns_rr;
    int res = _encode_label_compressed(mx->exchange, db, buffer);
    if (res != SDNS_ERROR_ELSIMPLE && res != SDNS_ERROR_ELCOMPRESSED)
        return res;
    uint16_t rdlength = strlen(buffer) + 2;
    rdlength += res == SDNS_ERROR_ELSIMPLE?1:0;
    tmp_bytes[0] = (uint8_t) (rdlength >> 8 & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    tmp_bytes[0] = (uint8_t)(mx->preference >> 8 & 0xFF);
    tmp_bytes[1] = (uint8_t)(mx->preference & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);
    dyn_buffer_append(db, buffer, rdlength - 2);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_RRSIG(sdns_context * ctx, dyn_buffer * db, sdns_rr * tmprr){
    DEBUG("******************Start encoding rrsig data");
    sdns_rr_RRSIG * rrsig = (sdns_rr_RRSIG*) tmprr->psdns_rr;
    uint16_t rdlength = 0;
    char tmp_bytes[10] = {0x00};
    // first we go for the name part since this is the only error-prone part
    char sn_buffer[256] = {0x00};
    int sn_result = _encode_label_simple(rrsig->signers_name, sn_buffer);
    if (sn_result != SDNS_ERROR_ELSIMPLE){
        // there is an error in encoding label
        return sn_result;
    }
    rdlength = strlen(sn_buffer) + 1;       // len + null character (this is simple encoding)
    rdlength += 2 + 1 + 1 + 4 + 4 + 4 + 2;  // typeCovered + algorithm + original ttl + expiration + inception + keytag
    rdlength += rrsig->signature_len;
    // write rdlength
    tmp_bytes[0] = (uint8_t) ((rdlength >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    // type covered
    tmp_bytes[0] = (uint8_t)((rrsig->type_covered  >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)((rrsig->type_covered & 0xFF));
    dyn_buffer_append(db, tmp_bytes, 2);
    // algorithm
    tmp_bytes[0] = (uint8_t)(rrsig->algorithm & 0xFF);
    // labels
    tmp_bytes[1] = (uint8_t)(rrsig->labels & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);
    // original TTL
    tmp_bytes[0] = (uint8_t)((rrsig->original_ttl >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((rrsig->original_ttl >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((rrsig->original_ttl >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(rrsig->original_ttl & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    // signature expiration
    tmp_bytes[0] = (uint8_t)((rrsig->signature_expiration >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((rrsig->signature_expiration >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((rrsig->signature_expiration >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(rrsig->signature_expiration & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    // signature inception
    tmp_bytes[0] = (uint8_t)((rrsig->signature_inception >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((rrsig->signature_inception >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((rrsig->signature_inception >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(rrsig->signature_inception & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    // key tag
    tmp_bytes[0] = (uint8_t)((rrsig->key_tag >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)((rrsig->key_tag & 0xFF));
    dyn_buffer_append(db, tmp_bytes, 2);
    // append the signer's name
    dyn_buffer_append(db, sn_buffer, strlen(sn_buffer) + 1);
    // append the signature
    dyn_buffer_append(db, rrsig->signature, rrsig->signature_len);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_SRV(sdns_context * ctx, dyn_buffer* db, sdns_rr * tmprr){
    // the 'target' field of SRV can not use compression based on RFC 2782
    int res_target = -1;
    char target[256] = {0x00};
    char tmp_bytes[10] = {0x00};
    uint16_t rdlength = 0;
    sdns_rr_SRV * srv = (sdns_rr_SRV*) tmprr->psdns_rr;
    res_target = _encode_label_simple(srv->Target, target);
    if (res_target != SDNS_ERROR_ELSIMPLE){
        ctx->err = res_target;
        return res_target;
    }
    rdlength = strlen(target) + 1 + 6; // len(target)+1+priority+weight+port
    tmp_bytes[0] = (uint8_t) ((rdlength >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    // priority
    tmp_bytes[0] = (uint8_t)((srv->Priority >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(srv->Priority & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);

    // weight
    tmp_bytes[0] = (uint8_t)((srv->Weight >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(srv->Weight & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);
    // port
    tmp_bytes[0] = (uint8_t)((srv->Port >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(srv->Port & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);
    // target
    dyn_buffer_append(db, target, strlen(target)+1);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_HINFO(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    // cpu and os are each, ONE <character-string>
    char tmp_bytes[10] = {0x00};
    sdns_rr_HINFO * hinfo = (sdns_rr_HINFO*) tmprr->psdns_rr;
    if (hinfo->cpu_len > 255 || hinfo->os_len > 255){
       return SDNS_ERROR_CHARACTER_STRING_TOO_LONG;
    }
    uint16_t rdlength = hinfo->cpu_len + hinfo->os_len;
    rdlength += 2;  // one byte for the length itself of each <character-string>
    tmp_bytes[0] = (uint8_t) ((rdlength >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    // cpu-len
    tmp_bytes[0] = (uint8_t) hinfo->cpu_len;
    dyn_buffer_append(db, tmp_bytes, 1);
    if (hinfo->cpu_len > 0){
        dyn_buffer_append(db, hinfo->cpu, hinfo->cpu_len);
    }
    // os-len
    tmp_bytes[0] = (uint8_t) hinfo->os_len;
    dyn_buffer_append(db, tmp_bytes, 1);
    if (hinfo->os_len > 0){
        dyn_buffer_append(db, hinfo->os, hinfo->os_len);
    }
    return sdns_rcode_NoError;
}

static int _encode_write_rr_AAAA(sdns_context * ctx, dyn_buffer * db, sdns_rr* tmprr){
    uint16_t rdlength = 16;     // length of IPv6
    sdns_rr_AAAA * aaaa = (sdns_rr_AAAA *) tmprr->psdns_rr;
    char tmp_bytes[10] = {0x00};
    tmp_bytes[0] = (uint8_t) ((rdlength >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    if (aaaa->address == NULL){
        ctx->err = SDNS_ERROR_INVALID_IPv6_FOUND;
        return ctx->err;
    }
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    dyn_buffer_append(db, aaaa->address, 16);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_SOA(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    int res_mname = -1;
    int res_rname = -1;
    char mname[256] = {0x00};
    char rname[256] = {0x00};
    char tmp_bytes[10] = {0x00};
    uint16_t rdlength = 0;
    sdns_rr_SOA * soa = (sdns_rr_SOA*) tmprr->psdns_rr;
    res_mname = _encode_label_compressed(soa->mname, db, mname);
    if (res_mname != SDNS_ERROR_ELSIMPLE && res_mname != SDNS_ERROR_ELCOMPRESSED)
        return res_mname;
    res_rname = _encode_label_compressed(soa->rname, db, rname);
    if (res_rname != SDNS_ERROR_ELSIMPLE && res_rname != SDNS_ERROR_ELCOMPRESSED)
        return res_rname;
    rdlength = 20; // + strlen(mname) + strlen(rname);
    rdlength += res_mname == SDNS_ERROR_ELSIMPLE?strlen(mname) + 1:strlen(mname);
    rdlength += res_rname == SDNS_ERROR_ELSIMPLE?strlen(rname) + 1:strlen(rname);
    tmp_bytes[0] = (uint8_t) ((rdlength >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    dyn_buffer_append(db, mname, res_mname == SDNS_ERROR_ELSIMPLE?strlen(mname) +1:strlen(mname));
    dyn_buffer_append(db, rname, res_rname == SDNS_ERROR_ELSIMPLE?strlen(rname) +1:strlen(rname));
    //serial
    tmp_bytes[0] = (uint8_t)((soa->serial >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((soa->serial >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((soa->serial >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(soa->serial & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    //refresh
    tmp_bytes[0] = (uint8_t)((soa->refresh >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((soa->refresh >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((soa->refresh >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(soa->refresh & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    //retry
    tmp_bytes[0] = (uint8_t)((soa->retry >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((soa->retry >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((soa->retry >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(soa->retry & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    //expire
    tmp_bytes[0] = (uint8_t)((soa->expire >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((soa->expire >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((soa->expire >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(soa->expire & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    // minimum
    tmp_bytes[0] = (uint8_t)((soa->minimum >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((soa->minimum >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((soa->minimum >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(soa->minimum & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_NID(sdns_context * ctx, dyn_buffer * db, sdns_rr* tmprr){
    char tmp_bytes[10] = {0x00};
    uint16_t rdlength = 10;     // it's always 10 (preference + nodeID)
    sdns_rr_NID * nid = (sdns_rr_NID*) tmprr->psdns_rr;
    if (nid->NodeId == NULL){
        return SDNS_ERROR_BUFFER_IS_NULL;
    }
    tmp_bytes[0] = (uint8_t) ((rdlength >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    // preference
    tmp_bytes[0] = (uint8_t) ((nid->Preference >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t) (nid->Preference & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);
    // nodeid
    dyn_buffer_append(db, nid->NodeId, 8);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_L32(sdns_context * ctx, dyn_buffer * db, sdns_rr* tmprr){
    //TODO: need to be tested
    char tmp_bytes[10] = {0x00};
    uint16_t rdlength = 48;     // it's always 10 (preference + locator32)
    sdns_rr_L32 * l32 = (sdns_rr_L32*) tmprr->psdns_rr;
    // rdlength
    tmp_bytes[0] = (uint8_t) ((rdlength >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    // preference
    tmp_bytes[0] = (uint8_t) ((l32->Preference >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t) (l32->Preference & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);
    // locator 32 bit
    tmp_bytes[0] = (uint8_t)((l32->Locator32 >> 24) & 0xFF);
    tmp_bytes[1] = (uint8_t)((l32->Locator32 >> 16) & 0xFF);
    tmp_bytes[2] = (uint8_t)((l32->Locator32 >> 8) & 0xFF);
    tmp_bytes[3] = (uint8_t)(l32->Locator32 & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 4);
    return sdns_rcode_NoError;
}

static int _encode_write_rr_L64(sdns_context * ctx, dyn_buffer * db, sdns_rr* tmprr){
    //TODO: need to be tested
    char tmp_bytes[10] = {0x00};
    uint16_t rdlength = 16 + 64;     // it's always 10 (preference + locator64)
    sdns_rr_L64 * l64 = (sdns_rr_L64*) tmprr->psdns_rr;
    if (l64->Locator64 == NULL){
        ctx->err = SDNS_ERROR_BUFFER_IS_NULL;
        return ctx->err;
    }
    // rdlength
    tmp_bytes[0] = (uint8_t) ((rdlength >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t)(rdlength & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);    // rdlength
    // preference
    tmp_bytes[0] = (uint8_t) ((l64->Preference >> 8) & 0xFF);
    tmp_bytes[1] = (uint8_t) (l64->Preference & 0xFF);
    dyn_buffer_append(db, tmp_bytes, 2);
    // locator 64
    dyn_buffer_append(db, l64->Locator64, 8);
    return sdns_rcode_NoError;
}

static int _encode_write_rr(sdns_context * ctx, dyn_buffer* db, sdns_rr* tmprr){
    //TODO: implement URI, LP, CAA
    // different strategies based on the typeof RR
    if (tmprr->type == sdns_rr_type_A)
        return _encode_write_rr_A(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_NS)
        return _encode_write_rr_NS(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_PTR)
        return _encode_write_rr_PTR(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_CAA)
        return _encode_write_rr_CAA(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_CNAME)
        return _encode_write_rr_CNAME(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_MX)
        return _encode_write_rr_MX(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_OPT)
        return _encode_write_rr_OPT(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_TXT)
        return _encode_write_rr_TXT(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_SOA)
        return _encode_write_rr_SOA(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_RRSIG)
        return _encode_write_rr_RRSIG(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_SRV)
        return _encode_write_rr_SRV(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_HINFO)
        return _encode_write_rr_HINFO(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_AAAA)
        return _encode_write_rr_AAAA(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_NID)
        return _encode_write_rr_NID(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_L32)
        return _encode_write_rr_L32(ctx, db, tmprr);
    if (tmprr->type == sdns_rr_type_L64)
        return _encode_write_rr_L64(ctx, db, tmprr);
    ERROR("We have not implemented DNS RR of type: %d", tmprr->type);
    return sdns_rcode_NotImp;
}

/*************end of static functions********************************/

int check_if_rrclass_is_valid(uint16_t qclass){
    int valid = 0;
    switch(qclass){
        case sdns_rr_class_IN:
        case sdns_rr_class_CS:
        case sdns_rr_class_CH:
        case sdns_rr_class_HS:
            valid = 1;
    }
    return valid;
}

int check_if_qclass_is_valid(uint16_t qclass){
    // the only difference between this method and  `check_if_rrclass_is_valid()`
    // is in 'sdns_q_class_STAR'
    return check_if_rrclass_is_valid(qclass) | (qclass == sdns_q_class_STAR);
}


int check_if_qtype_is_valid(uint16_t qtype){
    // RFC1035: qtype is the same as rrtype + (axfr, maila, mailb, star)
    return check_if_rrtype_is_valid(qtype) | (qtype == sdns_rr_type_AXFR) |
           (qtype == sdns_rr_type_MAILA) | (qtype == sdns_rr_type_MAILB) |
           (qtype == sdns_rr_type_star);
}

int check_if_rrtype_is_valid(uint16_t rrtype){
    int valid = 0;
    switch(rrtype){
        case sdns_rr_type_A:
        case sdns_rr_type_NS:
        case sdns_rr_type_MD:
        case sdns_rr_type_MF:
        case sdns_rr_type_CNAME:
        case sdns_rr_type_SOA:
        case sdns_rr_type_MB:
        case sdns_rr_type_MG:
        case sdns_rr_type_MR:
        case sdns_rr_type_NULL:
        case sdns_rr_type_WKS:
        case sdns_rr_type_PTR:
        case sdns_rr_type_HINFO:
        case sdns_rr_type_MINFO:
        case sdns_rr_type_MX:
        case sdns_rr_type_TXT:
        case sdns_rr_type_RP:
        case sdns_rr_type_AFSDB:
        case sdns_rr_type_X25:
        case sdns_rr_type_ISDN:
        case sdns_rr_type_RT:
        case sdns_rr_type_NSAP:
        case sdns_rr_type_NSAP_PTR:
        case sdns_rr_type_SIG:
        case sdns_rr_type_KEY:
        case sdns_rr_type_PX:
        case sdns_rr_type_GPOS:
        case sdns_rr_type_AAAA:
        case sdns_rr_type_LOC:
        case sdns_rr_type_NXT:
        case sdns_rr_type_EID:
        case sdns_rr_type_NIMLOC:
        case sdns_rr_type_SRV:
        case sdns_rr_type_ATMA:
        case sdns_rr_type_NAPTR:
        case sdns_rr_type_KX:
        case sdns_rr_type_CERT:
        case sdns_rr_type_A6:
        case sdns_rr_type_DNAME:
        case sdns_rr_type_SINK:
        case sdns_rr_type_OPT:
        case sdns_rr_type_APL:
        case sdns_rr_type_DS:
        case sdns_rr_type_SSHFP:
        case sdns_rr_type_IPSECKEY:
        case sdns_rr_type_RRSIG:
        case sdns_rr_type_NSEC:
        case sdns_rr_type_DNSKEY:
        case sdns_rr_type_DHCID:
        case sdns_rr_type_NSEC3:
        case sdns_rr_type_NSEC3PARAM:
        case sdns_rr_type_TLSA:
        case sdns_rr_type_SMIMEA:
        case sdns_rr_type_HIP:
        case sdns_rr_type_NINFO:
        case sdns_rr_type_RKEY:
        case sdns_rr_type_TALINK:
        case sdns_rr_type_CDS:
        case sdns_rr_type_CDNSKEY:
        case sdns_rr_type_OPENPGPKEY:
        case sdns_rr_type_CSYNC:
        case sdns_rr_type_ZONEMD:
        case sdns_rr_type_SVCB:
        case sdns_rr_type_HTTPS:
        case sdns_rr_type_SPF:
        case sdns_rr_type_UINFO:
        case sdns_rr_type_UID:
        case sdns_rr_type_GID:
        case sdns_rr_type_UNSPEC:
        case sdns_rr_type_NID:
        case sdns_rr_type_L32:
        case sdns_rr_type_L64:
        case sdns_rr_type_LP:
        case sdns_rr_type_EUI48:
        case sdns_rr_type_EUI64:
        case sdns_rr_type_TKEY:
        case sdns_rr_type_TSIG:
        case sdns_rr_type_IXFR:
        case sdns_rr_type_URI:
        case sdns_rr_type_CAA:
        case sdns_rr_type_AVC:
        case sdns_rr_type_DOA:
        case sdns_rr_type_AMTRELAY:
        case sdns_rr_type_RESINFO:
        case sdns_rr_type_TA:
        case sdns_rr_type_DLV:
            valid = 1;
    }
    return valid;
}

// returns the text representation of the option code.
// caller responsible to provide the buffer.
// the buffer must be large enough to keep the text (256 is always large enough)
// return 0 if the value is valid else 1
// so you can use the function for both validation and text representation!
int sdns_ends0_option_code_to_text(sdns_edns0_option_code oc, char * buffer){
    if (oc == sdns_edns0_option_code_Reserved0){strcpy(buffer, "Reserved");return 0;}
    if (oc == sdns_edns0_option_code_LLQ){strcpy(buffer, "LLQ");return 0;}
    if (oc == sdns_edns0_option_code_Update_Lease){strcpy(buffer, "Update Lease");return 0;}
    if (oc == sdns_edns0_option_code_NSID){strcpy(buffer, "NSID");return 0;}
    if (oc == sdns_edns0_option_code_Reserved4){strcpy(buffer, "Reserved");return 0;}
    if (oc == sdns_edns0_option_code_DAU){strcpy(buffer, "DAU");return 0;}
    if (oc == sdns_edns0_option_code_DHU){strcpy(buffer, "DHU");return 0;}
    if (oc == sdns_edns0_option_code_N3U){strcpy(buffer, "N3U");return 0;}
    if (oc == sdns_edns0_option_code_edns_client_subnet){strcpy(buffer, "edns-client-subnet");return 0;}
    if (oc == sdns_edns0_option_code_EDNS_EXPIRE){strcpy(buffer, "EDNS EXPIRE");return 0;}
    if (oc == sdns_edns0_option_code_COOKIE){strcpy(buffer, "COOKIE");return 0;}
    if (oc == sdns_edns0_option_code_edns_tcp_keepalive){strcpy(buffer, "edns-tcp-keepalive");return 0;}
    if (oc == sdns_edns0_option_code_Padding){strcpy(buffer, "Padding");return 0;}
    if (oc == sdns_edns0_option_code_CHAIN){strcpy(buffer, "CHAIN");return 0;}
    if (oc == sdns_edns0_option_code_edns_key_tag){strcpy(buffer, "edns-key-tag");return 0;}
    if (oc == sdns_edns0_option_code_Extended_DNS_Error){strcpy(buffer, "Extended DNS Error");return 0;}
    if (oc == sdns_edns0_option_code_EDNS_Client_Tag){strcpy(buffer, "EDNS-Client-Tag");return 0;}
    if (oc == sdns_edns0_option_code_EDNS_Server_Tag){strcpy(buffer, "EDNS-Server-Tag");return 0;}
    if (oc == sdns_edns0_option_code_Report_Channel){strcpy(buffer, "Report-Channel");return 0;}
    if (oc >= 19 && oc <= 20291){strcpy(buffer, "Unassigned");return 1;}
    if (oc == sdns_edns0_option_code_Umbrella_Ident){strcpy(buffer, "Umbrella Ident");return 0;}
    if (oc >= 20293 && oc <= 26945){strcpy(buffer, "Unassigned");return 1;}
    if (oc == sdns_edns0_option_code_DeviceID){strcpy(buffer, "DeviceID");return 0;}
    if (oc >= 26947 && oc <= 65000){strcpy(buffer, "Unassigned");return 1;}
    if (oc >= 65001 && oc <= 65534){strcpy(buffer, "Reserved for Local/Experimental Use");return 1;}
    if (oc == 65535){strcpy(buffer, "Reserved for future expansion");return 1;}
    return 1;
}

sdns_rr_HINFO * sdns_init_rr_HINFO(uint8_t cpu_len, char * cpu, uint8_t os_len, char * os){
    sdns_rr_HINFO * hinfo = (sdns_rr_HINFO*) malloc_or_abort(sizeof(sdns_rr_HINFO));
    hinfo->cpu_len = cpu_len;
    hinfo->os_len = os_len;
    hinfo->cpu = cpu;
    hinfo->os = os;
    return hinfo;
}

void sdns_free_rr_HINFO(sdns_rr_HINFO * hinfo){
    if (NULL == hinfo)
        return;
    free(hinfo->os);
    free(hinfo->cpu);
    free(hinfo);
}

void sdns_free_rr_NID(sdns_rr_NID * nid){
    if (NULL == nid)
        return;
    free(nid->NodeId);
    free(nid);
}

void sdns_free_rr_L32(sdns_rr_L32 * l32){
    if (NULL == l32)
        return;
    free(l32);
}


void sdns_free_rr_L64(sdns_rr_L64 * l64){
    if (NULL == l64)
        return;
    free(l64->Locator64);
    free(l64);
}

void sdns_free_rr_LP(sdns_rr_LP * lp){
    if (NULL == lp)
        return;
    free(lp->FQDN);
    free(lp);
}

void sdns_free_rr_CAA(sdns_rr_CAA * caa){
    if (NULL == caa)
        return;
    free(caa->tag);
    free(caa->value);
    free(caa);
}

sdns_rr_NID * sdns_init_rr_NID(uint16_t preference, char * nodeid){
    sdns_rr_NID * nid = (sdns_rr_NID *) malloc_or_abort(sizeof(sdns_rr_NID));
    nid->Preference = preference;
    nid->NodeId = nodeid;
    return nid;
}

sdns_rr_L32 * sdns_init_rr_L32(uint16_t preference, uint32_t locator32){
    sdns_rr_L32 * l32 = (sdns_rr_L32 *) malloc_or_abort(sizeof(sdns_rr_L32));
    l32->Preference = preference;
    l32->Locator32 = locator32;
    return l32;
}

sdns_rr_L64 * sdns_init_rr_L64(uint16_t preference, char* locator64){
    sdns_rr_L64 * l64 = (sdns_rr_L64 *) malloc_or_abort(sizeof(sdns_rr_L64));
    l64->Preference = preference;
    l64->Locator64 = locator64;
    return l64;
}


sdns_rr_LP * sdns_init_rr_LP(uint16_t preference, char* fqdn){
    sdns_rr_LP * lp = (sdns_rr_LP *) malloc_or_abort(sizeof(sdns_rr_LP));
    lp->Preference = preference;
    lp->FQDN = fqdn;
    return lp;
}

sdns_rr_CAA * sdns_init_rr_CAA(uint8_t flag, char * tag, uint8_t tag_len, char * value, uint16_t value_len){
   sdns_rr_CAA * caa = (sdns_rr_CAA*) malloc_or_abort(sizeof(sdns_rr_CAA));
   caa->flag = flag;
   caa->tag = tag;
   caa->value = value;
   caa->tag_len = tag_len;
   caa->value_len = value_len;
   return caa;
}

//initialize a TXT record structure
//it's either successfull or abort the code
sdns_rr_TXT * sdns_init_rr_TXT(char * data, uint16_t data_len){
    sdns_rr_TXT * txt = (sdns_rr_TXT*) malloc_or_abort(sizeof(sdns_rr_TXT));
    txt->next = NULL;
    // we don't need to fragment it
    if (NULL == data || data_len == 0){
        txt->character_string.len = 0;
        txt->character_string.content = NULL;
        return txt;
    }
    if (data_len <= 255){
        txt->character_string.content = data;
        txt->character_string.len = data_len;
        return txt;
    }
    // we have to break it to parts each with at most 255 character
    sdns_rr_TXT * tmp = txt;
    txt->character_string.content = data;
    txt->character_string.len = 255;
    char * data_tmp = data;
    while (2){  // why 2?
        data_len -= 255;
        data_tmp += 255;
        sdns_rr_TXT * txt_tmp = (sdns_rr_TXT*) malloc_or_abort(sizeof(sdns_rr_TXT));
        txt_tmp->next = NULL;
        txt_tmp->character_string.content = data_tmp;
        txt_tmp->character_string.len = data_len < 255?data_len:255;
        tmp->next = txt_tmp;
        tmp = txt_tmp;
        if (data_len < 255)
            break;
    }
    return txt;
}

// initialize NS structure
sdns_rr_NS * sdns_init_rr_NS(char * nsdname){
    sdns_rr_NS * ns = (sdns_rr_NS*) malloc_or_abort(sizeof(sdns_rr_NS));
    ns->NSDNAME = nsdname;
    return ns;
}


// initialize PTR structure
sdns_rr_PTR * sdns_init_rr_PTR(char * ptrdname){
    sdns_rr_PTR * ptr = (sdns_rr_PTR*) malloc_or_abort(sizeof(sdns_rr_PTR));
    ptr->PTRDNAME = ptrdname;
    return ptr;
}

// initialize CNAME structure
sdns_rr_CNAME * sdns_init_rr_CNAME(char * name){
    sdns_rr_CNAME * cname = (sdns_rr_CNAME*) malloc_or_abort(sizeof(sdns_rr_CNAME));
    cname->CNAME = name;
    return cname;
}

// either sucessful or abort the code
sdns_rr_SOA * sdns_init_rr_SOA(char * mname, char * rname, uint32_t expire, uint32_t minimum,
                               uint32_t refresh, uint32_t retry, uint32_t serial){
    sdns_rr_SOA * soa = (sdns_rr_SOA*) malloc_or_abort(sizeof(sdns_rr_SOA));
    soa->mname = mname;
    soa->rname = rname;
    soa->expire = expire;
    soa->minimum = minimum;
    soa->refresh = refresh;
    soa->retry = retry;
    soa->serial = serial;
    return soa;
}


// init and creates a new sdns_rr_RRSIG and return the pointer
// user is responsible to free the memory by calling sdns_free_rr_RRSIG()
// to create an empty structure, call it with:
// sdns_init_rr_RRSIG(0, 0, 0, 0, 0, 0, 0, NULL, NULL, 0);
sdns_rr_RRSIG * sdns_init_rr_RRSIG(uint16_t type_covered, uint8_t algorithm, uint8_t labels,
                                   uint32_t original_ttl, uint32_t signature_expiration,
                                   uint32_t signature_inception, uint8_t key_tag, char * signers_name,
                                   char * signature, uint16_t signature_len){

    sdns_rr_RRSIG * rrsig = (sdns_rr_RRSIG*) malloc_or_abort(sizeof(sdns_rr_RRSIG));
    rrsig->type_covered = type_covered;
    rrsig->algorithm = algorithm;
    rrsig->labels = labels;
    rrsig->original_ttl = original_ttl;
    rrsig->signature_expiration = signature_expiration;
    rrsig->signature_inception = signature_inception;
    rrsig->key_tag = key_tag;
    rrsig->signers_name = signers_name;
    rrsig->signature = signature;
    rrsig->signature_len = signature_len;
    return rrsig;
}

sdns_rr_SRV * sdns_init_rr_SRV(uint16_t Priority, uint16_t Weight, uint16_t Port, char * target){
    sdns_rr_SRV * srv = (sdns_rr_SRV*) malloc_or_abort(sizeof(sdns_rr_SRV));
    srv->Priority = Priority;
    srv->Weight = Weight;
    srv->Port = Port;
    srv->Target = target;
    return srv;
}

sdns_rr_URI * sdns_init_rr_URI(uint16_t Priority, uint16_t Weight, char * Target, uint16_t target_len){
    sdns_rr_URI * uri = (sdns_rr_URI*) malloc_or_abort(sizeof(sdns_rr_URI));
    uri->Priority = Priority;
    uri->Weight = Weight;
    uri->target_len = target_len;
    uri->Target = Target;
    return uri;
}

void sdns_free_rr_URI(sdns_rr_URI * uri){
    if (NULL == uri)
        return;
    free(uri->Target);
    free(uri);
}

void sdns_free_rr_NS(sdns_rr_NS* ns){
    if (NULL == ns)
        return;
    free(ns->NSDNAME);
    free(ns);
}

void sdns_free_rr_RRSIG(sdns_rr_RRSIG* rrsig){
    if (NULL == rrsig)
        return;
    free(rrsig->signers_name);
    free(rrsig->signature);
    free(rrsig);
}

void sdns_free_rr_SRV(sdns_rr_SRV* srv){
    if (NULL == srv)
        return;
    free(srv->Target);
    free(srv);
}

void sdns_free_rr_PTR(sdns_rr_PTR* ptr){
    if (NULL == ptr)
        return;
    free(ptr->PTRDNAME);
    free(ptr);
}

void sdns_free_rr_CNAME(sdns_rr_CNAME* cname){
    if (NULL == cname)
        return;
    free(cname->CNAME);
    free(cname);
}

//initialize an A record structure
// this function either returns successfully or abort() the whole code
sdns_rr_A * sdns_init_rr_A(uint32_t ipaddress){
    sdns_rr_A * a = (sdns_rr_A*) malloc_or_abort(sizeof(sdns_rr_A));
    a->address = ipaddress;
    return a;
}

void sdns_free_rr_TXT(sdns_rr_TXT * txt){
    if (NULL == txt)
        return;
    free(txt->character_string.content);
    sdns_rr_TXT * tmp = txt->next;
    free(txt);
    while (tmp){
        txt = tmp->next;
        free(tmp);
        tmp = txt;
    }
}

void sdns_free_rr_A(sdns_rr_A * a){
    free(a);
}


sdns_rr_A * sdns_decode_rr_A(sdns_context * ctx, sdns_rr * rr){
    /**decode the section assuming it's an A record.
     * the section is already parsed so all we have to do is
     * to parse the rdata part of the section.*/
    if (rr->rdlength != 4){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    if (ctx->raw_len - (rr->rdata - ctx->raw) < 4){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    sdns_rr_A * A = (sdns_rr_A*) malloc_or_abort(sizeof(sdns_rr_A));
    A->address = (((uint8_t)rr->rdata[0] & 0xFF) << 24) | ((uint8_t)rr->rdata[1] << 16);
    A->address += ((uint8_t)rr->rdata[2] << 8) | ((uint8_t)rr->rdata[3]);
    ctx->err = 0;   // success
    return A;
}

sdns_rr_AAAA * sdns_decode_rr_AAAA(sdns_context * ctx, sdns_rr * rr){
    if (rr->rdlength != 16){
        ctx->err = SDNS_ERROR_BUFFER_TOO_SHORT;
        return NULL;
    }
    if (ctx->raw_len - (rr->rdata - ctx->raw) < 16){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    sdns_rr_AAAA * aaaa = sdns_init_rr_AAAA(NULL);
    aaaa->address = mem_copy(rr->rdata, 16);
    ctx->err = 0;   //success
    return aaaa;
}

sdns_rr_L32 * sdns_decode_rr_L32(sdns_context * ctx, sdns_rr * rr){
    if (rr == NULL || ctx == NULL)
        return NULL;        // we should never hit this!
    sdns_rr_L32 * l32 = sdns_init_rr_L32(0, 0);
    uint16_t rr_len = rr->rdlength;
    char * tmp = rr->rdata;
    uint16_t cnt = 0;
    // rdlength must be exactly 6 for 32 RR
    if (rr_len != 6 || tmp == NULL){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_L32(l32);
        return NULL;
    }
    l32->Preference = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    l32->Locator32 = (((uint8_t)tmp[cnt] << 24) & 0xFF000000) | (((uint8_t)tmp[cnt+1] << 16) & 0x00FF0000);
    l32->Locator32 |= (((uint8_t)tmp[cnt+2] << 8) & 0x0000FF00) | (((uint8_t)tmp[cnt+3]) & 0x000000FF);
    DEBUG("%u", l32->Locator32);
    // reset the error code and return the pointer
    ctx->err = sdns_rcode_NoError;
    return l32;
}


sdns_rr_L64 * sdns_decode_rr_L64(sdns_context * ctx, sdns_rr * rr){
    if (rr == NULL || ctx == NULL)
        return NULL;        // we should never hit this!
    sdns_rr_L64 * l64 = sdns_init_rr_L64(0, NULL);
    uint16_t rr_len = rr->rdlength;
    char * tmp = rr->rdata;
    uint16_t cnt = 0;
    // rdlength must be exactly 10 for L64 RR
    if (rr_len != 10 || tmp == NULL){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_L64(l64);
        return NULL;
    }
    l64->Preference = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    l64->Locator64 = mem_copy(tmp + cnt, 8);
    // reset the error code and return the pointer
    ctx->err = sdns_rcode_NoError;
    return l64;
}

sdns_rr_LP * sdns_decode_rr_LP(sdns_context * ctx, sdns_rr * rr){
    if (rr == NULL || ctx == NULL)
        return NULL;        // we should never hit this!
    sdns_rr_LP * lp = sdns_init_rr_LP(0, NULL);
    if (NULL == lp){
        ctx->err = SDNS_ERROR_MEMORY_ALLOC_FAILD;
        return NULL;
    }
    if (rr->rdlength < 3){    // 2 for preference + 1 (atleast) for fqdn
        sdns_free_rr_LP(lp);
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    char * tmp = rr->rdata;
    uint16_t cnt = 0;
    lp->Preference = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    char buffer_label[256] = {0x00};
    int res = decode_label_simple(tmp + cnt, buffer_label);
    if (res != sdns_rcode_NoError){
        sdns_free_rr_LP(lp);
        ctx->err = sdns_rcode_FormErr;
        return NULL;
    }
    lp->FQDN = strdup(buffer_label);
    ctx->err = 0;   // success
    return lp;
}

sdns_rr_CAA * sdns_decode_rr_CAA(sdns_context * ctx, sdns_rr * rr){
    if (rr == NULL || ctx == NULL)
        return NULL;        // impossible to hit
    sdns_rr_CAA * caa = sdns_init_rr_CAA(0, NULL, 0, NULL, 0);
    // don't need to check if caa is NULL or not. if it's null, the code breaks
    ctx->cursor = rr->rdata;
    if (ctx->raw_len - (ctx->cursor - ctx->raw) < rr->rdlength){
        ERROR("packet is not long enough.....");
        sdns_free_rr_CAA(caa);
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    uint16_t rdlength = rr->rdlength;
    if (rdlength < 2){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_CAA(caa);
        return NULL;
    }
    int cnt = 0;
    char * rdata = rr->rdata;
    char * upper_bound = ctx->raw + ctx->raw_len -1;
    char read[1];
    if (read_buffer(rdata, upper_bound, 1, read) != 0){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_CAA(caa);
        return NULL;
    }
    cnt += 1;
    caa->flag = (uint8_t)read[0];
    // read tag size
    if (read_buffer(rdata + cnt, upper_bound, 1, read) != 0){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_CAA(caa);
        return NULL;
    }
    cnt += 1;
    caa->tag_len = (uint8_t)read[0];
    if (rdata + cnt + caa->tag_len > upper_bound){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_CAA(caa);
        return NULL;
    }
    caa->tag = mem_copy(rdata + cnt, caa->tag_len);
    int val_len = rdlength - 2 - caa->tag_len;
    if (val_len < 0){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_CAA(caa);
        return NULL;
    }
    if (val_len == 0)   // we are done
        return caa;
    caa->value = mem_copy(rdata + cnt + caa->tag_len, val_len);
    caa->value_len = val_len;
    return caa;
}   

sdns_rr_NID * sdns_decode_rr_NID(sdns_context * ctx, sdns_rr * rr){
    if (rr == NULL || ctx == NULL)
        return NULL;        // we should never hit this!
    sdns_rr_NID * nid = sdns_init_rr_NID(0, NULL);
    uint16_t rr_len = rr->rdlength;
    char * tmp = rr->rdata;
    uint16_t cnt = 0;
    // rdlength must be exactly 10 for NID RR
    if (rr_len != 10 || tmp == NULL){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_NID(nid);
        return NULL;
    }
    nid->Preference = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    nid->NodeId = mem_copy(tmp + cnt, 8);        // it's always 8 bytes so we don't need to keep the length
    // reset the error code and return the pointer
    ctx->err = sdns_rcode_NoError;
    return nid;
}

// either is successful or abort the code
sdns_rr_AAAA* sdns_init_rr_AAAA(char * addr){
    sdns_rr_AAAA * aaaa = (sdns_rr_AAAA*) malloc_or_abort(sizeof(sdns_rr_AAAA));
    aaaa->address = addr;
    return aaaa;
}


void sdns_free_rr_AAAA(sdns_rr_AAAA * aaaa){
    if (NULL == aaaa)
        return;
    free(aaaa->address);
    free(aaaa);
}

sdns_rr_SRV * sdns_decode_rr_SRV(sdns_context * ctx, sdns_rr * rr){
    sdns_rr_SRV * srv = sdns_init_rr_SRV(0, 0, 0, NULL);
    uint16_t rr_len = rr->rdlength;
    if (rr_len < 6){  // priority + weight + port
        sdns_free_rr_SRV(srv);
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    char * tmp = rr->rdata;
    uint16_t cnt = 0;
    srv->Priority = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    srv->Weight = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    srv->Port = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    char buffer_label[256] = {0x00};
    int res = decode_label_simple(tmp + cnt, buffer_label);
    if (res != sdns_rcode_NoError){
        sdns_free_rr_SRV(srv);
        ctx->err = sdns_rcode_FormErr;
        return NULL;
    }
    srv->Target = strdup(buffer_label);
    ctx->err = 0;       // success
    return srv;
}

sdns_rr_URI * sdns_decode_rr_URI(sdns_context * ctx, sdns_rr* rr){
    sdns_rr_URI * uri = sdns_init_rr_URI(0, 0, NULL, 0);
    uint16_t rr_len = rr->rdlength;
    if (rr_len < 4){
        sdns_free_rr_URI(uri);
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    char * tmp = rr->rdata;
    uint16_t cnt = 0;
    uri->Priority = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    uri->Weight = (((uint8_t)tmp[cnt] << 8) & 0xFF00) | ((uint8_t)tmp[cnt + 1] & 0x00FF);
    cnt += 2;
    if (rr_len == cnt){  // target is empty
        ctx->err = 0;  // success
        return uri;
    }
    uri->target_len = rr_len - cnt;
    char * target = (char*) malloc_or_abort(uri->target_len);
    memcpy(target, tmp+cnt, uri->target_len);
    uri->Target = target;
    ctx->err = 0;   // success
    return uri;
}

sdns_rr_RRSIG * sdns_decode_rr_RRSIG(sdns_context * ctx, sdns_rr * rr){
    sdns_rr_RRSIG * rrsig = sdns_init_rr_RRSIG(0, 0, 0, 0, 0, 0, 0, NULL, NULL, 0);
    uint16_t cnt = 0;
    uint16_t rr_len = rr->rdlength;
    if (rr_len < 18){
        sdns_free_rr_RRSIG(rrsig);
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    char * tmp = rr->rdata;
    rrsig->type_covered = (((uint8_t)tmp[cnt] << 8)) | ((uint8_t)tmp[cnt+1] & 0xFF);
    cnt += 2;
    rrsig->algorithm = (uint8_t)tmp[cnt] & 0xFF;
    cnt += 1;
    rrsig->labels = (uint8_t)tmp[cnt] & 0xFF;
    cnt += 1;
    rrsig->original_ttl = ((tmp[cnt] << 24) & 0xFF000000) | 
                          ((tmp[cnt + 1] << 16) & 0x00FF0000) | 
                          ((tmp[cnt + 2] << 8) & 0x0000FF00) |
                          (tmp[cnt + 3] & 0x000000FF);
    cnt += 4;
    rrsig->signature_expiration = bytes_to_unix_timestamp(tmp+cnt);
    cnt += 4;
    rrsig->signature_inception = bytes_to_unix_timestamp(tmp+cnt);
    cnt += 4;
    rrsig->key_tag = ((tmp[cnt] << 8) & 0xFF00) | (tmp[cnt+1] & 0x00FF);
    cnt += 2;
    char buffer_label[256] = {0x00};
    int res = decode_label_simple(tmp+cnt, buffer_label);
    if (res != sdns_rcode_NoError){
        sdns_free_rr_RRSIG(rrsig);
        ctx->err = sdns_rcode_FormErr;
        return NULL;
    }
    rrsig->signers_name = strdup(buffer_label);
    // RFC4034#section-3.1.7: A sender MUST NOT use DNS name compression on the 
    // Signer's Name field when transmitting a RRSIG RR. Therefore, the label
    // is not compressed => len(label) = strlen(buffer_label) + 1
    cnt += strlen(buffer_label) + 1;
    // the remaining len from rr->rdlength is for 'Signature'
    rrsig->signature_len = rr_len - cnt;
    rrsig->signature = (char*) malloc_or_abort(rrsig->signature_len);
    memcpy(rrsig->signature, tmp + cnt, rrsig->signature_len);
    ctx->err = 0;       // success
    return rrsig;
}

sdns_rr_TXT * sdns_decode_rr_TXT(sdns_context * ctx, sdns_rr * rr){
    /**
     * decode the section assuming it's a TXT record.*/
    if (rr->rdlength == 0){  // empty txt is not allowed
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    uint16_t rdlen = rr->rdlength;
    sdns_rr_TXT * txt = sdns_init_rr_TXT(NULL, 0);
    sdns_rr_TXT * original = txt;
    uint8_t to_copy = 0;
    uint16_t cnt = 0;
    sdns_rr_TXT * last = original;
    char * buffer = (char*)malloc_or_abort(rr->rdlength);
    dyn_buffer * db = dyn_buffer_init(buffer, rr->rdlength, 0);
    char * offset = NULL;
    while (cnt < rr->rdlength){
        if (NULL == txt){
            txt = sdns_init_rr_TXT(NULL, 0);
        }
        offset = db->buffer + db->cursor;
        if (ctx->raw_len - ((rr->rdata + cnt) - ctx->raw) < 1){
            ERROR("the packet is malformed..........");
            if (original->character_string.content == NULL){    // the first one is NULL
                dyn_buffer_free(db);
                db = NULL;
            }
            sdns_free_rr_TXT(original);
            ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
            return NULL;
        }
        to_copy = (uint8_t)* (rr->rdata + cnt);
        cnt++;
        if (rdlen - cnt < to_copy){ // we don't have enough data to copy
            if (original->character_string.content == NULL){
                dyn_buffer_free(db);
                db = NULL;
            }
            if (original != txt)
                sdns_free_rr_TXT(txt);
            sdns_free_rr_TXT(original);
            ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
            if (db != NULL){
                db->buffer = NULL;
                free(db);
            }
            return NULL;
        }
        if (ctx->raw_len - ((rr->rdata + cnt) - ctx->raw) < to_copy){
            if (original->character_string.content == NULL){
                dyn_buffer_free(db);
                db = NULL;
            }
            if (original != txt)
                sdns_free_rr_TXT(txt);
            sdns_free_rr_TXT(original);
            ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
            if (db != NULL){
                db->buffer = NULL;
                free(db);
            }
            return NULL;
        }
        dyn_buffer_append(db, rr->rdata + cnt, to_copy);
        txt->character_string.len = to_copy;
        txt->character_string.content = offset;
        cnt +=  to_copy;
        if (original != txt){
            last->next = txt;
            last = txt;
        }else{
            last = original;
        }
        txt = NULL;
    }
    free(db);
    ctx->err = 0;   // success
    return original;
}


void sdns_free_rr_SOA(sdns_rr_SOA * soa){
   if (NULL == soa)
       return;
   free(soa->mname);
   free(soa->rname);
   free(soa);
}

sdns_rr_NS * sdns_decode_rr_NS(sdns_context * ctx, sdns_rr * rr){
    if (ctx == NULL || rr == NULL){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    sdns_rr_NS * ns = sdns_init_rr_NS(NULL);
    char * name = NULL;
    ctx->cursor = rr->rdata;
    int res = decode_name(ctx, &name);
    if (res != sdns_rcode_NoError){
        ERROR("Error in parsing name of the NS record: %d\n", res);
        ctx->err = sdns_rcode_FormErr;
        return NULL;
    }
    INFO("parsed NSDNAME is: %s\n", name);
    ns->NSDNAME = name;
    ctx->err = 0;       // success
    return ns;
}


sdns_rr_PTR * sdns_decode_rr_PTR(sdns_context * ctx, sdns_rr * rr){
    if (ctx == NULL || rr == NULL)
        return NULL;
    sdns_rr_PTR * ptr = sdns_init_rr_PTR(NULL);
    char * name = NULL;
    ctx->cursor = rr->rdata;
    int res = decode_name(ctx, &name);
    if (res != sdns_rcode_NoError){
        ctx->err = sdns_rcode_FormErr;
        ERROR("Error in parsing name of the PTR record: %d\n", res);
        return NULL;
    }
    ptr->PTRDNAME = name;
    ctx->err = 0; // success
    return ptr;
}

sdns_rr_CNAME * sdns_decode_rr_CNAME(sdns_context * ctx, sdns_rr * rr){
    if (ctx == NULL || rr == NULL)
        return NULL;
    sdns_rr_CNAME * cname = sdns_init_rr_CNAME(NULL);
    char * name = NULL;
    ctx->cursor = rr->rdata;
    int res = decode_name(ctx, &name);
    if (res != sdns_rcode_NoError){
        ERROR("Error in parsing name of the NS record: %d\n", res);
        ctx->err = sdns_rcode_FormErr;
        return NULL;
    }
    cname->CNAME = name;
    ctx->err = 0; // success
    return cname;
}


sdns_rr_SOA * sdns_decode_rr_SOA(sdns_context * ctx, sdns_rr * rr){
    if (ctx == NULL || rr == NULL)
        return NULL;
    sdns_rr_SOA * soa = sdns_init_rr_SOA(NULL, NULL, 0, 0, 0, 0, 0);
    // we assume that we have enough data in the `rr` as we have already parsed it as an rr
    char * name = NULL;
    ctx->cursor = rr->rdata;
    if (ctx->raw_len - (ctx->cursor - ctx->raw) < rr->rdlength){
        ERROR("packet is not long enough.....");
        sdns_free_rr_SOA(soa);
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }

    int res = decode_name(ctx, &name);
    if (res != sdns_rcode_NoError){
        ERROR("Error in parsing mname of soa record: %d\n", res);
        return NULL;
    }
    soa->mname = name;
    name = NULL;
    res = decode_name(ctx, &name);
    if (res != sdns_rcode_NoError){
        ERROR("Error in parsing rname of soa record: %d\n", res);
        return NULL;
    }
    soa->rname = name;
    name = NULL;

    soa->serial = read_uint32_from_buffer(ctx->cursor);
    ctx->cursor += 4;
    soa->refresh = read_uint32_from_buffer(ctx->cursor);
    ctx->cursor += 4;
    soa->retry = read_uint32_from_buffer(ctx->cursor);
    ctx->cursor += 4;
    soa->expire = read_uint32_from_buffer(ctx->cursor);
    ctx->cursor += 4;
    soa->minimum = read_uint32_from_buffer(ctx->cursor);
    ctx->cursor += 4;
    ctx->err = 0;   // success
    return soa;
}


int sdns_from_wire(sdns_context * ctx){
    if (ctx->raw_len == 0)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (ctx->raw == NULL)
        return SDNS_ERROR_BUFFER_IS_NULL;
    // first, fetch the header to see it's a valid DNS packet
    // the header is 12 bytes
    if (ctx->raw_len < DNS_HEADER_LENGTH)
        return SDNS_ERROR_INVALID_DNS_PACKET;
    char * tmp_buff = ctx->raw;
    unsigned int consumed = 0;
    ctx->msg->header.id = read_uint16_from_buffer(tmp_buff);
    tmp_buff += 2;
    uint16_t flags = read_uint16_from_buffer(tmp_buff);
    tmp_buff += 2;
    ctx->msg->header.qr = (flags & 0x8000) >> 15;
    ctx->msg->header.opcode = (flags & 0x7800) >> 11;
    ctx->msg->header.aa = (flags & 0x0400) >> 10;
    ctx->msg->header.tc = (flags & 0x0200) >> 9;
    ctx->msg->header.rd = (flags & 0x0100) >> 8;
    ctx->msg->header.ra = (flags & 0x0080) >> 7;
    ctx->msg->header.z = (flags & 0x0040) >> 6;
    ctx->msg->header.AD = (flags & 0x0020) >> 5;
    ctx->msg->header.CD = (flags & 0x0010) >> 4;
    ctx->msg->header.rcode = (flags & 0x000f); 
    ctx->msg->header.qdcount = read_uint16_from_buffer(tmp_buff);
    tmp_buff += 2;
    ctx->msg->header.ancount = read_uint16_from_buffer(tmp_buff);
    tmp_buff += 2;
    ctx->msg->header.nscount = read_uint16_from_buffer(tmp_buff);
    tmp_buff += 2;
    ctx->msg->header.arcount = read_uint16_from_buffer(tmp_buff);
    tmp_buff += 2;
    consumed += DNS_HEADER_LENGTH;      // we have consumed DNS header
    /******** done reading headers*/
    // if we have a question, we need to set the question part
    if (ctx->msg->header.qdcount > 0){
        // we can not have more than one question section (which is against the RFC1035)
        if (ctx->msg->header.qdcount > 1)
           return SDNS_ERROR_MORE_THAN_ONE_QUESTION_FOUND;
        // let's parse the question section
        ctx->cursor = tmp_buff;   // make sure we keep the cursor to know where we should start reading
        int q_result = decode_question_from_buffer(ctx);
        if (q_result != sdns_rcode_NoError){
            ERROR("Error happened in decoding question section: %d", q_result);
            return q_result;
        }
    }
    if (ctx->msg->header.ancount > 0){
        sdns_rr * section = NULL;
        int an_result = decode_rr_from_buffer(ctx, &section, ctx->msg->header.ancount);
        if (an_result != sdns_rcode_NoError){
            ERROR("Error happend in decoding answer seciton: %d", an_result);
            return an_result;
        }
        if (check_if_section_is_valid(section, DNS_SECTION_ANSWER) != 0){
            ERROR("Error invalid section found in answer part");
            ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
            return SDNS_ERROR_RR_SECTION_MALFORMED;
        }
        ctx->msg->answer = section;
    }else{
        ctx->msg->answer = NULL;
    }
    if (ctx->msg->header.nscount > 0){
        sdns_rr * section = NULL;
        int ns_result = decode_rr_from_buffer(ctx, &section, ctx->msg->header.nscount);
        if (ns_result != sdns_rcode_NoError){
            ERROR("Error happend in decoding authority seciton: %d", ns_result);
            return ns_result;
        }
        if (check_if_section_is_valid(section, DNS_SECTION_ANSWER) != 0){
            ERROR("Error invalid section found in answer part");
            ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
            return SDNS_ERROR_RR_SECTION_MALFORMED;
        }
        ctx->msg->authority = section;
    }else{
        ctx->msg->authority = NULL;
    }
    if (ctx->msg->header.arcount > 0){
        sdns_rr * section = NULL;
        int ar_result = decode_rr_from_buffer(ctx, &section, ctx->msg->header.arcount);
        if (ar_result != sdns_rcode_NoError){
            ERROR("Error happend in decoding additional seciton: %d", ar_result);
            // what should be free here?
            sdns_free_message(ctx->msg);
            ctx->msg = NULL;
            return ar_result;
        }
        ctx->msg->additional = section;
    }else{
        ctx->msg->additional = NULL;
    }
    return sdns_rcode_NoError;
}

static int _encode_write_section(sdns_context * ctx, dyn_buffer * db, sdns_rr * section){
    sdns_rr * tmprr = section;
    char buffer[256];
    char tmp_byte[10];
    int res;
    while (tmprr){
        memset(buffer, 0x00, 256);
        DEBUG("encode label compressed name: %s", tmprr->name);
        res = _encode_label_compressed(tmprr->name, db, buffer);
        DEBUG("DONE encode label compressed name: %s", tmprr->name);
        if (res != SDNS_ERROR_ELSIMPLE && res != SDNS_ERROR_ELCOMPRESSED){
            ERROR("Can not compress the name of the answer section....");
            return res;
        }
        dyn_buffer_append(db, buffer, res == SDNS_ERROR_ELSIMPLE?strlen(buffer)+1:strlen(buffer));
        // write type
        tmp_byte[0] = (tmprr->type >> 8) & 0xFF;
        tmp_byte[1] = (tmprr->type) & 0xFF;
        dyn_buffer_append(db, tmp_byte, 2);

        // write class
        tmp_byte[0] = (tmprr->class >> 8) & 0xFF;
        tmp_byte[1] = (tmprr->class) & 0xFF;
        dyn_buffer_append(db, tmp_byte, 2);

        // write ttl
        if (tmprr->type == sdns_rr_type_OPT){
            tmp_byte[0] = (uint8_t)(tmprr->opt_ttl.extended_rcode & 0xFF);
            tmp_byte[1] = (uint8_t)(tmprr->opt_ttl.version & 0xFF);
            tmp_byte[2] = ((uint8_t)((tmprr->opt_ttl.DO & 0x01) << 7))  | ((uint8_t)(tmprr->opt_ttl.Z & 0x7F));
            tmp_byte[3] = (uint8_t)(tmprr->opt_ttl.Z & 0xFF);
            
        }else{
            tmp_byte[0] = (tmprr->ttl >> 24) & 0xFF;
            tmp_byte[1] = (tmprr->ttl >> 16) & 0xFF;
            tmp_byte[2] = (tmprr->ttl >> 8) & 0xFF;
            tmp_byte[3] = (tmprr->ttl) & 0xFF;
        }
        dyn_buffer_append(db, tmp_byte, 4);

        if (tmprr->decoded){
            res = _encode_write_rr(ctx, db, tmprr);
            if (res != sdns_rcode_NoError){
                // free something?
                return res;
            }
        }else{
            // it's already encoded
            tmp_byte[0] = (tmprr->rdlength >> 8) & 0xFF;
            tmp_byte[1] = (tmprr->rdlength) & 0xFF;
            dyn_buffer_append(db, tmp_byte, 2);
        }
        // next rr
        tmprr = tmprr->next;
    }
    return sdns_rcode_NoError;
}


/*
 * @brief receives a buffer and fill it with wire format using given sdns_message object
 * @param msg sdns_message context
 *
 * If the __buffer__ param is NULL, we are going to allocate it using malloc function.
 *
 * @return 0 on success other values for failure
 *
 * possible values for error:
 *  - -2 the user-provided buffer is not big enough
 */
int sdns_to_wire(sdns_context * ctx){
    if (!ctx)
        return SDNS_ERROR_BUFFER_TOO_SHORT;
    dyn_buffer * db = dyn_buffer_init(ctx->raw, ctx->raw_len, ctx->cursor - ctx->raw);
    if (NULL == db)
        return SDNS_ERROR_MEMORY_ALLOC_FAILD;
    char tmp_byte[8] = {0x00};
    char tmpbuff[4] = {0};

    tmp_byte[0] = (ctx->msg->header.id >> 8) & 0xFF;
    tmp_byte[1] = (ctx->msg->header.id) & 0xFF;
    dyn_buffer_append(db, tmp_byte, 2);
    
    // first 8 bits of flags
    tmpbuff[0] = 0x00;
    tmpbuff[0] |= ctx->msg->header.qr > 0?0b10000000:0x00;
    tmpbuff[0] |= (ctx->msg->header.opcode << 3);
    tmpbuff[0] |= (ctx->msg->header.aa << 2);
    tmpbuff[0] |= (ctx->msg->header.tc << 1);
    tmpbuff[0] |= (ctx->msg->header.rd & 0x01);
    dyn_buffer_append(db, tmpbuff, 1);
 
    // second 8 bits of flags
    tmpbuff[0] = 0x00;
    tmpbuff[0] |= (ctx->msg->header.ra << 7);
    tmpbuff[0] |= (ctx->msg->header.z << 6);
    tmpbuff[0] |= (ctx->msg->header.AD << 5);
    tmpbuff[0] |= (ctx->msg->header.CD << 4);
    tmpbuff[0] |= (ctx->msg->header.rcode & 0x0F);
    dyn_buffer_append(db, tmpbuff, 1);


    tmp_byte[0] = (ctx->msg->header.qdcount >> 8) & 0xFF;
    tmp_byte[1] = (ctx->msg->header.qdcount) & 0xFF;
    dyn_buffer_append(db, tmp_byte, 2);


    tmp_byte[0] = (ctx->msg->header.ancount >> 8) & 0xFF;
    tmp_byte[1] = (ctx->msg->header.ancount) & 0xFF;
    dyn_buffer_append(db, tmp_byte, 2);


    tmp_byte[0] = (ctx->msg->header.nscount >> 8) & 0xFF;
    tmp_byte[1] = (ctx->msg->header.nscount) & 0xFF;
    dyn_buffer_append(db, tmp_byte, 2);



    tmp_byte[0] = (ctx->msg->header.arcount >> 8) & 0xFF;
    tmp_byte[1] = (ctx->msg->header.arcount) & 0xFF;
    dyn_buffer_append(db, tmp_byte, 2);

    char buffer[256] = {0x00};
    int res;
    // end of writing header part
    DEBUG("let's to wire the question section....");
    if (ctx->msg->question.qname == NULL){
        dyn_buffer_append(db, tmpbuff + 3, 1);  // we just add 0x00 to the buffer
    }else{
        if (strlen(ctx->msg->question.qname) > 255){
            dyn_buffer_free(db);
            ctx->raw = NULL;
            ctx->raw_len = 0;
            ctx->err = SDNS_ERROR_HOSTNAME_TOO_LONG;
            return SDNS_ERROR_HOSTNAME_TOO_LONG;
        }
        // encode the label and store it
        memset(buffer, 0x00, 256);
        res = _encode_label_simple(ctx->msg->question.qname, buffer);
        if (res != SDNS_ERROR_ELSIMPLE){
            dyn_buffer_free(db);
            ctx->raw = NULL;
            ctx->raw_len = 0;
            ERROR("Encoding name for question\n");
            ctx->err = res;
            return res;
        }
        dyn_buffer_append(db, buffer, strlen(buffer)+1);
    }

    tmp_byte[0] = (ctx->msg->question.qtype >> 8) & 0xFF;
    tmp_byte[1] = (ctx->msg->question.qtype) & 0xFF;
    dyn_buffer_append(db, tmp_byte, 2);

    tmp_byte[0] = (ctx->msg->question.qclass >> 8) & 0xFF;
    tmp_byte[1] = (ctx->msg->question.qclass) & 0xFF;
    dyn_buffer_append(db, tmp_byte, 2);
    // end of question section

    // let's do the answer section
    if (ctx->msg->header.ancount > 0){
        INFO("start writing answer section.....");
        res = _encode_write_section(ctx, db, ctx->msg->answer);
        if (res != sdns_rcode_NoError){
            ctx->err = res;
            dyn_buffer_free(db);
            ctx->raw = NULL;
            ctx->raw_len = 0;
            return res;
        }
    }
    // let's do the authority section
    if (ctx->msg->header.nscount > 0){
        INFO("start writing authority section.....");
        res = _encode_write_section(ctx, db, ctx->msg->authority);
        if (res != sdns_rcode_NoError){
            ctx->err = res;
            dyn_buffer_free(db);
            ctx->raw = NULL;
            ctx->raw_len = 0;
            return res;
        }
    }
    // let's do the additional section
    if (ctx->msg->header.arcount > 0){
        INFO("start writing additional section.....");
        res = _encode_write_section(ctx, db, ctx->msg->additional);
        if (res != sdns_rcode_NoError){
            ctx->err = res;
            dyn_buffer_free(db);
            ctx->raw = NULL;
            ctx->raw_len = 0;
            return res;
        }
    }
    // we are done
    ctx->raw = db->buffer;
    ctx->raw_len = db->cursor;
    free(db);       // we don't use dyn_buffer_free() here
    return 0;
}

void sdns_class_to_string(uint16_t cls, char * buff){
    if (cls == sdns_rr_class_IN)
        TO_OUTPUT(buff, "IN")
    else if (cls == sdns_rr_class_CH)
        TO_OUTPUT(buff, "CH")
    else if (cls == sdns_rr_class_CS)
        TO_OUTPUT(buff, "CS")
    else if (cls == sdns_rr_class_HS)
        TO_OUTPUT(buff, "HS")
    else if (cls == sdns_q_class_STAR)
        TO_OUTPUT(buff, "STAR")
    else
        sprintf(buff, "CLASS%d", cls);
}

void sdns_rr_type_to_string(uint16_t t, char * buff){
    // if buff is NULL, the result will be printed to stdout
    // else -> the result will be printed in buff and it must
    // be long enough to contain the result
    if (t == sdns_rr_type_A)
        TO_OUTPUT(buff, "A")
    else if (t == sdns_rr_type_CDS)
        TO_OUTPUT(buff, "CDS")
    else if (t == sdns_rr_type_TALINK)
        TO_OUTPUT(buff, "TALINK")
    else if (t == sdns_rr_type_RKEY)
        TO_OUTPUT(buff, "RKEY")
    else if (t == sdns_rr_type_NINFO)
        TO_OUTPUT(buff, "NINFO")
    else if (t == sdns_rr_type_HIP)
        TO_OUTPUT(buff, "HIP")
    else if (t == sdns_rr_type_SMIMEA)
        TO_OUTPUT(buff, "SMIMEA")
    else if (t == sdns_rr_type_TLSA)
        TO_OUTPUT(buff, "TLSA")
    else if (t == sdns_rr_type_NSEC3PARAM)
        TO_OUTPUT(buff, "NSEC3PARAM")
    else if (t == sdns_rr_type_NSEC3)
        TO_OUTPUT(buff, "NSEC3")
    else if (t == sdns_rr_type_DHCID)
        TO_OUTPUT(buff, "DHCID")
    else if (t == sdns_rr_type_DNSKEY)
        TO_OUTPUT(buff, "DNSKEY")
    else if (t == sdns_rr_type_NSEC)
        TO_OUTPUT(buff, "NSEC")
    else if (t == sdns_rr_type_RRSIG)
        TO_OUTPUT(buff, "RRSIG")
    else if (t == sdns_rr_type_IPSECKEY)
        TO_OUTPUT(buff, "IPSECKEY")
    else if (t == sdns_rr_type_SSHFP)
        TO_OUTPUT(buff, "SSHFP")
    else if (t == sdns_rr_type_DS)
        TO_OUTPUT(buff, "DS")
    else if (t == sdns_rr_type_APL)
        TO_OUTPUT(buff, "APL")
    else if (t == sdns_rr_type_SINK)
        TO_OUTPUT(buff, "SINK")
    else if (t == sdns_rr_type_DNAME)
        TO_OUTPUT(buff, "DNAME")
    else if (t == sdns_rr_type_CDNSKEY)
        TO_OUTPUT(buff, "CDNSKEY")
    else if (t == sdns_rr_type_OPENPGPKEY)
        TO_OUTPUT(buff, "OPENPGPKEY")
    else if (t == sdns_rr_type_CSYNC)
        TO_OUTPUT(buff, "CSYNK")
    else if (t == sdns_rr_type_ZONEMD)
        TO_OUTPUT(buff, "ZONEMD")
    else if (t == sdns_rr_type_SVCB)
        TO_OUTPUT(buff, "SVCB")
    else if (t == sdns_rr_type_HTTPS)
        TO_OUTPUT(buff, "HTTPS")
    else if (t == sdns_rr_type_SPF)
        TO_OUTPUT(buff, "SPF")
    else if (t == sdns_rr_type_UINFO)
        TO_OUTPUT(buff, "UINFO")
    else if (t == sdns_rr_type_UID)
        TO_OUTPUT(buff, "UID")
    else if (t == sdns_rr_type_GID)
        TO_OUTPUT(buff, "GID")
    else if (t == sdns_rr_type_UNSPEC)
        TO_OUTPUT(buff, "UNSPEC")
    else if (t == sdns_rr_type_NID)
        TO_OUTPUT(buff, "NID")
    else if (t == sdns_rr_type_L32)
        TO_OUTPUT(buff, "L32")
    else if (t == sdns_rr_type_L64)
        TO_OUTPUT(buff, "L64")
    else if (t == sdns_rr_type_LP)
        TO_OUTPUT(buff, "LP")
    else if (t == sdns_rr_type_EUI48)
        TO_OUTPUT(buff, "EUI48")
    else if (t == sdns_rr_type_EUI64)
        TO_OUTPUT(buff, "EUI64")
    else if (t == sdns_rr_type_TKEY)
        TO_OUTPUT(buff, "TKEY")
    else if (t == sdns_rr_type_TSIG)
        TO_OUTPUT(buff, "TSIG")
    else if (t == sdns_rr_type_IXFR)
        TO_OUTPUT(buff, "IXFR")
    else if (t == sdns_rr_type_AXFR)
        TO_OUTPUT(buff, "AXFR")
    else if (t == sdns_rr_type_A6)
        TO_OUTPUT(buff, "A6")
    else if (t == sdns_rr_type_CERT)
        TO_OUTPUT(buff, "CERT")
    else if (t == sdns_rr_type_KX)
        TO_OUTPUT(buff, "KX")
    else if (t == sdns_rr_type_NAPTR)
        TO_OUTPUT(buff, "NAPTR")
    else if (t == sdns_rr_type_ATMA)
        TO_OUTPUT(buff, "ATMA")
    else if (t == sdns_rr_type_SRV)
        TO_OUTPUT(buff, "SRV")
    else if (t == sdns_rr_type_NIMLOC)
        TO_OUTPUT(buff, "NIMLOC")
    else if (t == sdns_rr_type_EID)
        TO_OUTPUT(buff, "EID")
    else if (t == sdns_rr_type_NXT)
        TO_OUTPUT(buff, "NXT")
    else if (t == sdns_rr_type_LOC)
        TO_OUTPUT(buff, "LOC")
    else if (t == sdns_rr_type_AAAA)
        TO_OUTPUT(buff, "AAAA")
    else if (t == sdns_rr_type_GPOS)
        TO_OUTPUT(buff, "GPOS")
    else if (t == sdns_rr_type_PX)
        TO_OUTPUT(buff, "PX")
    else if (t == sdns_rr_type_KEY)
        TO_OUTPUT(buff, "KEY")
    else if (t == sdns_rr_type_SIG)
        TO_OUTPUT(buff, "SIG")
    else if (t == sdns_rr_type_NSAP_PTR)
        TO_OUTPUT(buff, "NSAP-PTR")
    else if (t == sdns_rr_type_NSAP)
        TO_OUTPUT(buff, "NSAP")
    else if (t == sdns_rr_type_RT)
        TO_OUTPUT(buff, "RT")
    else if (t == sdns_rr_type_ISDN)
        TO_OUTPUT(buff, "ISDN")
    else if (t == sdns_rr_type_X25)
        TO_OUTPUT(buff, "X25")
    else if (t == sdns_rr_type_AFSDB)
        TO_OUTPUT(buff, "AFSDB")
    else if (t == sdns_rr_type_RP)
        TO_OUTPUT(buff, "RP")
    else if (t == sdns_rr_type_WKS)
        TO_OUTPUT(buff, "WKS")
    else if (t == sdns_rr_type_star)
        TO_OUTPUT(buff, "*")
    else if (t == sdns_rr_type_URI)
        TO_OUTPUT(buff, "URI")
    else if (t == sdns_rr_type_CAA)
        TO_OUTPUT(buff, "CAA")
    else if (t == sdns_rr_type_AVC)
        TO_OUTPUT(buff, "AVC")
    else if (t == sdns_rr_type_DOA)
        TO_OUTPUT(buff, "DOA")
    else if (t == sdns_rr_type_AMTRELAY)
        TO_OUTPUT(buff, "AMTRELAY")
    else if (t == sdns_rr_type_RESINFO)
        TO_OUTPUT(buff, "RESINFO")
    else if (t == sdns_rr_type_TA)
        TO_OUTPUT(buff, "TA")
    else if (t == sdns_rr_type_DLV)
        TO_OUTPUT(buff, "DLV")
    else if (t == sdns_rr_type_TXT)
        TO_OUTPUT(buff, "TXT")
    else if (t == sdns_rr_type_MB)
        TO_OUTPUT(buff, "MB")
    else if (t == sdns_rr_type_MD)
        TO_OUTPUT(buff, "MD")
    else if (t == sdns_rr_type_PTR)
        TO_OUTPUT(buff, "PTR")
    else if (t == sdns_rr_type_MF)
        TO_OUTPUT(buff, "MF")
    else if (t == sdns_rr_type_MG)
        TO_OUTPUT(buff, "MG")
    else if (t == sdns_rr_type_MR)
        TO_OUTPUT(buff, "MR")
    else if (t == sdns_rr_type_MX)
        TO_OUTPUT(buff, "MX")
    else if (t == sdns_rr_type_MAILA)
        TO_OUTPUT(buff, "MAILA")
    else if (t == sdns_rr_type_MAILB)
        TO_OUTPUT(buff, "MAILB")
    else if (t == sdns_rr_type_MINFO)
        TO_OUTPUT(buff, "MINFO")
    else if (t == sdns_rr_type_CNAME)
        TO_OUTPUT(buff, "CNAME")
    else if (t == sdns_rr_type_SOA)
        TO_OUTPUT(buff, "SOA")
    else if (t == sdns_rr_type_NULL)
        TO_OUTPUT(buff, "NULL")
    else if (t == sdns_rr_type_NS)
        TO_OUTPUT(buff, "NS")
    else if (t == sdns_rr_type_OPT)
        TO_OUTPUT(buff, "OPT")
    else if (t == sdns_rr_type_HINFO)
        TO_OUTPUT(buff, "HINFO")
    else
        sprintf(buff, "TYPE%d", t);
}


void sdns_error_string(int err, char ** err_buffer){
    if (*err_buffer == NULL){
        *err_buffer = (char*) malloc_or_abort(256);
        memset(*err_buffer, 0x00, 256);
    }
    if (err == SDNS_ERROR_MEMORY_ALLOC_FAILD)
        strcpy(*err_buffer, "Failed to allocate memory using malloc()");
    else if (err == SDNS_ERROR_BUFFER_TOO_SHORT)
        strcpy(*err_buffer, "DNS packet is shorter than expected");
    else if (err == SDNS_ERROR_QNAME_IS_NULL)
        strcpy(*err_buffer, "qname param of the sdns_make_query() can not be NULL");
    else if (err == SDNS_ERROR_HOSTNAME_TOO_LONG)
        strcpy(*err_buffer, "Maximum length of a host name is 255 (RFC1034 section 3.1)");
    else if (err == SDNS_ERROR_WRONG_LABEL_SPECIFIED)
        strcpy(*err_buffer, "Each part of the label can not be more than 63 characters (RFC1034 section 3.1)");
    else if (err == SDNS_ERROR_BUFFER_IS_NULL)
        strcpy(*err_buffer, "buffer provided to function can not be NULL");
    else if (err == SDNS_ERROR_INVALID_DNS_PACKET)
        strcpy(*err_buffer, "The received packet is not a valid DNS packet");
    else if (err == SDNS_ERROR_ILLEGAL_COMPRESSION)
        strcpy(*err_buffer, "Compressed label detected while is not allowed");
    else if (err == SDNS_ERROR_MORE_THAN_ONE_QUESTION_FOUND)
        strcpy(*err_buffer, "The question section has more than one part");
    else if (err == SDNS_ERROR_LABEL_MAX_63)
        strcpy(*err_buffer, "The maximum possible length of the label is 63 (RFC1034 section 3.1)");
    else if (err == SDNS_ERROR_RR_SECTION_MALFORMED)
        strcpy(*err_buffer, "Resource Record Section is malformed");
    else if (err == SDNS_ERROR_INVALID_HEX_VALUE)
        strcpy(*err_buffer, "Invalid HEX representation of the input string");
    else if (err == SDNS_ERROR_WRONG_INPUT_PARAMETER)
        strcpy(*err_buffer, "Wrong input parameter for the function");
    else if (err == SDNS_ERROR_NSID_NOT_FOUND)
        strcpy(*err_buffer, "There is no NSID in the DNS packet");
    else if (err == SDNS_ERROR_CLIENT_COOKIE_NOT_FOUND)
        strcpy(*err_buffer, "There is no client cookie in the DNS packet");
    else if (err == SDNS_ERROR_CHARACTER_STRING_TOO_LONG)
        strcpy(*err_buffer, "Maximum size of a <character-string> is 255 bytes");
    else if (err == SDNS_ERROR_NO_ANSWER_FOUND)
        strcpy(*err_buffer, "There is no answer section in the DNS context");
    else if (err == SDNS_ERROR_NO_AUTHORITY_FOUND)
        strcpy(*err_buffer, "There is no authority section in the DNS context");
    else if (err == SDNS_ERROR_NO_ADDITIONAL_FOUND)
        strcpy(*err_buffer, "There is no additional section in the DNS context");
    else if (err == SDNS_ERROR_ADDDITIONAL_RR_OPT)
        strcpy(*err_buffer, "Additional section is OPT RR. Use other functions to fetch it");
    else if (err == sdns_rcode_FormErr)
        strcpy(*err_buffer, "FormErr");
    else if (err == sdns_rcode_NoError)
        strcpy(*err_buffer, "NoError");
    else if (err == sdns_rcode_ServFail)
        strcpy(*err_buffer, "ServFail");
    else if (err == sdns_rcode_NXDomain)
        strcpy(*err_buffer, "NXDomain");
    else if (err == sdns_rcode_NotImp)
        strcpy(*err_buffer, "NotImp");
    else if (err == sdns_rcode_Refused)
        strcpy(*err_buffer, "Refused");
    else if (err == sdns_rcode_YXDomain)
        strcpy(*err_buffer, "YXDomain");
    else if (err == sdns_rcode_YXRRSet)
        strcpy(*err_buffer, "YXRRSet");
    else if (err == sdns_rcode_NXRRSet)
        strcpy(*err_buffer, "NXRRSet");
    else if (err == sdns_rcode_NotAuth)
        strcpy(*err_buffer, "NotAuth");
    else if (err == sdns_rcode_NotZone)
        strcpy(*err_buffer, "NotZone");
    else if (err == sdns_rcode_DSOTYPENI)
        strcpy(*err_buffer, "DSOTYPENI");
    else if (err == sdns_rcode_BADVERS)
        strcpy(*err_buffer, "BADVERS");
    else if (err == sdns_rcode_BADSIG)
        strcpy(*err_buffer, "BADSIG");
    else if (err == sdns_rcode_BADKEY)
        strcpy(*err_buffer, "BADKEY");
    else if (err == sdns_rcode_BADTIME)
        strcpy(*err_buffer, "BADTIME");
    else if (err == sdns_rcode_BADMODE)
        strcpy(*err_buffer, "BADMODE");
    else if (err == sdns_rcode_BADNAME)
        strcpy(*err_buffer, "BADNAME");
    else if (err == sdns_rcode_BADALG)
        strcpy(*err_buffer, "BADALG");
    else if (err == sdns_rcode_BADTRUNC)
        strcpy(*err_buffer, "BADTRUNC");
    else if (err == sdns_rcode_BADCOOKIE)
        strcpy(*err_buffer, "BADCOOKIE");
    else if (err == sdns_rcode_Reserved)
        strcpy(*err_buffer, "Reserved");
    else if (err >= 24 && err <= 3840)
        strcpy(*err_buffer, "Unassigned");
    else if (err >= 3841 && err <= 4095)
        strcpy(*err_buffer, "Reserved for Private Use");
    else if (err >= 4096 && err <= 65534)
        strcpy(*err_buffer, "Unassigned");
    else if (err == SDNS_ERROR_RR_NULL)
        strcpy(*err_buffer, "Resource record parameter is NULL");
    else
        strcpy(*err_buffer, "Non-standard error code");
}

int sdns_make_query(sdns_context * ctx, sdns_rr_type qtype,
                    sdns_q_class cls, char * qname, int enable_edns0){
    if (!ctx)
        return SDNS_ERROR_BUFFER_IS_NULL;
    if (!qname)
        return SDNS_ERROR_QNAME_IS_NULL;
    // set the header values
    ctx->msg->header.id = (uint16_t)(rand() % 0xFFFF);
    ctx->msg->header.qr = 0;          // this is a query
    ctx->msg->header.aa = 0;          // dont give a fuck if it's authoritative answer
    ctx->msg->header.ra = 0;          // don't give a fuck if recursion available or not
    ctx->msg->header.rd = 1;          // we want recursion
    ctx->msg->header.rcode = 0;       // noerror 
    ctx->msg->header.tc = 0;          // no truncatation
    ctx->msg->header.z = 0;           // reserved for now
    ctx->msg->header.AD = 0;          // set AD=0
    ctx->msg->header.CD = 0;          // set CD=0
    ctx->msg->header.qdcount = 1;     // one question section
    ctx->msg->header.ancount = 0;     // no answer section
    ctx->msg->header.nscount = 0;     // no authority section
    ctx->msg->header.arcount = 0;     // no additional
    ctx->msg->header.opcode = 0;      // this is a query
    // set the question section of the message
    ctx->msg->question.qclass = cls;
    ctx->msg->question.qtype = qtype;
    // convet domain name to a series of 
    // N<chars>M<chars>
    ctx->msg->question.qname = qname;
    // empty answer
    ctx->msg->answer = NULL;
    // empty authority
    ctx->msg->authority = NULL;
    // empty additional section
    ctx->msg->additional = NULL;

    if (enable_edns0){      // we need to add an empty edns0 packet
        sdns_opt_rdata * opt = NULL;
        int res = sdns_create_edns_option(0, 0, NULL, &opt);
        if (res != sdns_rcode_NoError){
            ERROR("Error adding edns0 to the query packet");
            return res;
        }
        res = sdns_add_edns(ctx, opt);
        if (!res)
            return res;
    }
    return 0;
}


/**
 * @brief decode a resource record section and return a pointer.
 * @param rr_section a pointer to a RR section we want to decode
 * @param rr_type a value (number) specifies the type of the section (A, AAAA, ...)
 *
 * The return value must be cast by the caller based on the type
 *
 * @return a pointer to the structure of the decoded section.
 */
void * sdns_decode_rr_section(sdns_context* ctx, sdns_rr * rr_section){
    if (NULL == rr_section)
        return NULL;
    uint16_t rr_type = rr_section->type;
    switch (rr_type){
        case sdns_rr_type_A:
            return (void*) sdns_decode_rr_A(ctx, rr_section);
        case sdns_rr_type_TXT:
            return (void*) sdns_decode_rr_TXT(ctx, rr_section);
        case sdns_rr_type_SOA:
            return (void*) sdns_decode_rr_SOA(ctx, rr_section);
        case sdns_rr_type_AAAA:
            return (void*) sdns_decode_rr_AAAA(ctx, rr_section);
        case sdns_rr_type_MX:
            return (void*) sdns_decode_rr_MX(ctx, rr_section);
        case sdns_rr_type_RRSIG:
            return (void*) sdns_decode_rr_RRSIG(ctx, rr_section);
        case sdns_rr_type_LP:
            return (void*) sdns_decode_rr_LP(ctx, rr_section);
        case sdns_rr_type_L32:
            return (void*) sdns_decode_rr_L32(ctx, rr_section);
        case sdns_rr_type_L64:
            return (void*) sdns_decode_rr_L64(ctx, rr_section);
        case sdns_rr_type_NS:
            return (void*) sdns_decode_rr_NS(ctx, rr_section);
        case sdns_rr_type_NID:
            return (void*) sdns_decode_rr_NID(ctx, rr_section);
        case sdns_rr_type_CNAME:
            return (void*) sdns_decode_rr_CNAME(ctx, rr_section);
        case sdns_rr_type_PTR:
            return (void*) sdns_decode_rr_PTR(ctx, rr_section);
        case sdns_rr_type_SRV:
            return (void*) sdns_decode_rr_SRV(ctx, rr_section);
        case sdns_rr_type_HINFO:
            return (void*) sdns_decode_rr_HINFO(ctx, rr_section);
        case sdns_rr_type_URI:
            return (void*) sdns_decode_rr_URI(ctx, rr_section);
        case sdns_rr_type_CAA:
            return (void*) sdns_decode_rr_CAA(ctx, rr_section);
        default:
            // eventually replace this default by other RRs
            return NULL;
    }
    return NULL;
}

sdns_rr_A * sdns_copy_rr_A(sdns_context * ctx, sdns_rr * rr){
    // assuming rr is sdns_rr_A structure, deep copy the structure
    sdns_rr_A* copy = sdns_init_rr_A(0);
    copy->address = ((sdns_rr_A*)(rr->psdns_rr))->address;
    return (void*)copy;
}

sdns_rr_TXT* sdns_copy_rr_TXT(sdns_context * ctx, sdns_rr * rr){
   sdns_rr_TXT * copy = sdns_init_rr_TXT(NULL, 0);
   sdns_rr_TXT * tmp = ((sdns_rr_TXT*)(rr->psdns_rr));
   dyn_buffer * db = dyn_buffer_init(NULL, 0, 0);
   if (NULL == db){
        free(copy);
        return NULL;
   }
   sdns_rr_TXT * copy_pointer = copy;
   while(tmp){
        copy_pointer->character_string.content = db->buffer + db->cursor;
        copy_pointer->character_string.len = tmp->character_string.len;
        dyn_buffer_append(db, tmp->character_string.content, tmp->character_string.len);
        if (tmp->next){
            copy_pointer->next = sdns_init_rr_TXT(NULL, 0);
            copy_pointer = copy_pointer->next;
            tmp = tmp->next;
            continue;
        }else{
            break;
        }
   }
   free(db);
   return copy;
}

sdns_rr_SOA * sdns_copy_rr_SOA(sdns_context * ctx, sdns_rr * rr){
    //TODO: WE DON'T HAVE TEST FOR THIS FUNCTION
    sdns_rr_SOA * copy = sdns_init_rr_SOA(NULL, NULL, 0, 0, 0, 0, 0);
    sdns_rr_SOA * soa = (sdns_rr_SOA*)(rr->psdns_rr);
    copy->mname = safe_strdup(soa->mname);
    copy->rname = safe_strdup(soa->rname);
    copy->expire = soa->expire;
    copy->minimum = soa->minimum;
    copy->retry = soa->retry;
    copy->refresh = soa->refresh;
    copy->serial = soa->serial;
    return copy;
}


sdns_rr_MX * sdns_copy_rr_MX(sdns_context * ctx, sdns_rr * rr){
    sdns_rr_MX * copy = sdns_init_rr_MX(0, NULL);
    sdns_rr_MX * mx = (sdns_rr_MX*)rr->psdns_rr;
    copy->preference = mx->preference;
    copy->exchange = safe_strdup(mx->exchange);
    return copy;
}

sdns_rr_CNAME * sdns_copy_rr_CNAME(sdns_context * ctx, sdns_rr * rr){
    //TODO: WE DON'T HAVE TEST FOR THIS FUNCTION
    sdns_rr_CNAME * copy = sdns_init_rr_CNAME(NULL);
    copy->CNAME = safe_strdup(((sdns_rr_CNAME*)rr->psdns_rr)->CNAME);
    return copy;
}

sdns_rr_PTR * sdns_copy_rr_PTR(sdns_context * ctx, sdns_rr * rr){
    //TODO: WE DON'T HAVE TEST FOR THIS FUNCTION
    sdns_rr_PTR * copy = sdns_init_rr_PTR(NULL);
    copy->PTRDNAME = safe_strdup(((sdns_rr_PTR*)rr->psdns_rr)->PTRDNAME);
    return copy;
}

sdns_rr_NID * sdns_copy_rr_NID(sdns_context * ctx, sdns_rr * rr){
    //TODO: WE DONT HAVE TEST FOR THIS FUNCTION
    sdns_rr_NID * copy = sdns_init_rr_NID(0, NULL);
    copy->Preference = ((sdns_rr_NID*)rr->psdns_rr)->Preference;
    if (((sdns_rr_NID*)rr->psdns_rr)->NodeId != NULL)
        copy->NodeId = mem_copy(((sdns_rr_NID*)rr->psdns_rr)->NodeId, 8);
    return copy;
}

sdns_rr_HINFO * sdns_copy_rr_HINFO(sdns_context * ctx, sdns_rr * rr){
    //TODO: WE DONT HAVE TEST FOR THIS FUNCTION
    sdns_rr_HINFO * copy = sdns_init_rr_HINFO(0, NULL, 0, NULL);
    sdns_rr_HINFO * tmp = (sdns_rr_HINFO *)rr->psdns_rr;
    if (tmp->cpu)
        copy->cpu = mem_copy(tmp->cpu, tmp->cpu_len);
    if (tmp->os)
        copy->os = mem_copy(tmp->os, tmp->os_len);
    copy->cpu_len = tmp->cpu_len;
    copy->os_len = tmp->os_len;
    return copy;
}

sdns_rr_URI * sdns_copy_rr_URI(sdns_context * ctx, sdns_rr * rr){
    //TODO: WE DONT HAVE TEST FOR THIS FUNCTION
    sdns_rr_URI * copy = sdns_init_rr_URI(0, 0, NULL, 0);
    sdns_rr_URI * tmp = (sdns_rr_URI*)rr->psdns_rr;
    copy->target_len = tmp->target_len;
    copy->Priority = tmp->Priority;
    copy->Weight = tmp->Weight;
    if (tmp->Target)
        copy->Target = mem_copy(tmp->Target, tmp->target_len);
    return copy;
}

sdns_rr_NS * sdns_copy_rr_NS(sdns_context * ctx, sdns_rr * rr){
    sdns_rr_NS * copy = sdns_init_rr_NS(NULL);
    sdns_rr_NS * tmp = (sdns_rr_NS*)rr->psdns_rr;
    copy->NSDNAME = safe_strdup(tmp->NSDNAME);
    return copy;
}

sdns_rr_SRV * sdns_copy_rr_SRV(sdns_context * ctx, sdns_rr * rr){
    sdns_rr_SRV * copy = sdns_init_rr_SRV(0, 0, 0, NULL);
    sdns_rr_SRV * tmp = (sdns_rr_SRV*)rr->psdns_rr;
    copy->Weight = tmp->Weight;
    copy->Port = tmp->Port;
    copy->Priority = tmp->Priority;
    copy->Target = safe_strdup(tmp->Target);
    return copy;
}

void * sdns_copy_rr_section(sdns_context * ctx, sdns_rr* rr_section){
    //TODO: implement the code
    if (NULL == rr_section)
        return NULL;
    uint16_t rr_type = rr_section->type;
    switch (rr_type){
        case sdns_rr_type_A:
            return (void*) sdns_copy_rr_A(ctx, rr_section);
        case sdns_rr_type_TXT:
            return (void*) sdns_copy_rr_TXT(ctx, rr_section);
        case sdns_rr_type_SOA:
            return (void*) sdns_copy_rr_SOA(ctx, rr_section);
//        case sdns_rr_type_AAAA:
//            return (void*) sdns_copy_rr_AAAA(ctx, rr_section);
        case sdns_rr_type_MX:
            return (void*) sdns_copy_rr_MX(ctx, rr_section);
//        case sdns_rr_type_RRSIG:
//            return (void*) sdns_copy_rr_RRSIG(ctx, rr_section);
//        case sdns_rr_type_LP:
//            return (void*) sdns_copy_rr_LP(ctx, rr_section);
//        case sdns_rr_type_L32:
//            return (void*) sdns_copy_rr_L32(ctx, rr_section);
//        case sdns_rr_type_CAA:
//            return (void*) sdns_copy_rr_CAA(ctx, rr_section);
//        case sdns_rr_type_L64:
//            return (void*) sdns_copy_rr_L64(ctx, rr_section);
        case sdns_rr_type_NS:
            return (void*) sdns_copy_rr_NS(ctx, rr_section);
        case sdns_rr_type_NID:
            return (void*) sdns_copy_rr_NID(ctx, rr_section);
          case sdns_rr_type_CNAME:
            return (void*) sdns_copy_rr_CNAME(ctx, rr_section);
        case sdns_rr_type_PTR:
            return (void*) sdns_copy_rr_PTR(ctx, rr_section);
        case sdns_rr_type_SRV:
            return (void*) sdns_copy_rr_SRV(ctx, rr_section);
        case sdns_rr_type_HINFO:
            return (void*) sdns_copy_rr_HINFO(ctx, rr_section);
        case sdns_rr_type_URI:
            return (void*) sdns_copy_rr_URI(ctx, rr_section);
        default:
            // eventually replace this default by other RRs
            return NULL;
    }
    return NULL;
}



sdns_rr_MX * sdns_init_rr_MX(uint16_t preference, char * exchange){
    sdns_rr_MX * mx = (sdns_rr_MX*) malloc_or_abort(sizeof(sdns_rr_MX));
    mx->preference = preference;
    mx->exchange = exchange;
    return mx;
}

void sdns_free_rr_MX(sdns_rr_MX * mx){
    if (NULL == mx)
        return;
    free(mx->exchange);
    free(mx);
}

sdns_rr_MX * sdns_decode_rr_MX(sdns_context * ctx, sdns_rr * rr){
    if (NULL == ctx || NULL == rr)
        return NULL;
    sdns_rr_MX * mx = sdns_init_rr_MX(0, NULL);
    ctx->cursor = rr->rdata;
    char * qname = NULL;
    if (rr->rdlength < 2){      // we must have preference
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_MX(mx);
        return NULL;
    }
    if (ctx->raw_len - (ctx->cursor - ctx->raw) < 2){
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        sdns_free_rr_MX(mx);
        return NULL;
    }
    mx->preference = read_uint16_from_buffer(ctx->cursor);
    ctx->cursor += 2;
    int res = decode_name(ctx, &qname);
    if (res != sdns_rcode_NoError){
        ERROR("Can not parse the exchange name of MX record: %d\n", res);
        sdns_free_rr_MX(mx);
        return NULL;
    }
    mx->exchange = qname;
    return mx;
}


sdns_rr_HINFO * sdns_decode_rr_HINFO(sdns_context * ctx, sdns_rr * rr){
    if (ctx == NULL || rr == NULL)
        return NULL;
    sdns_rr_HINFO * hinfo = sdns_init_rr_HINFO(0, NULL, 0, NULL);
    uint16_t rd_len = rr->rdlength;
    if (rd_len < 2){  // the minimum length of hinfo record is 2
        sdns_free_rr_HINFO(hinfo);
        return NULL;
    }
    char * tmp = rr->rdata;
    uint16_t cnt = 0;
    hinfo->cpu_len = (uint8_t)tmp[cnt];
    cnt += 1;
    if (rd_len - cnt < hinfo->cpu_len){
        sdns_free_rr_HINFO(hinfo);
        return NULL;
    }
    if (hinfo->cpu_len == 0){
        hinfo->cpu = NULL;
    }else{
        hinfo->cpu = (char*) malloc_or_abort(hinfo->cpu_len);
        // copy bytes
        memcpy(hinfo->cpu, tmp + cnt, hinfo->cpu_len);
    }
    cnt += hinfo->cpu_len;
    if (rd_len - cnt < 1){
        sdns_free_rr_HINFO(hinfo);
        return NULL;
    }
    // read os len
    hinfo->os_len = (uint8_t) tmp[cnt];
    cnt += 1;
    if (rd_len - cnt < hinfo->os_len){
        sdns_free_rr_HINFO(hinfo);
        return NULL;
    }
    if (hinfo->os_len == 0){
        hinfo->os = NULL;
    }else{
        hinfo->os = (char*) malloc_or_abort(hinfo->os_len);
        // copy bytes
        memcpy(hinfo->os, tmp + cnt, hinfo->os_len);
    }
    return hinfo;
}

sdns_message * sdns_init_message(void){
    sdns_message * msg = (sdns_message*) malloc_or_abort(sizeof(sdns_message));
    msg->question.qname = NULL;
    msg->answer = NULL;
    msg->additional = NULL;
    msg->authority = NULL;
    msg->header.ancount = 0;
    msg->header.arcount = 0;
    msg->header.qdcount = 0;
    msg->header.nscount = 0;
    return msg;
}

void sdns_free_rr(sdns_rr * rr){
    if (NULL == rr)
        return;
    sdns_rr_type rr_type = rr->type;
    void * tmp = rr->psdns_rr;
    if (rr_type  == sdns_rr_type_A)
        return sdns_free_rr_A((sdns_rr_A*)tmp);
    else if (rr_type == sdns_rr_type_TXT)
        return sdns_free_rr_TXT((sdns_rr_TXT*)tmp);
    else if (rr_type == sdns_rr_type_MX)
        return sdns_free_rr_MX((sdns_rr_MX*)tmp);
    else if (rr_type == sdns_rr_type_SOA)
        return sdns_free_rr_SOA((sdns_rr_SOA*)tmp);
    else if (rr_type == sdns_rr_type_PTR)
        return sdns_free_rr_PTR((sdns_rr_PTR*)tmp);
    else if (rr_type == sdns_rr_type_L32)
        return sdns_free_rr_L32((sdns_rr_L32*)tmp);
    else if (rr_type == sdns_rr_type_CNAME)
        return sdns_free_rr_CNAME((sdns_rr_CNAME*)tmp);
    else if (rr_type == sdns_rr_type_NS)
        return sdns_free_rr_NS((sdns_rr_NS*)tmp);
    else if (rr_type == sdns_rr_type_RRSIG)
        return sdns_free_rr_RRSIG((sdns_rr_RRSIG*)tmp);
    else if (rr_type == sdns_rr_type_AAAA)
        return sdns_free_rr_AAAA((sdns_rr_AAAA*)tmp);
    else if (rr_type == sdns_rr_type_HINFO)
        return sdns_free_rr_HINFO((sdns_rr_HINFO*)tmp);
    else if (rr_type == sdns_rr_type_SRV)
        return sdns_free_rr_SRV((sdns_rr_SRV*)tmp);
    else if (rr_type == sdns_rr_type_NID)
        return sdns_free_rr_NID((sdns_rr_NID*)tmp);
    else if (rr_type == sdns_rr_type_URI)
        return sdns_free_rr_URI((sdns_rr_URI*)tmp);
    else if (rr_type == sdns_rr_type_CAA)
        return sdns_free_rr_CAA((sdns_rr_CAA*)tmp);
    if (rr_type == sdns_rr_type_OPT){
        // we need to free the options of edns0
        sdns_opt_rdata * opt = rr->opt_rdata;
        sdns_opt_rdata * tmp = opt;
        while (opt){
            free(opt->option_data);
            tmp = opt->next;
            free(opt);
            opt = tmp;
        }
    }
}

void sdns_free_section(sdns_rr * rr){
    sdns_rr * sec = rr;
    sdns_rr * tmp = sec;
    while(sec){
        free(sec->name);
        if (sec->decoded){
            // we have to free per structure
            sdns_free_rr(sec);
        }else{
            // just free the pointer
        }
        tmp = sec->next;
        free(sec);
        sec = tmp;
    }
}

static void sdns_free_message(sdns_message * msg){
    if (NULL == msg)
        return;
    free(msg->question.qname);
    //free all in answer section
    if (msg->header.ancount > 0){
        sdns_rr * sec = msg->answer;
        sdns_rr * tmp = sec;
        while(sec){
            free(sec->name);
            if (sec->decoded){
                // we have to free per structure
                sdns_free_rr(sec);
            }else{
                // just free the pointer
                // we should not free it as it's part of the original memory
            }
            tmp = sec->next;
            free(sec);
            sec = tmp;
        }
    }
    if (msg->header.arcount > 0){
        sdns_rr * sec = msg->additional;
        sdns_rr * tmp = sec;
        while(sec){
            free(sec->name);
            if (sec->decoded){
                // we have to free per structure
                sdns_free_rr(sec);
            }else{
                // just free the pointer
            }
            tmp = sec->next;
            free(sec);
            sec = tmp;
        }
    }
    if (msg->header.nscount > 0){
        sdns_rr * sec = msg->authority;
        sdns_rr * tmp = sec;
        while(sec){
            free(sec->name);
            if (sec->decoded){
                // we have to free per structure
                sdns_free_rr(sec);
            }else{
                // just free the pointer
            }
            tmp = sec->next;
            free(sec);
            sec = tmp;
        }
    }
    // and finally
    free(msg);
    return;
}

sdns_rr * sdns_init_rr(char * name, uint16_t type, uint16_t class, uint32_t ttl,
                       uint16_t rdlength, uint8_t decoded, void * rdata){
    sdns_rr * rr = (sdns_rr*)malloc_or_abort(sizeof(sdns_rr));
    rr->name = name;
    rr->type = type;
    rr->class = class;
    rr->ttl = ttl;
    rr->rdlength = rdlength;
    rr->decoded = decoded;
    if (rr->decoded)
        rr->psdns_rr = rdata;
    else
        rr->rdata = (char*) rdata;
    rr->next = NULL;
    return rr;
}


int sdns_convert_type_to_int(char * type){
    // no allocation no leak
    if (type == NULL)
        return -1;
    if (strcasecmp(type, "A") == 0)
        return sdns_rr_type_A;
    if (strcasecmp(type, "NS") == 0)
        return sdns_rr_type_NS;
    if (strcasecmp(type, "MD") == 0)
        return sdns_rr_type_MD;
    if (strcasecmp(type, "MF") == 0)
        return sdns_rr_type_MF;
    if (strcasecmp(type, "CNAME") == 0)
        return sdns_rr_type_CNAME;
    if (strcasecmp(type, "SOA") == 0)
        return sdns_rr_type_SOA;
    if (strcasecmp(type, "MB") == 0)
        return sdns_rr_type_MB;
    if (strcasecmp(type, "MG") == 0)
        return sdns_rr_type_MG;
    if (strcasecmp(type, "MR") == 0)
        return sdns_rr_type_MR;
    if (strcasecmp(type, "NULL") == 0)
        return sdns_rr_type_NULL;
    if (strcasecmp(type, "WKS") == 0)
        return sdns_rr_type_WKS;
    if (strcasecmp(type, "PTR") == 0)
        return sdns_rr_type_PTR;
    if (strcasecmp(type, "HINFO") == 0)
        return sdns_rr_type_HINFO;
    if (strcasecmp(type, "MINFO") == 0)
        return sdns_rr_type_MINFO;
    if (strcasecmp(type, "MX") == 0)
        return sdns_rr_type_MX;
    if (strcasecmp(type, "TXT") == 0)
        return sdns_rr_type_TXT;
    if (strcasecmp(type, "RP") == 0)
        return sdns_rr_type_RP;
    if (strcasecmp(type, "AFSDB") == 0)
        return sdns_rr_type_AFSDB;
    if (strcasecmp(type, "X25") == 0)
        return sdns_rr_type_X25;
    if (strcasecmp(type, "ISDN") == 0)
        return sdns_rr_type_ISDN;
    if (strcasecmp(type, "RT") == 0)
        return sdns_rr_type_RT;
    if (strcasecmp(type, "NSAP") == 0)
        return sdns_rr_type_NSAP;
    if (strcasecmp(type, "NSAP-PTR") == 0)
        return sdns_rr_type_NSAP_PTR;
    if (strcasecmp(type, "SIG") == 0)
        return sdns_rr_type_SIG;
    if (strcasecmp(type, "KEY") == 0)
        return sdns_rr_type_KEY;
    if (strcasecmp(type, "PX") == 0)
        return sdns_rr_type_PX;
    if (strcasecmp(type, "GPOS") == 0)
        return sdns_rr_type_GPOS;
    if (strcasecmp(type, "AAAA") == 0)
        return sdns_rr_type_AAAA;
    if (strcasecmp(type, "LOC") == 0)
        return sdns_rr_type_LOC;
    if (strcasecmp(type, "NXT") == 0)
        return sdns_rr_type_NXT;
    if (strcasecmp(type, "EID") == 0)
        return sdns_rr_type_EID;
    if (strcasecmp(type, "NIMLOC") == 0)
        return sdns_rr_type_NIMLOC;
    if (strcasecmp(type, "SRV") == 0)
        return sdns_rr_type_SRV;
    if (strcasecmp(type, "ATMA") == 0)
        return sdns_rr_type_ATMA;
    if (strcasecmp(type, "NAPTR") == 0)
        return sdns_rr_type_NAPTR;
    if (strcasecmp(type, "KX") == 0)
        return sdns_rr_type_KX;
    if (strcasecmp(type, "CERT") == 0)
        return sdns_rr_type_CERT;
    if (strcasecmp(type, "A6") == 0)
        return sdns_rr_type_A6;
    if (strcasecmp(type, "DNAME") == 0)
        return sdns_rr_type_DNAME;
    if (strcasecmp(type, "SINK") == 0)
        return sdns_rr_type_SINK;
    if (strcasecmp(type, "OPT") == 0)
        return sdns_rr_type_OPT;
    if (strcasecmp(type, "APL") == 0)
        return sdns_rr_type_APL;
    if (strcasecmp(type, "DS") == 0)
        return sdns_rr_type_DS;
    if (strcasecmp(type, "SSHFP") == 0)
        return sdns_rr_type_SSHFP;
    if (strcasecmp(type, "IPSECKEY") == 0)
        return sdns_rr_type_IPSECKEY;
    if (strcasecmp(type, "RRSIG") == 0)
        return sdns_rr_type_RRSIG;
    if (strcasecmp(type, "NSEC") == 0)
        return sdns_rr_type_NSEC;
    if (strcasecmp(type, "DNSKEY") == 0)
        return sdns_rr_type_DNSKEY;
    if (strcasecmp(type, "DHCID") == 0)
        return sdns_rr_type_DHCID;
    if (strcasecmp(type, "NSEC3") == 0)
        return sdns_rr_type_NSEC3;
    if (strcasecmp(type, "NSEC3PARAM") == 0)
        return sdns_rr_type_NSEC3PARAM;
    if (strcasecmp(type, "TLSA") == 0)
        return sdns_rr_type_TLSA;
    if (strcasecmp(type, "SMIMEA") == 0)
        return sdns_rr_type_SMIMEA;
    if (strcasecmp(type, "HIP") == 0)
        return sdns_rr_type_HIP;
    if (strcasecmp(type, "NINFO") == 0)
        return sdns_rr_type_NINFO;
    if (strcasecmp(type, "RKEY") == 0)
        return sdns_rr_type_RKEY;
    if (strcasecmp(type, "TALINK") == 0)
        return sdns_rr_type_TALINK;
    if (strcasecmp(type, "CDS") == 0)
        return sdns_rr_type_CDS;
    if (strcasecmp(type, "CDNSKEY") == 0)
        return sdns_rr_type_CDNSKEY;
    if (strcasecmp(type, "OPENPGPKEY") == 0)
        return sdns_rr_type_OPENPGPKEY;
    if (strcasecmp(type, "CSYNC") == 0)
        return sdns_rr_type_CSYNC;
    if (strcasecmp(type, "ZONEMD") == 0)
        return sdns_rr_type_ZONEMD;
    if (strcasecmp(type, "SVCB") == 0)
        return sdns_rr_type_SVCB;
    if (strcasecmp(type, "HTTPS") == 0)
        return sdns_rr_type_HTTPS;
    if (strcasecmp(type, "SPF") == 0)
        return sdns_rr_type_SPF;
    if (strcasecmp(type, "UINFO") == 0)
        return sdns_rr_type_UINFO;
    if (strcasecmp(type, "UID") == 0)
        return sdns_rr_type_UID;
    if (strcasecmp(type, "GID") == 0)
        return sdns_rr_type_GID;
    if (strcasecmp(type, "UNSPEC") == 0)
        return sdns_rr_type_UNSPEC;
    if (strcasecmp(type, "NID") == 0)
        return sdns_rr_type_NID;
    if (strcasecmp(type, "L32") == 0)
        return sdns_rr_type_L32;
    if (strcasecmp(type, "L64") == 0)
        return sdns_rr_type_L64;
    if (strcasecmp(type, "LP") == 0)
        return sdns_rr_type_LP;
    if (strcasecmp(type, "EUI48") == 0)
        return sdns_rr_type_EUI48;
    if (strcasecmp(type, "EUI64") == 0)
        return sdns_rr_type_EUI64;
    if (strcasecmp(type, "TKEY") == 0)
        return sdns_rr_type_TKEY;
    if (strcasecmp(type, "TSIG") == 0)
        return sdns_rr_type_TSIG;
    if (strcasecmp(type, "IXFR") == 0)
        return sdns_rr_type_IXFR;
    if (strcasecmp(type, "AXFR") == 0)
        return sdns_rr_type_AXFR;
    if (strcasecmp(type, "MAILB") == 0)
        return sdns_rr_type_MAILB;
    if (strcasecmp(type, "MAILA") == 0)
        return sdns_rr_type_MAILA;
    if (strcasecmp(type, "*") == 0)
        return 255;
    if (strcasecmp(type, "URI") == 0)
        return sdns_rr_type_URI;
    if (strcasecmp(type, "CAA") == 0)
        return sdns_rr_type_CAA;
    if (strcasecmp(type, "AVC") == 0)
        return sdns_rr_type_AVC;
    if (strcasecmp(type, "DOA") == 0)
        return sdns_rr_type_DOA;
    if (strcasecmp(type, "AMTRELAY") == 0)
        return sdns_rr_type_AMTRELAY;
    if (strcasecmp(type, "RESINFO") == 0)
        return sdns_rr_type_RESINFO;
    if (strcasecmp(type, "WALLET") == 0)
        return sdns_rr_type_WALLET;
    if (strcasecmp(type, "TA") == 0)
        return sdns_rr_type_TA;
    if (strcasecmp(type, "DLV") == 0)
        return sdns_rr_type_DLV;
    return -2;
}


int sdns_convert_class_to_int(char * cls){
    // no allocation no leak
    if (cls == NULL)
        return -1;
    if (strcasecmp(cls, "IN") == 0)
        return sdns_q_class_IN;
    if (strcasecmp(cls, "CH") == 0)
        return sdns_q_class_CH;
    if (strcasecmp(cls, "CS") == 0)
        return sdns_q_class_CH;
    if (strcasecmp(cls, "HS") == 0)
        return sdns_q_class_HS;
    if (strcasecmp(cls, "*") == 0)
        return sdns_q_class_STAR;
    return -2;
}

sdns_context * sdns_init_context(void){
    sdns_message * msg = sdns_init_message();
    sdns_context * ctx = (sdns_context*) malloc_or_abort(sizeof(sdns_context));
    ctx->msg = msg;
    ctx->raw_len = 0;
    ctx->raw = NULL;
    ctx->cursor = NULL;
    ctx->err = 0;       // no error
    return ctx;
}

void sdns_free_context(sdns_context * ctx){
    if (ctx == NULL)
        return;
    sdns_free_message(ctx->msg);
    free(ctx->raw);
    free(ctx);
}

int sdns_add_answer_section(sdns_context * ctx, sdns_rr * rr){
    // adds a new answer section to the current ones
    if (NULL == rr || NULL == ctx)
        return SDNS_ERROR_RR_NULL;
    sdns_rr * tmp = ctx->msg->answer;
    if (NULL == tmp){   // this is the first one
        ctx->msg->answer = rr;
        ctx->msg->header.ancount = 1;
        return sdns_rcode_NoError;
    }
    // this is not the first one
    while (tmp)
        if (tmp->next)
            tmp = tmp->next;
        else
            break;
    tmp->next = rr;
    ctx->msg->header.ancount += 1;
    return sdns_rcode_NoError;
}

int sdns_add_authority_section(sdns_context * ctx, sdns_rr * rr){
    // adds a new authority section to the current ones
    if (NULL == rr || NULL == ctx)
        return SDNS_ERROR_RR_NULL;
    sdns_rr * tmp = ctx->msg->authority;
    if (NULL == tmp){   // this is the first one
        ctx->msg->authority = rr;
        ctx->msg->header.nscount = 1;
        return sdns_rcode_NoError;
    }
    // this is not the first one
    while (tmp)
        if (tmp->next)
            tmp = tmp->next;
        else
            break;
    tmp->next = rr;
    ctx->msg->header.nscount += 1;
    return sdns_rcode_NoError;
}

int sdns_add_additional_section(sdns_context * ctx, sdns_rr * rr){
    // adds a new additional section to the current ones
    if (NULL == rr || NULL == ctx)
        return SDNS_ERROR_RR_NULL;
    sdns_rr * tmp = ctx->msg->additional;
    if (NULL == tmp){   // this is the first one
        ctx->msg->additional = rr;
        ctx->msg->header.arcount = 1;
        return sdns_rcode_NoError;
    }
    // this is not the first one
    // if this is OPT (type 41), we can only have one
    while (tmp)
        if (tmp->next)
            tmp = tmp->next;
        else
            break;
    tmp->next = rr;
    ctx->msg->header.arcount += 1;
    return sdns_rcode_NoError;
}

// this method will return an sdns_opt_rdata* structure and need to be freed by the caller
// returns NULL on fail
// if buffer is NULL, we will malloc it else we just fill it
int sdns_create_edns_option(uint16_t opt_code, uint16_t opt_length, char * opt_data, sdns_opt_rdata** buffer){
    if (*buffer == NULL){
        // we have to allocate it
        *buffer = (sdns_opt_rdata*)malloc_or_abort(sizeof(sdns_opt_rdata));
    }
    (*buffer)->next = NULL;
    (*buffer)->option_code = opt_code;
    (*buffer)->option_length = opt_length;
    (*buffer)->option_data = opt_data;
    return sdns_rcode_NoError;  //worst possible name for success!
}

// adds edns option to the current context
int sdns_add_edns(sdns_context * ctx, sdns_opt_rdata * opt){
    // if we have additional section -> eaither we have edns, we add this one
    // or this is the first one and we need to create the section for it
    if (NULL == ctx || NULL == opt)
        return SDNS_ERROR_RR_NULL;
    if (ctx->msg->header.arcount > 0){
        // we have some additional section
        // we need to check if it's opt(41) or not
        int found = 0;
        sdns_rr * tmp = ctx->msg->additional;
        while (tmp){
            if (tmp->type == sdns_rr_type_OPT){
                found = 1;
                break;
            }
            if (tmp->next)
                tmp = tmp->next;
            else
                break;
        }
        // tmp refers to eaither OPT (found=1) or the last entry (found=0)
        if (found){
            // if the new record is an empty edns0 record, we just skip
            // this is just edns0-aware structure, we can skip it as the packet already has edns0
            if (opt->option_length == 0 && opt->option_data == NULL && opt->option_code == 0){
                free(opt);
                return sdns_rcode_NoError;
            }
            // if the new record has data, we need to check if the last one was empty
            // or not. if the previous one is empty, we replace it and recalculate the length
            if (tmp->opt_rdata->option_data == NULL && tmp->opt_rdata->option_length == 0 && tmp->opt_rdata->option_code == 0){
                // this is not a valid edns0. it's just there to say I'm edns0 aware!
                // first keep the reference to previos one to make if free later
                sdns_opt_rdata *just_to_free = tmp->opt_rdata;
                tmp->opt_rdata = opt;
                tmp->rdlength = 4 + opt->option_length;
                // now free() the previous one
                free(just_to_free);
                // we don't need to increment the header as we replaced the previous one
                return sdns_rcode_NoError;
            }else{
                tmp->rdlength += opt->option_length + 4;
                tmp->opt_rdata->next = opt;
                return sdns_rcode_NoError;
            }
        }else{
            // we have additional section but we don't have type OPT(41)
            // tmp refers to the last entry
            sdns_rr * new_section = NULL;
            if (opt->option_length == 0 && opt->option_data == NULL && opt->option_code == 0){
            // this is an empty edns just to say we are edns0-aware
                new_section = sdns_init_rr(NULL, sdns_rr_type_OPT, UDP_PAYLOAD_SIZE, 0x00, 0, 1, (void*)opt);
            }else{
                new_section = sdns_init_rr(NULL, sdns_rr_type_OPT, UDP_PAYLOAD_SIZE, 0x00, opt->option_length + 4, 1, (void*)opt);
            }
            tmp->next = new_section;
            ctx->msg->header.arcount += 1;
        }
    }else{
        // we need to add a new section (we don't have additional section)
        //we assume that UDP_PAYLOAD_SIZE=1232 and ttl=0
        sdns_rr * new_section = NULL;
        if (opt->option_length == 0 && opt->option_data == NULL  && opt->option_code == 0){
            // this is an empty edns just to say we are edns0 enabled
            new_section = sdns_init_rr(NULL, 41, UDP_PAYLOAD_SIZE, 0x0, 0, 1, (void*) opt);
        }else{
            // this is a real edns0 data
            new_section = sdns_init_rr(NULL, 41, UDP_PAYLOAD_SIZE, 0x0, opt->option_length + 4, 1, (void*) opt);
        }
        ctx->msg->additional = new_section;
        ctx->msg->header.arcount = 1;
    }
    return sdns_rcode_NoError;
}




//return null on failure, a pointer to sdns_rr_OPT_EDE on success
//the function creates a copy of the data, so user is responsible to free the extra_text if it's necessary
sdns_opt_rdata * sdns_create_edns0_ede(uint16_t info_code, char * extra_text, uint16_t extra_text_len){
    sdns_opt_rdata * opt = (sdns_opt_rdata *) malloc_or_abort(sizeof(sdns_opt_rdata));
    opt->option_code = sdns_edns0_option_code_Extended_DNS_Error;
    opt->next = NULL;
    opt->option_length = extra_text_len + 2;
    opt->option_data = (char*) malloc_or_abort(opt->option_length);
    opt->option_data[0] = (uint8_t)((info_code >> 8) & 0xFF);
    opt->option_data[1] = (uint8_t)(info_code & 0xFF);
    if (extra_text != NULL)
        memcpy(opt->option_data + 2, extra_text, extra_text_len);
    return opt;
}

// this function will add NSID to the packet in edns0 part
// nsid structure is empty but its option_code is 3
sdns_opt_rdata * sdns_create_edns0_nsid(char * nsid, uint16_t nsid_len){
    sdns_opt_rdata * opt = (sdns_opt_rdata *) malloc_or_abort(sizeof(sdns_opt_rdata));
    if (nsid == NULL && nsid_len != 0){
        sdns_free_opt_rdata(opt);
        return NULL;    // can not have NULL with length > 0
    }
    opt->option_code = sdns_edns0_option_code_NSID;
    opt->next = NULL;
    opt->option_length = nsid_len;
    opt->option_data = nsid;
    return opt;
}

// creates a cookie for edns0. 
// You must provide the client cookie exactly with length 8
// If server_cookie is NULL, we keep it null
// Client cookie length must be 8 bytes.
// Server cookie length must be between 8 and 32 (both included).
// we allocate new memories for all char* inputs. caller is responsible to free client_cookie and servier_cookie
sdns_opt_rdata * sdns_create_edns0_cookie(char * client_cookie, char * server_cookie, uint8_t server_cookie_len){
    if ((server_cookie_len < 8 || server_cookie_len > 32) && server_cookie != NULL)
        return NULL;
    if (client_cookie == NULL)
        return NULL;
    // len(client_cookie) = 8
    sdns_opt_rdata * cookie = (sdns_opt_rdata*)malloc_or_abort(sizeof(sdns_opt_rdata));
    cookie->next = NULL;
    cookie->option_code = sdns_edns0_option_code_COOKIE;
    cookie->option_data = (char*)malloc_or_abort(server_cookie_len + 8);
    cookie->option_length = server_cookie_len + 8;
    memcpy(cookie->option_data, client_cookie, 8);
    if (server_cookie_len > 0)
        memcpy(cookie->option_data + 8, server_cookie, server_cookie_len);
    return cookie;
}

sdns_opt_rdata * sdns_init_opt_rdata(void){
    sdns_opt_rdata * opt = (sdns_opt_rdata*)malloc_or_abort(sizeof(sdns_opt_rdata));
    opt->next = NULL;
    opt->option_code = 0;
    opt->option_data = NULL;
    opt->option_length = 0;
    return opt;
}


void sdns_free_opt_rdata(sdns_opt_rdata * opt){
    if (opt == NULL)
        return;
    sdns_opt_rdata * tmp = opt;
    sdns_opt_rdata * helper = NULL;
    while (tmp){
        free(tmp->option_data);
        helper = tmp->next;
        free(tmp);
        tmp = helper;
    }
    return;
}

// this method only decode rr->rdata to option_code and option_info and option_data and next
// but option_data is still encoded based on different types of option_code
sdns_opt_rdata * sdns_decode_rr_OPT(sdns_context * ctx, sdns_rr * rr){
    if (ctx == NULL || rr == NULL){
        ctx->err = SDNS_ERROR_RR_NULL;
        return NULL;
    }
    sdns_opt_rdata * opt = sdns_init_opt_rdata();
    if (NULL == opt){
        ctx->err = SDNS_ERROR_MEMORY_ALLOC_FAILD;
        return NULL;
    }
    if (rr->rdlength == 0){
        // this is just edns0 aware packet. it has nothing in it
        return opt;
    }
    if (rr->rdlength < 4){  // if it's > 0 then it must be atleast 4
        free(opt);
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    if (rr->rdata + rr->rdlength > ctx->raw + ctx->raw_len){
        // we don't have enough data in the packet
        free(opt);
        ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
        return NULL;
    }
    unsigned int length = rr->rdlength;
    unsigned int cnt = 0;
    sdns_opt_rdata * last = opt;
    char * rdata = rr->rdata;
    sdns_opt_rdata * tmp = opt;
    while (cnt < length){
        if (tmp == NULL){
            tmp = sdns_init_opt_rdata();
            if (tmp == NULL){
                sdns_free_opt_rdata(opt);
                ctx->err = SDNS_ERROR_MEMORY_ALLOC_FAILD;
                return NULL;
            }
        }
        if (length - cnt < 4){
            sdns_free_opt_rdata(opt);
            if (tmp != opt)
                sdns_free_opt_rdata(tmp);
            ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
            return NULL;
        }
        tmp->option_code = (((uint8_t)rdata[cnt] << 8) & 0xFF00) | ((uint8_t)rdata[cnt+1] & 0x00FF);
        cnt += 2;
        tmp->option_length = (((uint8_t)rdata[cnt] << 8) & 0xFF00) | ((uint8_t)rdata[cnt+1] & 0x00FF);
        cnt += 2;
        if (tmp->option_length > 0){
            if (tmp->option_length > (length - cnt)){       // there is not enough data
                sdns_free_opt_rdata(opt);
                if (tmp != opt)
                    sdns_free_opt_rdata(tmp);
                ctx->err = SDNS_ERROR_RR_SECTION_MALFORMED;
                return NULL;
            }
            tmp->option_data = mem_copy(rdata + cnt, tmp->option_length);
            cnt += tmp->option_length;
        }
        if (opt == tmp){
            last = tmp;
        }else{
            last->next = tmp;
            last = tmp;
        }
        tmp = NULL;
    }
    ctx->err = 0;  // success
    return opt;
}
