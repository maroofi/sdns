#include <stdint.h>
#include <stdio.h>

#ifndef DNS_UTILS_H
#define DNS_UTILS_H

///////////////////////declaration/////////////////////////////////
char * mem2hex(char * mem, unsigned int mem_len);
uint32_t bytes_to_unix_timestamp(char * bytes);
void print_c_array(char * buffer, unsigned long int buffer_len);

char * timestr_from_timestamp(uint32_t ts);
char * mem_copy(char * data, unsigned long int len);

void * memmem(const void *l, size_t l_len, const void *s, size_t s_len);
uint16_t read_uint16_from_buffer(char * buff);
uint32_t read_uint32_from_buffer(char * buff);
void word_2_char(uint16_t wrd, char *buff);


void char_2_char(uint8_t bt, char *buff);

void dword_2_char(uint32_t dwrd, char * buff, unsigned long int bufflen,
                                unsigned long int *pos);


const char * cipv4_uint_to_str(uint32_t addr, const char * buffer);

int hex_dump(const char * buffer, unsigned long int offset,unsigned long int len);

///////////////////////////////////////////////////////////////////////



#endif
