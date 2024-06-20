#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>


void print_c_array(char * buffer, unsigned long int buffer_len){
    // no allocation no leak
    int cnt = 0;
    fprintf(stdout, "char packet_bytes[] = {\n\t");
    for (int i=0; i<buffer_len; ++i){
        fprintf(stdout, "0x%02x", (uint8_t)buffer[i]);
        if (i<buffer_len -1)
            fprintf(stdout, ", ");
        cnt++;
        if (cnt % 16 == 0){
            fprintf(stdout, "\n\t");
            cnt = 0;
        }
    }
    fprintf(stdout, "\n}\n");
}

char * mem2hex(char * mem, unsigned int mem_len){
    if (mem == NULL)
        return NULL;
    if (mem_len == 0)
        return NULL;
    char * result = (char *) malloc(mem_len * 2);
    if (NULL == result)
        return NULL;
    unsigned int j=0;
    for (unsigned int i=0; i< mem_len; ++i){
        sprintf(result + j, "%02x", (uint8_t)mem[i]);
        j+= 2;
    }
    return result;
}


// with the assumption that len(bytes) >= 4
uint32_t bytes_to_unix_timestamp(char * bytes){
    return ((bytes[0]<<24) & 0xFF000000) | ((bytes[1]<<16) & 0x00FF0000) | ((bytes[2]<<8) & 0x0000FF00) | (bytes[3] & 0x000000FF);
}

// converts timestamp (unix) to standard time string
char * timestr_from_timestamp(uint32_t ts){
    time_t raw_time = ts;
    struct tm * tif;
    char timestr[255] = {0x00};
    tif = gmtime(&raw_time);
    sprintf(timestr, "%d-%02d-%02d %02d:%02d:%02d UTC", tif->tm_year + 1900,
            tif->tm_mon + 1, tif->tm_mday, tif->tm_hour, tif->tm_min, tif->tm_sec);
    free(tif);
    return strdup(timestr);
}

//from https://opensource.apple.com/source/Libc/Libc-825.25/string/FreeBSD/memmem.c.auto.html
void * memmem(const void *l, size_t l_len, const void *s, size_t s_len){
	register char *cur, *last;
	const char *cl = (const char *)l;
	const char *cs = (const char *)s;

	/* we need something to compare */
	if (l_len == 0 || s_len == 0)
		return NULL;

	/* "s" must be smaller or equal to "l" */
	if (l_len < s_len)
		return NULL;

	/* special case where s_len == 1 */
	if (s_len == 1)
		return memchr(l, (int)*cs, l_len);

	/* the last position where its possible to find "s" in "l" */
	last = (char *)cl + l_len - s_len;

	for (cur = (char *)cl; cur <= last; cur++)
		if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
			return cur;
	return NULL;
}


//allocate memory and copy data into allocated memory and return the address
//caller is responsible for freeing the allocated memory
char * mem_copy(char * data, unsigned long int len){
    char * tmp = (char *) malloc(len);
    if (!tmp)
        return NULL;
    memcpy(tmp, data, len);
    return tmp;
}

uint16_t read_uint16_from_buffer(char * buff){
    // reads two bytes from the buffer of type char * and convert it to big endian uint16
    // we assume that buffer has enough data to read from
    return (((uint16_t)(*buff) & 0x00FF) << 8) +
           ((uint16_t)((*(buff+1)) & 0x00FF));
}

uint32_t read_uint32_from_buffer(char * buff){
    // reads four bytes from the buffer of type char * and convert it to big endian uint32
    // we assume that buffer has enough data to read from
    return (((uint32_t)(*(buff)& 0x000000FF) << 24)) +
           (((uint32_t)(*((buff) + 1)) & 0x000000FF) << 16) +
           (((uint32_t)(*((buff) + 2)) & 0x000000FF)<< 8) +
           (((uint32_t)(*((buff) + 3)) & 0x000000FF));
}


void word_2_char(uint16_t wrd, char *buff){
    // two-bytes integer to char * (big endian)
    buff[0] = (wrd >> 8) & 0xFF;
    buff[1] = (wrd) & 0xFF;
}


void char_2_char(uint8_t bt, char *buff){
    buff[0] = bt & 0xFF;
}

void dword_2_char(uint32_t dwrd, char * buff, unsigned long int bufflen, unsigned long int *pos){
    // 4-bytes integer to char * (big endian)
    buff[(*pos)++] = (dwrd >> 24) & 0xFF;
    buff[(*pos)++] = (dwrd >> 16) & 0xFF;
    buff[(*pos)++] = (dwrd >> 8) & 0xFF;
    buff[(*pos)++] = dwrd & 0xFF;
    return;
}

/**
 * @brief Converts an integer to IPv4 address
 * @param addr the IPv4 as integer
 * @param buffer A pointer to a buffer to receive the IPv4 string
 *
 * buffer must be allocated and freed by the caller and must be 
 * big enough to receive an IPv4 address (16 is enough)
 * @return A pointer to the provided buffer on success or NULL on failure
 */
const char * cipv4_uint_to_str(uint32_t addr, const char * buffer){
    if (!buffer)
        return NULL;
    char * tmp = (char *) buffer;
    uint8_t part = 0;
    int shft = 3;
    unsigned long int len = 0;
    for (int i=0; i<4; ++i){
        part = (addr >> (8* shft--)) & 0xFF;
        sprintf(tmp, "%d", part);
        if (i<3){
            len = strlen(tmp);
            tmp[len] = '.';
            tmp[len +1] = '\0';
        }
        tmp = tmp + strlen(tmp);
    }
    return buffer;
}


/**
 * @brief Prints the data in hex dump format
 * @param buffer A pointer to the buffer contains the data
 * @param the start position for printing
 * @param an integer showing how many bytes we should print (len <= size(buffer))
 *
 * @return 0 on success, non-zero for failure
 */
int hex_dump(const char * buffer, unsigned long int offset,unsigned long int len){
    // dump len bytes of buffer from byte 'offset'
    if (len == 0)
        return 0;
    if (offset > len){
        fprintf(stderr, "Error: offset is too big!\n");
        return 1;
    }
    uint32_t address = 0;
    address = offset;
    int x = 0;
    int read = 0;
    uint8_t ch = 0;
    int * data = (int*)malloc(16 * sizeof(int));
    unsigned int mov = offset;
    while (read < len){
        ch = buffer[mov++];
        data[x++] = ch;
        read++;
        if (x % 16 == 0){
            // first print address
            printf("0x%08X: ", address);
            address += 0x10;
            // now it's time to print values
            int j = 0;
            while (j < 16){
                if (j == 8)
                    printf("  ");
                printf("%02X", data[j]);
                if (j != 15)
                    printf(" ");
                j++;
            }
            printf("    ");
            printf("|");
            for (int i = 0; i<16; i++){
                if (data[i] > 0x20 && data[i] < 0x7E)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            printf("|");
            printf("\n");
            x = 0;
        }
    }
    // now printf whatever remaining in x
    // first print address
    if (x != 0){
        printf("0x%08X: ", address);
        address += 0x10;
    }
    if (x < 8 && x!= 0){
        for (int i=0; i<x; i++){
            printf("%02X", data[i]);
            if (i != x-1)
               printf(" ");
        }
        // (remaining-characters * 3) + 2 spaces between cols + 
        // 24 spaces for remaining 8 chars + 4 spaces related to third col
        int spaces = (8 - x) * 3 + 2 + 24 + 4;
        for (int i = 0; i < spaces;i++)
            printf(" ");
        printf("|");
        // now print characters
        for (int i=0;i<x;i++){
            if (data[i] > 0x20 && data[i] < 0x7E)
                printf("%c", data[i]);
            else
                printf(".");
        }
        spaces = (16 - x) * 1;
        for (int i = 0; i < spaces;i++)
            printf(" ");
        printf("|");
    }else if (x == 8){
        for (int i=0; i<x; i++){
            printf("%02X", data[i]);
            if (i != x-1)
                printf(" ");
        }
        // (remaining-characters * 3) + 2 spaces between cols + 
        // 24 spaces for remaining 8 chars + 4 spaces related to third col
        int spaces =  2 + 24 + 4;
        for (int i = 0; i < spaces;i++)
            printf(" ");
        printf("|");
        // now print characters
        for (int i=0;i<x;i++){
            if (data[i] > 0x20 && data[i] < 0x7E)
                printf("%c", data[i]);
            else
                printf(".");
        }
        spaces = (16 - x) * 1;
        for (int i = 0; i < spaces;i++)
            printf(" ");
        printf("|");
    }else if (x > 8 && x != 16){
        int j = 0;
        while (j < x){
            if (j == 8)
                printf("  ");
            printf("%02X", data[j]);
            if (j != (x-1))
                printf(" ");
            j++;
        }
        int spaces = ((16 - x)* 3) + 4;
        for (int i = 0; i < spaces;i++)
            printf(" ");
        printf("|");
        for (int i = 0; i<x; i++){
            if (data[i] > 0x20 && data[i] < 0x7E)
                printf("%c", data[i]);
            else
                printf(".");
        }
        spaces = (16 - x) * 1;
        for (int i = 0; i < spaces;i++)
            printf(" ");
        printf("|");
    }else { // x is 16
        // should never happen since we handle it inside the loop
    }
    printf("\n");
    free(data);
    return 0; 
}


