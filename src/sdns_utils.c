#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

void * malloc_or_abort(size_t n){
    void * p = malloc(n);
    if (NULL == p){
        fprintf(stderr, "Can not allocate %ld bytes of memory...aborting...\n", n);
        abort();
    }
    return p;
}

char * ipv6_mem_to_str(char * mem){
    // mem must be exactly 16 bytes
    // the returned string is null terminated
    char * addr = (char*) malloc_or_abort(40); // max possible length of AAAA(no double dot)
    addr[39] = '\0';
    int j = 1;
    int l = 0;
    for (int i=0; i< 16; ++i, j++){
        sprintf(addr + l, "%02x", (uint8_t)*(mem + i));
        l += 2;
        if (j == 2 && i != 16 -1){
            sprintf(addr + l, "%c", ':');
            l++;
            j=0;
        }
    }
    return addr;
}


int safe_strcase_equal(const char * a, const char * b){
    if (NULL == a || b == NULL)
        return a==NULL && b==NULL?0:1;
    else
        return strcasecmp(a, b)==0?0:1;
    return 1;
}

char * safe_strdup(const char * s){
    return s==NULL?NULL:strdup(s);
}

unsigned long int cstr_len(const char * str){
    if (!str)
        return 0;
    char * p = (char*)str;
    unsigned long long int len = 0;
    while (*p++)
        len++;
    return len;
}


char *cstr_chr(const char *s, int c){
    if (!s)
        return NULL;
    char * t = (char*) s;
    if (c == '\0')
        return t + cstr_len(s);
    while (*t != '\0'){
        if (*t == c)
            return t;
        t++;
    }
    return NULL;
}


unsigned int cstr_count(const char * str, int ch){
    // counts the number of occurrence of ch in str
    // str must not be null
    int cnt = 0;
    char * tmp = (char*)str;
    while (*tmp){
        if (*tmp == ch)
            cnt++;
        tmp++;
    }
    return cnt;
}

unsigned int cstr_to_uint(const char * str){
    // convert str to unsigned integer
    // str must be positive integer less than 2^32-1
    int i = 0;
    int digit;
    char * tmp = (char*)str;
    while(*tmp){
        digit = (int)(*tmp) - 0x30;
        i = i * 10 + digit;
        tmp++;
    }
    return i;
}

unsigned int cis_digit(int c){
    return c >= 0x30 && c <= 0x39?1:0;
}

int cipv4_is_ip_valid(const char * ip){
    if ((!ip) || (cstr_len(ip) < 7) || (cstr_count(ip, '.') != 3) || (cstr_len(ip) > 15))
        return 0;
    char * tmp = (char*)ip;
    char * dot_pos = NULL;
    char buffer[16] = {0};
    int i = 0;
    int is_invalid = 0;
    int j = 0;
    unsigned int part = 0;
    size_t buffer_len = 0;
    for(i =0; i<3; i++){
        dot_pos = cstr_chr(tmp, '.');
        j = 0;
        while (tmp<dot_pos){
            if (!cis_digit(*tmp))
                return 0;
            buffer[j] = *tmp;
            tmp++;
            j++;
        }
        buffer[j] = '\0';
        buffer_len = cstr_len(buffer);
        if ((buffer_len > 1 && buffer[0] == '0') || (buffer_len == 0))
            return 0;

        part = cstr_to_uint(buffer);
        if (part > 255 || part < 0)
            return 0;
        tmp = dot_pos+1;
    }
    i = 0;
    while (*tmp){
        if (!cis_digit(*tmp))
            return 0;
        buffer[i++] = *tmp++;
    }
    buffer[i] = '\0';
    buffer_len = cstr_len(buffer);
    if ((buffer_len > 1 && buffer[0] == '0') || (buffer_len == 0))
        return 0;
    part = cstr_to_uint(buffer);
    if (part < 0 || part > 255)
        return 0;
    return is_invalid == 1?0:1;           // valid
}


uint32_t cipv4_str_to_uint(const char *ip){
    // convert IPv4 ip to a number representation
    // example: 1.2.3.4 -> 16909060
    // you need to make sure the input IP address is valid
    // you can use cipv4_is_ip_valid() function for that.
    uint32_t result = 0;
    int i = 0;
    int j = 0;
    char * tmp = (char*)ip;
    uint32_t part = 0;
    char buffer[4] = {0};
    char * dot_pos = NULL;
    for (i=0; i< 3; i++){
        dot_pos = cstr_chr(tmp, '.');
        j = 0;
        while(tmp < dot_pos)
            buffer[j++] = *tmp++;
        buffer[j] = '\0';
        part = cstr_to_uint(buffer);
        result = result + (part << ((3-i)*8));
        tmp = dot_pos+1;
    }
    i = 0;
    while (*tmp)
        buffer[i++] = *tmp++;
    buffer[i] = '\0';
    part = cstr_to_uint(buffer);
    result = result + part;
    return result;
}


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

char * hex2mem(char * hexdata){
    // hexdata is a null-terminated string
    // we calculate the length by strlen
    uint16_t hexdata_len = hexdata == NULL?0:strlen(hexdata);
    if (hexdata_len == 0)
        return NULL;
    if (hexdata_len % 2 != 0)
        return NULL;
    char * mem = (char *) malloc_or_abort((int)(hexdata_len / 2));
    char * pos = hexdata;
    for (int i=0; i< (int)(hexdata_len/2); ++i){
        sscanf(pos, "%2hhx", &(mem[i]));
        pos += 2;
    }
    return mem;
}



char * mem2hex(char * mem, unsigned int mem_len){
    if (mem == NULL)
        return NULL;
    if (mem_len == 0)
        return NULL;
    char * result = (char *) malloc_or_abort(mem_len * 2 + 1); // one more for automatic NULL character
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
    char * tmp = (char *) malloc_or_abort(len);
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
    int * data = (int*)malloc_or_abort(16 * sizeof(int));
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

static unsigned int _parseHex ( const char** pchCursor ){
    unsigned int nVal = 0;
    char chNow;
    while ( chNow = **pchCursor & 0x5f, //(collapses case, but mutilates digits)
            (chNow >= ('0'&0x5f) && chNow <= ('9'&0x5f)) || 
            (chNow >= 'A' && chNow <= 'F') 
            )
    {
        unsigned char nybbleValue;
        chNow -= 0x10;  //scootch digital values down; hex now offset by x31
        nybbleValue = ( chNow > 9 ? chNow - (0x31-0x0a) : chNow );
        //shift nybble in
        nVal <<= 4;
        nVal += nybbleValue;

        ++*pchCursor;
    }
    return nVal;
}


int parse_IPv6 ( const char** ppszText, unsigned char* abyAddr){
    // adopted from rosettacode. changed to only parse IPv6. No IPv4/6 compination. No IPv4 value.
    // returns 1 on successful parsing otherwise 0
    // in case of success to byte representation of IPv6 will be in abyAddr memory passed by caller
    unsigned char* abyAddrLocal;

    const char* pchColon = strchr ( *ppszText, ':' );
    // don't parse it if it's combined
    if (strchr(*ppszText, '.') != NULL){
        return 0;
    }


    //we'll consider this to (probably) be IPv6 if we find an open
    //bracket, or an absence of dots, or if there is a colon, and it
    //precedes any dots that may or may not be there
    int bIsIPv6local = NULL != pchColon?1:0;
    if (bIsIPv6local == 0){
        return 0;   // fail
    }
    abyAddrLocal = abyAddr; 
    

    unsigned char* pbyAddrCursor;
    unsigned char* pbyZerosLoc;
    int nIdx;
    //up to 8 16-bit hex quantities, separated by colons, with at most one
    //empty quantity, acting as a stretchy run of zeroes.  optional port
    //if there are brackets followed by colon and decimal port number.
    //A further form allows an ipv4 dotted quad instead of the last two
    //16-bit quantities, but only if in the ipv4 space ::ffff:x:x .
    
    pbyAddrCursor = abyAddrLocal;
    pbyZerosLoc = NULL; //if we find a 'zero compression' location
    for ( nIdx = 0; nIdx < 8; ++nIdx ){  //we've got up to 8 of these, so we will use a loop
        const char* pszTextBefore = *ppszText;
        unsigned nVal =_parseHex ( ppszText );      //get value; these are hex
        if ( pszTextBefore == *ppszText ){   //if empty, we are zero compressing; note the loc
            if ( NULL != pbyZerosLoc ){  //there can be only one!
                //unless it's a terminal empty field, then this is OK, it just means we're done with the host part
                if ( pbyZerosLoc == pbyAddrCursor )
                {
                    --nIdx;
                    break;
                }
                return 0;   //otherwise, it's a format error
            }
            if ( ':' != **ppszText )    //empty field can only be via :
                return 0;
            if ( 0 == nIdx ){    //leading zero compression requires an extra peek, and adjustment
                ++(*ppszText);
                if ( ':' != **ppszText )
                    return 0;
            }
            pbyZerosLoc = pbyAddrCursor;
            ++(*ppszText);
        }else{
            if ( nVal > 65535 ) //must be 16 bit quantity
                return 0;
            *(pbyAddrCursor++) = nVal >> 8;     //transfer in network order
            *(pbyAddrCursor++) = nVal & 0xff;
            if ( ':' == **ppszText )    //typical case inside; carry on
            {
                ++(*ppszText);
            }
            else    //some other terminating character; done with this parsing parts
            {
                break;
            }
        }
    }
    
    //handle any zero compression we found
    if ( NULL != pbyZerosLoc )
    {
        int nHead = (int)( pbyZerosLoc - abyAddrLocal );    //how much before zero compression
        int nTail = nIdx * 2 - (int)( pbyZerosLoc - abyAddrLocal ); //how much after zero compression
        int nZeros = 16 - nTail - nHead;        //how much zeros
        memmove ( &abyAddrLocal[16-nTail], pbyZerosLoc, nTail );    //scootch stuff down
        memset ( pbyZerosLoc, 0, nZeros );      //clear the compressed zeros
    }
    return 1;
}

