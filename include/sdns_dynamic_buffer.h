#ifndef DYN_BUFFER_H
#define DYN_BUFFER_H

#define DEFAULT_BUFFER_LENGTH 128

typedef struct {
    char * buffer;
    unsigned long int len;
    unsigned long int cursor;
} dyn_buffer;

// initialize a buffer structure from a given buff, if buff is NULL, creates a new 128 bytes buffer
dyn_buffer * dyn_buffer_init(char * buff, unsigned long int len, unsigned long int cursor);
int dyn_buffer_append(dyn_buffer * ctx, char * data, unsigned long int data_len);
void dyn_buffer_free(dyn_buffer * ctx);
void dyn_buffer_reset(dyn_buffer * ctx);
char * dyn_buffer_copy(dyn_buffer * ctx);

#endif
