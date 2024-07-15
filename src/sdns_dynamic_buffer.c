#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sdns_dynamic_buffer.h>

dyn_buffer * dyn_buffer_init(char * buff, unsigned long int len, unsigned long int cursor){
    int we_allocated = 0;
    if (NULL == buff){
        buff = (char*) malloc(DEFAULT_BUFFER_LENGTH);
        if (buff == NULL)
            return NULL;
        len = 128;
        we_allocated = 1;
    }
    dyn_buffer * d = (dyn_buffer*) malloc(sizeof(dyn_buffer));
    if (NULL == d){
        if (we_allocated)
            free(buff);
        return NULL;
    }
    d->buffer = buff;
    d->len = len;
    d->cursor = cursor;
    return d;
}

// append the given data with length data_len to the buffer context, allocate more if necessary
// 0 on success, fail otherwise
int dyn_buffer_append(dyn_buffer * ctx, char * data, unsigned long int data_len){
    unsigned long int remain = ctx->len - ctx->cursor;
    if (remain < data_len){
        // we don't have space, allocate more
        unsigned to_alloc = data_len - remain + 1;
        char * tmp = (char*) realloc(ctx->buffer, ctx->len + to_alloc);
        if (NULL == tmp)
            return 1;
        ctx->buffer = tmp;
        ctx->len = ctx->len + to_alloc;
        memcpy(ctx->buffer + ctx->cursor, data, data_len);
        ctx->cursor += data_len;
    }else{
        memcpy(ctx->buffer + ctx->cursor, data, data_len);
        ctx->cursor += data_len;
    }
    return 0;
}


void dyn_buffer_free(dyn_buffer * ctx){
    if (NULL == ctx)
        return;
    free(ctx->buffer);
    ctx->buffer = NULL;
    free(ctx);
    ctx = NULL;
}

void dyn_buffer_reset(dyn_buffer * ctx){
    if (NULL == ctx)
        return;
    ctx->cursor = 0;
    memset(ctx->buffer, 0x00, ctx->len);
}

// copy the buffer and return a pointer to the new memory
char * dyn_buffer_copy(dyn_buffer * ctx){
    char * tmp = (char *) malloc(ctx->cursor);
    if (NULL == tmp)
        return NULL;
    memcpy(tmp, ctx->buffer, ctx->cursor);
    return tmp;
}




