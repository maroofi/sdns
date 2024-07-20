#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

// compile with
// gcc -g -c -Werror -fpic sdns_luanet.c -I. -I/usr/include/lua5.3 && gcc -I. -I/usr/include/lua5.3 -shared -o sdnsnetlib.so *.o

typedef struct {
    uint32_t timeout;
    char * dstip;
    uint16_t dstport;
    char * srcip;
    uint16_t srcport;
    char * to_send;
    uint16_t to_send_len;
    uint16_t to_receive_len;
    char * to_receive;
}param_udp;

typedef struct {        // for now, both of them are the same
    uint32_t timeout;
    char * dstip;
    uint16_t dstport;
    char * srcip;
    uint16_t srcport;
    char * to_send;
    uint16_t to_send_len;
    uint16_t to_receive_len;
    char * to_receive;
}param_tcp;

int perform_lookup_tcp(param_tcp * pt){
    struct timeval tv = {.tv_sec = pt->timeout, .tv_usec = 0};
    struct sockaddr_in server;
    server.sin_port = htons(pt->dstport);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(pt->dstip);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1){
        close(sockfd);
        return errno;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
        close(sockfd);
        return errno;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0){
        close(sockfd);
        return errno;
    }
    if (connect(sockfd, (struct sockaddr *) &server, sizeof(server)) < 0){
        close(sockfd);
        return errno;
    }
    ssize_t sent = 0;
    uint16_t payload_size = pt->to_send_len;
    char * payload = (char*) malloc(2 + payload_size);
    payload[0] = (uint8_t)((payload_size >> 8) & 0xFF);
    payload[1] = (uint8_t)(payload_size & 0xFF);
    memcpy(payload + 2, pt->to_send, pt->to_send_len);
    sent = send(sockfd, payload, pt->to_send_len + 2, 0);
    if (sent < 0){
        free(payload);
        close(sockfd);
        return errno;
    }
    free(payload);
    ssize_t received = 0;
    char recv_payload[2] = {0x00};
    received = recv(sockfd, (void*)recv_payload, 2, 0);
    uint16_t to_allocate = (uint8_t)recv_payload[0] << 8 |
                           (uint8_t)recv_payload[1];

    received = 0;
    received = recv(sockfd, pt->to_receive, to_allocate, MSG_WAITALL);
    if (received < 0){  // we have socket error
        close(sockfd);
        return errno;
    }
    pt->to_receive_len = received;
    close(sockfd);
    return 0;   //success
}

int perform_lookup_udp(param_udp * pu){
    //char buffer[256] = {0x00};
    //char * error = buffer;
    struct timeval tv = {.tv_sec = pu->timeout, .tv_usec = 0};
    struct sockaddr_in server;
    unsigned int from_size;
    server.sin_port = htons(pu->dstport);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(pu->dstip);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1){
        close(sockfd);
        return errno;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
        close(sockfd);
        return errno;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0){
        close(sockfd);
        return errno;
    }

    ssize_t sent = 0;
    sent = sendto(sockfd, pu->to_send, pu->to_send_len, 0, (struct sockaddr *)&server, sizeof(server));
    if (sent == -1){  //error
        close(sockfd);
        return errno;
    }
    if (sent == 0){
        close(sockfd);
        return errno;
    }
    // now let's receive the data
    ssize_t received = 0;
                                                    
    from_size = 0;
    received = recvfrom(sockfd, pu->to_receive, pu->to_receive_len, MSG_WAITALL, (struct sockaddr*)&server, &from_size);
    if (received == -1){
        close(sockfd);
        return errno;
    }
    if (received == 0){
        close(sockfd);
        return errno;
    }
    pu->to_receive_len = received;
    close(sockfd);
    return 0;
}



static int l_sdns_tcp(lua_State *L){
    // the input to the function is a table of this keys:
    // {timeout=<socket-timeout-integer>, dstip=<destination-IP-string>, dstport=<destination-port-integer>,
    // srcip=<src-IP-string>, srcport=<src-port-integer>, to_send=<string-data to send>}
    // the function returns:
    // on success: (data, nil): data is the received data from socket
    // on fail: (nil, msg): msg is the error msg
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "dstip") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'dstip' key is missing or not a string. It must be an IP address");
        return 2;
    }
    const char * dstip = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "to_send") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'to_send' key is missing or not a string. It must be the data you want to send");
        return 2;
    }
    unsigned long int to_send_len;
    const char * to_send = luaL_checklstring(L, -1, &to_send_len);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "timeout") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'timeout' key is missing or not an integer. Waiting time for the socket response");
        return 2;
    }
    uint32_t timeout = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "dstport") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'dstport' key is missing or not an integer. This is the destination port number.");
        return 2;
    }
    uint16_t dstport = luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    // pop the table itself
    lua_pop(L, 1);

    param_tcp * pt = (param_tcp*) malloc(sizeof(param_tcp));
    if (NULL == pt){
        lua_pushnil(L);
        lua_pushstring(L, "Can not allocate memory...");
        return 2;
    }
    pt->dstip = (char *)dstip;
    pt->dstport = (uint16_t)dstport;
    pt->timeout = (uint32_t)timeout;
    pt->to_send = (char*)to_send;
    pt->to_send_len = (uint16_t) to_send_len;
    pt->to_receive = (char *) malloc(65535);
    if (pt->to_receive == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Can not allocate memory...");
        free(pt);
        return 2;
    }
    pt->to_receive_len = 65535;
    int res = perform_lookup_tcp(pt);
    if (res != 0){
        lua_pushnil(L);
        lua_pushstring(L, strerror(res));
        free(pt->to_receive);
        free(pt);
        return 2;
    }
    // res is 0
    lua_pushlstring(L, pt->to_receive, pt->to_receive_len);
    free(pt->to_receive);
    free(pt);
    return 1;
}


static int l_sdns_udp(lua_State *L){
    // the input to the function is a table of this keys:
    // {timeout=<socket-timeout-integer>, dstip=<destination-IP-string>, dstport=<destination-port-integer>,
    // srcip=<src-IP-string>, srcport=<src-port-integer>, to_send=<string-data to send>}
    // the function returns:
    // on success: (data, nil): data is the received data from socket
    // on fail: (nil, msg): msg is the error msg
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "dstip") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'dstip' key is missing or not a string. It must be an IP address");
        return 2;
    }
    const char * dstip = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "to_send") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'to_send' key is missing or not a string. It must be the data you want to send");
        return 2;
    }
    unsigned long int to_send_len;
    const char * to_send = luaL_checklstring(L, -1, &to_send_len);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "timeout") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'timeout' key is missing or not an integer. Waiting time for the socket response");
        return 2;
    }
    uint32_t timeout = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "dstport") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'dstport' key is missing or not an integer. This is the destination port number.");
        return 2;
    }
    uint16_t dstport = luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    // pop the table itself
    lua_pop(L, 1);

    param_udp * pu = (param_udp*) malloc(sizeof(param_udp));
    if (NULL == pu){
        lua_pushnil(L);
        lua_pushstring(L, "Can not allocate memory...");
        return 2;
    }
    pu->dstip = (char *)dstip;
    pu->dstport = (uint16_t)dstport;
    pu->timeout = (uint32_t)timeout;
    pu->to_send = (char*)to_send;
    pu->to_send_len = (uint16_t) to_send_len;
    pu->to_receive = (char *) malloc(65535);
    if (pu->to_receive == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Can not allocate memory...");
        free(pu);
        return 2;
    }
    pu->to_receive_len = 65535;
    int res = perform_lookup_udp(pu);
    if (res != 0){
        lua_pushnil(L);
        lua_pushstring(L, strerror(res));
        free(pu->to_receive);
        free(pu);
        return 2;
    }
    // res is 0
    lua_pushlstring(L, pu->to_receive, pu->to_receive_len);
    free(pu->to_receive);
    free(pu);
    return 1;
}

static const struct luaL_Reg sdnsnet_lib_expose[] = {
    {"send_udp", l_sdns_udp},
    {"send_tcp", l_sdns_tcp},
    // TODO: ADD more function here
    {NULL, NULL}
};

int luaopen_sdnsnetlib(lua_State * L){
    // initialize the metatable
    luaL_newmetatable(L, "metasdnsnetlib");
    
    //lua_pushcfunction(L, l_sdns_free_context);
    //lua_setfield(L, -2, "__gc");
    
    //lua_pop(L, 1);
    // This exists in lua version >= 5.2
    luaL_newlib(L, sdnsnet_lib_expose);
    return 1;
}

