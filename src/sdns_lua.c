#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <time.h>

#include <sdns_api.h>
#include <sdns_print.h>
#include <sdns_utils.h>

// compile with: 
// gcc -c -Wall -Werror -fpic sdns_lua.c sdns.c sdns_api.c sdns_print.c sdns_utils.c
// sdns_dynamic_buffer.c -I. -I/usr/include/lua5.3 && gcc -I. -I/usr/include/lua5.3 -shared -o sdnslib.so *.o

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


static int perform_lookup_tcp(param_tcp * pt){
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

static int perform_lookup_udp(param_udp * pu){
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



static int l_sdns_send_tcp(lua_State *L){
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


static int l_sdns_send_udp(lua_State *L){
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




int l_sdns_create_query(lua_State * L){
    // get input params from the stack
    const char * cls = luaL_checkstring(L, -1);
    const char * type = luaL_checkstring(L, -2);
    const char * name = luaL_checkstring(L, -3);
    if (cls == NULL || type ==  NULL || name == NULL){
        lua_pushnil(L);
        return 1;
    }
    sdns_context ** dns;
    dns = lua_newuserdata(L, sizeof(sdns_context *));
    *dns = sdns_create_query((char*)name, (char*)type, (char*)cls);
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Can not create the query for a given name/type/class");
        return 2;
    }
    // we also setmetatable here
    luaL_getmetatable(L, "metasdnslib");
    lua_setmetatable(L, -2);
    return 1;
}

int l_sdns_print_dns(lua_State * L){
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -1, "metasdnslib");
    sdns_neat_print_dns(*dns);
    return 0;
}

static int l_sdns_free_context(lua_State * L){
    sdns_context ** dns = (sdns_context **)lua_touserdata(L, -1);
    sdns_free_context(*dns);
    *dns = NULL;
    return 0;
}

static int l_sdns_to_network(lua_State * L){
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -1, "metasdnslib");
    int err=0;
    uint16_t bufflen = 0;
    char errbuff[255] = {0x00};
    char * errstr = errbuff;
    char * buff = sdns_to_network(*dns, &err, &bufflen);
    sdns_error_string(err, &errstr);
    if (buff == NULL || bufflen == 0 || err != 0){
        lua_pushnil(L);
        lua_pushstring(L, errstr);
        return 2;
    }
    //hex_dump(buff, 0, bufflen);
    lua_pushlstring(L, buff, bufflen);
    free(buff);
    return 1;
}

static int l_sdns_from_network(lua_State * L){
    size_t len=0;
    const char * dns_bytes = luaL_checklstring(L, -1, &len);
    if (dns_bytes == NULL || len == 0){
        lua_pushnil(L);
        lua_pushstring(L, "Can not create packet from the given byte-stream");
        return 2;
    }
    sdns_context ** dns;
    dns = lua_newuserdata(L, sizeof(sdns_context *));
    *dns = sdns_from_network((char *) dns_bytes, len);
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Can not decode the buffer to DNS packet");
        return 2;
    }
    
    // we also setmetatable here
    luaL_getmetatable(L, "metasdnslib");
    lua_setmetatable(L, -2);
    return 1;
}

static int l_sdns_add_rr_AAAA(lua_State * L){
    // returns 0 on success, (nil, msg) on fail
    // {name="", section="", ttl=3, rdata={ip=''}}
    // ip:string, ttl:integer, name:string, dns:sdns_context
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "ip") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'ip' field of 'rdata' is missing or not a valid IPv6 ':' format");
        return 2;
    }
    const char * ip = luaL_checkstring(L, -1);
    lua_pop(L, 2);
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || ip == NULL || name == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (ip, name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_AAAA(*dns, (char*)name, (uint32_t)ttl, (const char*)ip);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_AAAA(*dns, (char*)name, (uint32_t)ttl, (const char*)ip);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_AAAA(*dns, (char*)name, (uint32_t)ttl, (const char*)ip);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_A(lua_State * L){
    // returns 0 on success, (nil, msg) on fail
    // stack (top to down): section,IP,ttl,name,dns
    // {name="", section="", ttl=3, rdata={ip=''}}
    // ip:string, ttl:integer, name:string, dns:sdns_context
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "ip") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'ip' field of 'rdata' is missing or not a valid IP string");
        return 2;
    }
    const char * ip = luaL_checkstring(L, -1);
    lua_pop(L, 2);

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || ip == NULL || name == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (ip, name, section) or DNS context is NULL");
        return 2;
    }
    if (cipv4_is_ip_valid(ip) != 1){
        lua_pushnil(L);
        lua_pushstring(L, "IP address is not valid");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_A(*dns, (char*)name, (uint32_t)ttl, (char*)ip);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_A(*dns, (char*)name, (uint32_t)ttl, (char*)ip);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_A(*dns, (char*)name, (uint32_t)ttl, (char*)ip);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_NS(lua_State * L){
    // returns 0 on success, (nil, msg) on fail
    // section: string: possible values: 'answer', 'additional', 'authority'
    // input of the lua function: add_rr_A(dns, {name="", ttl=, section=, rdata={nsname=}})
    
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "nsname") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'nsname' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * nsname = luaL_checkstring(L, -1);
    lua_pop(L, 2);

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || nsname == NULL || name == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (nsname, name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_NS(*dns, (char*)name, (uint32_t)ttl, (char*)nsname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_NS(*dns, (char*)name,(uint32_t) ttl, (char*)nsname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_NS(*dns, (char*)name,(uint32_t) ttl, (char*)nsname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_MX(lua_State * L){
    // returns 0 on success, (nil, msg) on fail
    // stack (top to down): section,exchange,preference,ttl,name,dns
    // section: string: possible values: 'answer', 'additional', 'authority'
    // exchange:string, preference:integer, ttl:integer, name:string, dns:sdns_context

    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "exchange") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'exchange' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * exchange = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "preference") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'preference' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint16_t preference = luaL_checkinteger(L, -1);
    lua_pop(L, 2);

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || exchange == NULL || name == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (exchange, name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    if ((uint16_t)preference > (65535)){
        lua_pushnil(L);
        lua_pushstring(L, "Preference value must be 0 <= Preference <= 65535");
        return 2;
    }
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_MX(*dns, (char*)name, (uint32_t)ttl, (uint16_t)preference, (char*)exchange);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_MX(*dns, (char*)name, (uint32_t) ttl, (uint16_t)preference, (char*)exchange);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_MX(*dns, (char*)name, (uint32_t)ttl, (uint16_t)preference, (char*)exchange);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_NID(lua_State * L){
    // returns 0 on success, (nil, msg) on fail
    // stack (top to down): section,nodeid,preference,ttl,name,dns
    // section: string: possible values: 'answer', 'additional', 'authority'
    // nodeid:memory(8bytes), preference:integer, ttl:integer, name:string, dns:sdns_context

    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "nodeid") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'nodeid' field of 'rdata' is missing");
        return 2;
    }
    size_t nodeid_len = 0;
    const char * nodeid = luaL_checklstring(L, -1, &nodeid_len);
    lua_pop(L, 1);
    
    if (lua_getfield(L, -1, "preference") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'preference' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint16_t preference = luaL_checkinteger(L, -1);
    lua_pop(L, 2);

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || nodeid == NULL || name == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (nodeid, name, section) or DNS context is NULL");
        return 2;
    }
    if (nodeid_len != 8){
        lua_pushnil(L);
        lua_pushstring(L, "NodeID must be exactly 8 bytes");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_NID(*dns, (char*)name, (uint32_t)ttl, (uint16_t)preference, (char*)nodeid);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_NID(*dns, (char*)name, (uint32_t) ttl, (uint16_t)preference, (char*)nodeid);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_NID(*dns, (char*)name, (uint32_t)ttl, (uint16_t)preference, (char*)nodeid);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}


static int l_sdns_add_rr_SOA(lua_State *L){
    // lua input: {name=, ttl=, section=, rdata={mname=, rname=, expire=, minimum=, refresh=, retry=, serial=}}                   
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "mname") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'mname' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * mname = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "rname") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'rname' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * rname = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "refresh") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'refresh' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint32_t refresh = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "retry") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'retry' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint32_t retry = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "minimum") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'minimum' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint32_t minimum = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "expire") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'expire' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint32_t expire = luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "serial") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'serial' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint32_t serial = luaL_checkinteger(L, -1);
    lua_pop(L, 2);

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || rname == NULL || mname == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (nsname, name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_SOA(*dns, (char*)name, (uint32_t)ttl, (char*)mname, (char*)rname, (uint32_t)expire,
                                         (uint32_t)minimum, (uint32_t)refresh, (uint32_t)retry, (uint32_t)serial);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_SOA(*dns, (char*)name, (uint32_t)ttl, (char*)mname, (char*)rname, (uint32_t)expire,
                                         (uint32_t)minimum, (uint32_t)refresh, (uint32_t)retry, (uint32_t)serial);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_SOA(*dns, (char*)name, (uint32_t)ttl, (char*)mname, (char*)rname, (uint32_t)expire,
                                         (uint32_t)minimum, (uint32_t)refresh, (uint32_t)retry, (uint32_t)serial);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_PTR(lua_State * L){
    // returns 0 on success, (nil, msg) on fail
    // section: string: possible values: 'answer', 'additional', 'authority'
    // input of the lua function: add_rr_A(dns, {name="", ttl=, section=, rdata={ptrdname=}})
    
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "ptrdname") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'ptrdname' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * ptrdname = luaL_checkstring(L, -1);
    lua_pop(L, 2);

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || ptrdname == NULL || name == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (ptrdname, name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_PTR(*dns, (char*)name, (uint32_t)ttl, (char*)ptrdname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_PTR(*dns, (char*)name,(uint32_t) ttl, (char*)ptrdname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_PTR(*dns, (char*)name,(uint32_t) ttl, (char*)ptrdname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_CNAME(lua_State * L){
    // returns 0 on success, (nil, msg) on fail
    // section: string: possible values: 'answer', 'additional', 'authority'
    // input of the lua function: add_rr_A(dns, {name="", ttl=, section=, rdata={cname=}})
    
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "cname") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'cname' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * cname = luaL_checkstring(L, -1);
    lua_pop(L, 2);

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || cname == NULL || name == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (cname, name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_CNAME(*dns, (char*)name, (uint32_t)ttl, (char*)cname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_CNAME(*dns, (char*)name,(uint32_t) ttl, (char*)cname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_CNAME(*dns, (char*)name,(uint32_t) ttl, (char*)cname);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_SRV(lua_State *L){
    // lua input: {name=, ttl=, section=, rdata={priority=, weight=, port=, target=}}                   
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "target") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'target' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * target = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "priority") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'priority' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint16_t priority = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "weight") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'weight' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint16_t weight = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "port") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'port' field of 'rdata' is missing or not a valid integer");
        return 2;
    }
    uint16_t port = luaL_checkinteger(L, -1);
    lua_pop(L, 2);


    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || target == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (target, name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_SRV(*dns, (char*)name, (uint32_t)ttl, (uint16_t)priority,
                                         (uint16_t) weight, (uint16_t) port, (char*)target);
                                         
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_SRV(*dns, (char*)name, (uint32_t)ttl, (uint16_t)priority,
                                         (uint16_t) weight, (uint16_t) port, (char*)target);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_SRV(*dns, (char*)name, (uint32_t)ttl, (uint16_t)priority,
                                         (uint16_t) weight, (uint16_t) port, (char*)target);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_TXT(lua_State *L){
    // lua input: {name=, ttl=, section=, rdata={txtdata=}}
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "txtdata") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'txtdata' field of 'rdata' is missing or is not string");
        return 2;
    }
    size_t txt_len;
    const char * txtdata = luaL_checklstring(L, -1, &txt_len);
    lua_pop(L, 2);
    
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || section == NULL || name == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_TXT(*dns, (char*)name, (uint32_t)ttl, (char*) txtdata, txt_len);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_TXT(*dns, (char*)name, (uint32_t)ttl, (char*) txtdata, txt_len);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_TXT(*dns, (char*)name, (uint32_t)ttl, (char*) txtdata, txt_len);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_rr_HINFO(lua_State *L){
    // lua input: {name=, ttl=, section=, rdata={os=, cpu=}}                   
    luaL_checktype(L, -1, LUA_TTABLE);
    if(lua_getfield(L, -1, "name") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'name' key is missing or not a string");
        return 2;
    }
    const char * name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "section") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'section' key is missing or not a string");
        return 2;
    }
    const char * section = luaL_checkstring(L, -1);
    lua_pop(L, 1);
    if (lua_getfield(L, -1, "ttl") != LUA_TNUMBER){
        lua_pushnil(L);
        lua_pushstring(L, "'ttl' key is missing or not an integer");
        return 2;
    }
    uint32_t ttl = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "rdata") != LUA_TTABLE){
        lua_pushnil(L);
        lua_pushstring(L, "'rdata' field is missing or not a table type");
        return 2;
    }
    if (lua_getfield(L, -1, "os") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'os' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * os = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    if (lua_getfield(L, -1, "cpu") != LUA_TSTRING){
        lua_pushnil(L);
        lua_pushstring(L, "'cpu' field of 'rdata' is missing or not a valid FQDN");
        return 2;
    }
    const char * cpu = luaL_checkstring(L, -1);
    lua_pop(L, 2);
    
    uint8_t os_len;
    uint8_t cpu_len;
    os_len = os == NULL?0:strlen(os);
    cpu_len = cpu == NULL?0:strlen(cpu);
    if (os_len > 255){
        lua_pushnil(L);
        lua_pushstring(L, "'os' must be a string with the length of at most 255");
        return 2;
    }
    if (cpu_len > 255){
        lua_pushnil(L);
        lua_pushstring(L, "'cpu' must be a string with the length of at most 255");
        return 2;

    }

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL || os == NULL || cpu == NULL || section == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (os, cpu, name, section) or DNS context is NULL");
        return 2;
    }
    int check_section = 0;
    check_section += safe_strcase_equal(section, "answer");
    check_section += safe_strcase_equal(section, "authority");
    check_section += safe_strcase_equal(section, "additional");
    if (check_section > 2){
        lua_pushnil(L);
        lua_pushstring(L, "Section name must be one of 'answer', 'authority' or 'additional' values");
        return 2;
    }
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    if (safe_strcase_equal(section, "answer") == 0){
        int res = sdns_add_rr_answer_HINFO(*dns, (char*)name, (uint32_t)ttl, (char*)os, (uint8_t)os_len, (char*)cpu, (uint8_t)cpu_len);
                                         
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else if (safe_strcase_equal(section, "authority") == 0){
        int res = sdns_add_rr_authority_HINFO(*dns, (char*)name, (uint32_t)ttl, (char*)os, (uint8_t)os_len, (char*)cpu, (uint8_t)cpu_len);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }else{  // it's additional
        int res = sdns_add_rr_additional_HINFO(*dns, (char*)name, (uint32_t)ttl, (char*)os, (uint8_t)os_len, (char*)cpu, (uint8_t)cpu_len);
        if (res == 0){
            lua_pushinteger(L, 0);
        }else{
            lua_pushinteger(L, res);
            sdns_error_string(res, &errpointer);
            lua_pushstring(L, errpointer);
            return 2;
        }
    }
    return 1;
}

static int l_sdns_add_nsid(lua_State * L){
    // if the input is empty string, we consider it as NULL
    // if there is a non-empty input, then we set it as nsid
    unsigned long int len;
    const char * nsid = luaL_checklstring(L, -1, &len);
    if (nsid == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "You must pass an NSID string (either empty string or with value)");
        return 2;
    }

    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (os, cpu, name, section) or DNS context is NULL");
        return 2;
    }
    char * new_nsid = len==0?NULL:mem2hex((char*)nsid, len);

    int res = sdns_add_nsid(*dns, new_nsid);
    free(new_nsid);
    if (res == 0){
        lua_pushinteger(L, 0);
        return 1;
    }
    lua_pushnil(L);
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    sdns_error_string(res, &errpointer);
    lua_pushstring(L, errpointer);
    return 2;
}

static int l_sdns_get_value_nsid(lua_State * L){
    // returns  the nsid value if there is any or error and msg
    // returns: (nsid, nil) on success. (nil, errmsg) on fail
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -1, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (os, cpu, name, section) or DNS context is NULL");
        return 2;
    }
    int err;
    uint16_t nsid_len;
    char * nsid = NULL;
    char errbuffer[255] = {0x00};
    char * errpointer = errbuffer;
    nsid = sdns_get_value_nsid(*dns, &err, &nsid_len);
    if (err != 0){
        free(nsid);    // it's null anyway
        lua_pushnil(L);
        sdns_error_string(err, &errpointer);
        lua_pushstring(L, errbuffer);
        return 2;
    }
    // now err = 0
    lua_pushlstring(L, nsid, nsid_len);
    free(nsid);
    return 1;
}

static int l_sdns_get_header(lua_State * L){
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -1, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Input string (os, cpu, name, section) or DNS context is NULL");
        return 2;
    }
    // we want to return a table with 15 key-values as the header table
    lua_createtable(L, 0, 15);
    // id
    lua_pushstring(L, "id");
    lua_pushinteger(L, (*dns)->msg->header.id);
    lua_settable(L, -3);
    // opcode
    lua_pushstring(L, "opcode");
    lua_pushinteger(L, (*dns)->msg->header.opcode);
    lua_settable(L, -3);
    // qr
    lua_pushstring(L, "qr");
    lua_pushinteger(L, (*dns)->msg->header.qr);
    lua_settable(L, -3);
    // aa
    lua_pushstring(L, "aa");
    lua_pushinteger(L, (*dns)->msg->header.aa);
    lua_settable(L, -3);
    // tc
    lua_pushstring(L, "tc");
    lua_pushinteger(L, (*dns)->msg->header.tc);
    lua_settable(L, -3);
    // rd
    lua_pushstring(L, "rd");
    lua_pushinteger(L, (*dns)->msg->header.rd);
    lua_settable(L, -3);
    // ra
    lua_pushstring(L, "ra");
    lua_pushinteger(L, (*dns)->msg->header.ra);
    lua_settable(L, -3);
    // z
    lua_pushstring(L, "z");
    lua_pushinteger(L, (*dns)->msg->header.z);
    lua_settable(L, -3);
    // ad
    lua_pushstring(L, "ad");
    lua_pushinteger(L, (*dns)->msg->header.AD);
    lua_settable(L, -3);
    // CD
    lua_pushstring(L, "cd");
    lua_pushinteger(L, (*dns)->msg->header.CD);
    lua_settable(L, -3);
    // rcode
    lua_pushstring(L, "rcode");
    lua_pushinteger(L, (*dns)->msg->header.rcode);
    lua_settable(L, -3);
    // qdcount
    lua_pushstring(L, "qdcount");
    lua_pushinteger(L, (*dns)->msg->header.qdcount);
    lua_settable(L, -3);
    // arcount
    lua_pushstring(L, "arcount");
    lua_pushinteger(L, (*dns)->msg->header.arcount);
    lua_settable(L, -3);
    // ancount
    lua_pushstring(L, "ancount");
    lua_pushinteger(L, (*dns)->msg->header.ancount);
    lua_settable(L, -3);
    // nscount
    lua_pushstring(L, "nscount");
    lua_pushinteger(L, (*dns)->msg->header.nscount);
    lua_settable(L, -3);
    return 1;
}

static int l_sdns_set_do(lua_State * L){
    int do_bit = luaL_checkinteger(L, -1);
    if (do_bit != 0 && do_bit != 1){
        lua_pushnil(L);
        lua_pushstring(L, "DO bit must be eihter zero or one");
        return 2;
    }
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_do(*dns, do_bit);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "There is no EDNS0 in this package to enable DO bit!");
        return 2;
    }
    return 1;
}

static int l_sdns_set_tc(lua_State * L){
    int tc_bit = luaL_checkinteger(L, -1);
    if (tc_bit != 0 && tc_bit != 1){
        lua_pushnil(L);
        lua_pushstring(L, "TC bit must be eihter zero or one");
        return 2;
    }
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_tc(*dns, tc_bit);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "sdns context is not valid");
        return 2;
    }
    return 1;
}


static int l_sdns_set_qr(lua_State * L){
    int qr_bit = luaL_checkinteger(L, -1);
    if (qr_bit != 0 && qr_bit != 1){
        lua_pushnil(L);
        lua_pushstring(L, "QR bit must be eihter zero or one");
        return 2;
    }
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_qr(*dns, qr_bit);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "sdns context is not valid");
        return 2;
    }
    return 1;
}

static int l_sdns_set_rd(lua_State * L){
    int rd_bit = luaL_checkinteger(L, -1);
    if (rd_bit != 0 && rd_bit != 1){
        lua_pushnil(L);
        lua_pushstring(L, "RD bit must be eihter zero or one");
        return 2;
    }
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_rd(*dns, rd_bit);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "sdns context is not valid");
        return 2;
    }
    return 1;
}

static int l_sdns_set_ra(lua_State * L){
    int ra_bit = luaL_checkinteger(L, -1);
    if (ra_bit != 0 && ra_bit != 1){
        lua_pushnil(L);
        lua_pushstring(L, "RA bit must be eihter zero or one");
        return 2;
    }
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_ra(*dns, ra_bit);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "sdns context is not valid");
        return 2;
    }
    return 1;
}

static int l_sdns_set_rcode(lua_State * L){
    int rcode = luaL_checkinteger(L, -1);
    if (rcode < 0 || rcode > 15){
        lua_pushnil(L);
        lua_pushstring(L, "rcode must be between 0 and 16 (excluded)");
        return 2;
    }
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_rcode(*dns, rcode);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "sdns context is not valid");
        return 2;
    }
    return 1;
}

static int l_sdns_set_aa(lua_State * L){
    int aa_bit = luaL_checkinteger(L, -1);
    if (aa_bit != 0 && aa_bit != 1){
        lua_pushnil(L);
        lua_pushstring(L, "AA bit must be eihter zero or one");
        return 2;
    }
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_aa(*dns, aa_bit);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "sdns context is not valid");
        return 2;
    }
    return 1;
}

static int l_sdns_set_cd(lua_State * L){
    int cd_bit = luaL_checkinteger(L, -1);
    if (cd_bit != 0 && cd_bit != 1){
        lua_pushnil(L);
        lua_pushstring(L, "CD bit must be eihter zero or one");
        return 2;
    }
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_cd(*dns, cd_bit);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "sdns context is not valid");
        return 2;
    }
    return 1;
}

static int l_sdns_set_id(lua_State * L){
    int id_num = luaL_checkinteger(L, -1);
    
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_set_id(*dns, (uint16_t)id_num);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        lua_pushstring(L, "sdns context is not valid");
        return 2;
    }
    return 1;
}

static int l_sdns_remove_edns(lua_State * L){
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -1, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    int res = sdns_remove_edns(*dns);
    if (res == 0){
        lua_pushinteger(L, 0);
    }else{
        lua_pushnil(L);
        char bufferr[255] = {0x00};
        char * errpointer = bufferr;
        sdns_error_string(res, &errpointer);
        lua_pushstring(L, errpointer);
        return 2;
    }
    return 1;
}

static int create_rdata_table(lua_State * L, sdns_rr * answer){
    // zero=success, one=fail
    if (answer->type == sdns_rr_type_A){
        lua_createtable(L, 0, 1);       // we only have 'ip' field
        lua_pushstring(L, "ip");
        char ip[20] = {0x00};
        cipv4_uint_to_str(((sdns_rr_A*)answer->psdns_rr)->address, ip);
        lua_pushstring(L, ip);
        lua_settable(L, -3);
        return 0;
    }
    if (answer->type == sdns_rr_type_AAAA){
        char * ip = ipv6_mem_to_str(((sdns_rr_AAAA*)answer->psdns_rr)->address);
        if (ip != NULL){
            lua_createtable(L, 0, 1);
            lua_pushstring(L, "ip");
            lua_pushstring(L, ip);
            lua_settable(L, -3);
            return 0;
        }
        return 1;
    }
    if (answer->type == sdns_rr_type_NS){
        lua_createtable(L, 0, 1);       // we only have 'nsname' field
        lua_pushstring(L, "nsname");
        lua_pushstring(L, ((sdns_rr_NS*)answer->psdns_rr)->NSDNAME);
        lua_settable(L, -3);
        return 0;
    }
    if (answer->type == sdns_rr_type_SOA){
        lua_createtable(L, 0, 7);   // mname, rname, expire, minimum, retry, refresh, serial
        lua_pushstring(L, "mname");
        lua_pushstring(L, ((sdns_rr_SOA*)answer->psdns_rr)->mname);
        lua_settable(L, -3);
        lua_pushstring(L, "rname");
        lua_pushstring(L, ((sdns_rr_SOA*)answer->psdns_rr)->rname);
        lua_settable(L, -3);
        lua_pushstring(L, "expire");
        lua_pushinteger(L, ((sdns_rr_SOA*)answer->psdns_rr)->expire);
        lua_settable(L, -3);
        lua_pushstring(L, "minimum");
        lua_pushinteger(L, ((sdns_rr_SOA*)answer->psdns_rr)->minimum);
        lua_settable(L, -3);
        lua_pushstring(L, "retry");
        lua_pushinteger(L, ((sdns_rr_SOA*)answer->psdns_rr)->retry);
        lua_settable(L, -3);
        lua_pushstring(L, "refresh");
        lua_pushinteger(L, ((sdns_rr_SOA*)answer->psdns_rr)->refresh);
        lua_settable(L, -3);
        lua_pushstring(L, "serial");
        lua_pushinteger(L, ((sdns_rr_SOA*)answer->psdns_rr)->serial);
        lua_settable(L, -3);
        return 0;
    }
    if (answer->type == sdns_rr_type_MX){
        lua_createtable(L, 0, 2);   // preference, exchange
        lua_pushstring(L, "exchange");
        lua_pushstring(L, ((sdns_rr_MX*)answer->psdns_rr)->exchange);
        lua_settable(L, -3);
        lua_pushstring(L, "preference");
        lua_pushinteger(L, ((sdns_rr_MX*)answer->psdns_rr)->preference);
        lua_settable(L, -3);
        return 0;
    }
    if (answer->type == sdns_rr_type_PTR){
        lua_createtable(L, 0, 1);   // ptrdname
        lua_pushstring(L, "ptrdname");
        lua_pushstring(L, ((sdns_rr_PTR*)answer->psdns_rr)->PTRDNAME);
        lua_settable(L, -3);
        return 0;
    }
    if (answer->type == sdns_rr_type_SRV){
        lua_createtable(L, 0, 4);   // target, priority, weight, port
        lua_pushstring(L, "target");
        lua_pushstring(L, ((sdns_rr_SRV*)answer->psdns_rr)->Target);
        lua_settable(L, -3);
        lua_pushstring(L, "priority");
        lua_pushinteger(L, ((sdns_rr_SRV*)answer->psdns_rr)->Priority);
        lua_settable(L, -3);
        lua_pushstring(L, "weight");
        lua_pushinteger(L, ((sdns_rr_SRV*)answer->psdns_rr)->Weight);
        lua_settable(L, -3);
        lua_pushstring(L, "port");
        lua_pushinteger(L, ((sdns_rr_SRV*)answer->psdns_rr)->Port);
        lua_settable(L, -3);
        return 0;
    }
    if (answer->type == sdns_rr_type_HINFO){
        lua_createtable(L, 0, 2);   // os, cpu
        lua_pushstring(L, "cpu");
        lua_pushlstring(L, ((sdns_rr_HINFO*)answer->psdns_rr)->cpu, ((sdns_rr_HINFO*)answer->psdns_rr)->cpu_len);
        lua_settable(L, -3);
        lua_pushstring(L, "os");
        lua_pushlstring(L, ((sdns_rr_HINFO*)answer->psdns_rr)->os, ((sdns_rr_HINFO*)answer->psdns_rr)->os_len);
        lua_settable(L, -3);
        return 0;
    }
    if (answer->type == sdns_rr_type_TXT){
        lua_createtable(L, 0, 1);   // txtdata
        lua_pushstring(L, "txtdata");
        size_t len = 1;
        sdns_rr_TXT * tmp = (sdns_rr_TXT*)answer->psdns_rr;
        while(tmp){
            len += tmp->character_string.len;
            tmp = tmp->next;
        }
        char * data = malloc_or_abort(len);
        //printf("need a buffer of length:%ld\n", len);
        memset(data, 0, len);
        tmp = (sdns_rr_TXT*)answer->psdns_rr;   // reset
        size_t cnt = 0;
        while(tmp){
            for (int i=0; i<tmp->character_string.len; ++i){
                data[cnt] = tmp->character_string.content[i];
                cnt++;
            }
            tmp = tmp->next;
        }
        lua_pushlstring(L, data, len -1);
        lua_settable(L, -3);
        free(data);
        return 0;
    }
    if (answer->type == sdns_rr_type_CNAME){
        lua_createtable(L, 0, 1);   // cname
        lua_pushstring(L, "cname");
        lua_pushstring(L, ((sdns_rr_CNAME*)answer->psdns_rr)->CNAME);
        lua_settable(L, -3);
        return 0;
    }
    if (answer->type == sdns_rr_type_NID){
        lua_createtable(L, 0, 2);   // nodeid, preference
        lua_pushstring(L, "preference");
        lua_pushinteger(L, ((sdns_rr_NID*)answer->psdns_rr)->Preference);
        lua_settable(L, -3);
        lua_pushstring(L, "nodeid");
        if (((sdns_rr_NID*)answer->psdns_rr)->NodeId == NULL){
            lua_pushstring(L, "");
        }else{
            lua_pushlstring(L, ((sdns_rr_NID*)answer->psdns_rr)->NodeId, 8);
        }
        lua_settable(L, -3);
        return 0;
    }
    //TODO: add more RR here
    return 1;
}

static int l_sdns_get_additional(lua_State * L){
    // the Lua function receives 2 params:
    // get_additional(DNS, ans-num)
    // DNS: dns context and ans-num: starts from 1 is the nth additional RR in the packet
    int num = luaL_checkinteger(L, -1);
    if (num < 1){
        lua_pushnil(L);
        lua_pushstring(L, "The number starts from 1");
        return 2;
    }
    num = num -1;   // in C, we start from zero
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    // it to lua table, send it back to user
    int err;
    sdns_rr * additional = sdns_get_additional(*dns, &err, num);
    if (err != sdns_rcode_NoError || additional == NULL){
        char errbuff[255] = {0x00};
        char * errpointer = errbuff;
        sdns_error_string(err, &errpointer);
        lua_pushnil(L);
        lua_pushstring(L, errpointer);
        return 2;
    }

    char type_rr_class[20] = {0x00};
    lua_createtable(L, 1, 4);    // this is top to the stack
    // name
    lua_pushstring(L, "name");
    lua_pushstring(L, additional->name);
    lua_settable(L, -3);
    // ttl
    lua_pushstring(L, "ttl");
    lua_pushinteger(L, additional->ttl);
    lua_settable(L, -3);
    // class
    lua_pushstring(L, "class");
    sdns_class_to_string(additional->class, type_rr_class);
    lua_pushstring(L, type_rr_class);
    lua_settable(L, -3);
    // type
    memset(type_rr_class, 0, 20);
    lua_pushstring(L, "type");
    sdns_rr_type_to_string(additional->type, type_rr_class);
    lua_pushstring(L, type_rr_class);
    lua_settable(L, -3);
    // rdata
    lua_pushstring(L, "rdata");
    int res = create_rdata_table(L, additional);
    if (res == 0){
        lua_settable(L, -3);
        sdns_free_section(additional);
        return 1;
    }
    // we failed to create rdata table, we need to clean up the memory
    lua_pop(L, 3);
    lua_pushnil(L);
    lua_pushstring(L, "The additional section RR not supported by the Lua wrapper yet!");
    sdns_free_section(additional);
    return 2;
}


static int l_sdns_get_answer(lua_State * L){
    // the Lua function receives 2 params:
    // get_answer(DNS, ans-num)
    // DNS: dns context and ans-num: starts from 1 is the nth answer in the packet
    int num = luaL_checkinteger(L, -1);
    if (num < 1){
        lua_pushnil(L);
        lua_pushstring(L, "The number starts from 1");
        return 2;
    }
    num = num -1;   // in C, we start from zero
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    // it to lua table, send it back to user
    int err;
    sdns_rr * answer = sdns_get_answer(*dns, &err, num);
    if (err != sdns_rcode_NoError || answer == NULL){
        char errbuff[255] = {0x00};
        char * errpointer = errbuff;
        sdns_error_string(err, &errpointer);
        lua_pushnil(L);
        lua_pushstring(L, errpointer);
        return 2;
    }
    char type_rr_class[20] = {0x00};
    lua_createtable(L, 1, 4);    // this is top to the stack
    // name
    lua_pushstring(L, "name");
    lua_pushstring(L, answer->name);
    lua_settable(L, -3);
    // ttl
    lua_pushstring(L, "ttl");
    lua_pushinteger(L, answer->ttl);
    lua_settable(L, -3);
    // class
    lua_pushstring(L, "class");
    sdns_class_to_string(answer->class, type_rr_class);
    lua_pushstring(L, type_rr_class);
    lua_settable(L, -3);
    // type
    memset(type_rr_class, 0, 20);
    lua_pushstring(L, "type");
    sdns_rr_type_to_string(answer->type, type_rr_class);
    lua_pushstring(L, type_rr_class);
    lua_settable(L, -3);
    // rdata
    lua_pushstring(L, "rdata");
    int res = create_rdata_table(L, answer);
    if (res == 0){
        lua_settable(L, -3);
        sdns_free_section(answer);
        return 1;
    }
    // we failed to create rdata table, we need to clean up the shit
    lua_pop(L, 3);
    lua_pushnil(L);
    lua_pushstring(L, "The answer section RR not supported by the Lua wrapper yet!");
    sdns_free_section(answer);
    return 2;
}

static int l_sdns_get_authority(lua_State * L){
    // the Lua function receives 2 params:
    // get_answer(DNS, ans-num)
    // DNS: dns context and ans-num: starts from 1 is the nth answer in the packet
    int num = luaL_checkinteger(L, -1);
    if (num < 1){
        lua_pushnil(L);
        lua_pushstring(L, "The number starts from 1");
        return 2;
    }
    num = num -1;   // in C, we start from zero
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -2, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    // it to lua table, send it back to user
    int err;
    sdns_rr * authority = sdns_get_authority(*dns, &err, num);
    if (err != sdns_rcode_NoError || authority == NULL){
        char errbuff[255] = {0x00};
        char * errpointer = errbuff;
        sdns_error_string(err, &errpointer);
        lua_pushnil(L);
        lua_pushstring(L, errpointer);
        return 2;
    }

    char type_rr_class[20] = {0x00};
    lua_createtable(L, 1, 4);    // this is top to the stack
    // name
    lua_pushstring(L, "name");
    lua_pushstring(L, authority->name);
    lua_settable(L, -3);
    // ttl
    lua_pushstring(L, "ttl");
    lua_pushinteger(L, authority->ttl);
    lua_settable(L, -3);
    // class
    lua_pushstring(L, "class");
    sdns_class_to_string(authority->class, type_rr_class);
    lua_pushstring(L, type_rr_class);
    lua_settable(L, -3);
    // type
    memset(type_rr_class, 0, 20);
    lua_pushstring(L, "type");
    sdns_rr_type_to_string(authority->type, type_rr_class);
    lua_pushstring(L, type_rr_class);
    lua_settable(L, -3);
    // rdata
    lua_pushstring(L, "rdata");
    int res = create_rdata_table(L, authority);
    if (res == 0){
        lua_settable(L, -3);
        sdns_free_section(authority);
        return 1;
    }
    // we failed to create rdata table, we need to clean up the shit
    lua_pop(L, 3);
    lua_pushnil(L);
    lua_pushstring(L, "The authority section RR not supported by the Lua wrapper yet!");
    sdns_free_section(authority);
    return 2;
}


static int l_sdns_get_question(lua_State * L){
    sdns_context ** dns = (sdns_context **)luaL_checkudata(L, -1, "metasdnslib");
    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    sdns_question * q = sdns_get_question(*dns);
    if (q == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Question section is NULL");
        return 2;
    }
    lua_createtable(L, 0, 0);    // this is top to the stack
    // name
    lua_pushstring(L, "qname");
    lua_pushstring(L, q->qname);
    lua_settable(L, -3);
    char type_rr_class[20] = {0x00};
    // class
    lua_pushstring(L, "qclass");
    sdns_class_to_string(q->qclass, type_rr_class);
    lua_pushstring(L, type_rr_class);
    lua_settable(L, -3);
    // type
    memset(type_rr_class, 0, 20);
    lua_pushstring(L, "qtype");
    sdns_rr_type_to_string(q->qtype, type_rr_class);
    lua_pushstring(L, type_rr_class);
    lua_settable(L, -3);
    free(q->qname);
    free(q);
    return 1;
}

static int l_sdns_create_response_from_query(lua_State * L){
    sdns_context ** query = (sdns_context **)luaL_checkudata(L, -1, "metasdnslib");
    if (*query == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "DNS context is NULL");
        return 2;
    }
    sdns_context ** dns;
    dns = lua_newuserdata(L, sizeof(sdns_context *));
    *dns = sdns_create_response_from_query(*query);

    if (*dns == NULL){
        lua_pushnil(L);
        lua_pushstring(L, "Can not create the response for a given query");
        return 2;
    }
    // we also setmetatable here
    luaL_getmetatable(L, "metasdnslib");
    lua_setmetatable(L, -2);
    return 1;
}


static const struct luaL_Reg sdns_lib_expose[] = {
    {"create_query", l_sdns_create_query},
    {"print_dns", l_sdns_print_dns},
    {"to_network", l_sdns_to_network},
    {"from_network", l_sdns_from_network},
    {"add_rr_A", l_sdns_add_rr_A},
    {"add_rr_AAAA", l_sdns_add_rr_AAAA},
    {"add_rr_NS", l_sdns_add_rr_NS},
    {"add_rr_MX", l_sdns_add_rr_MX},
    {"add_rr_SOA", l_sdns_add_rr_SOA},
    {"add_rr_PTR", l_sdns_add_rr_PTR},
    {"add_rr_SRV", l_sdns_add_rr_SRV},
    {"add_rr_HINFO", l_sdns_add_rr_HINFO},
    {"add_rr_TXT", l_sdns_add_rr_TXT},
    {"add_rr_CNAME", l_sdns_add_rr_CNAME},
    {"add_rr_NID", l_sdns_add_rr_NID},
    {"add_nsid", l_sdns_add_nsid},
    {"get_nsid", l_sdns_get_value_nsid},
    {"get_header", l_sdns_get_header},
    {"remove_edns", l_sdns_remove_edns},
    {"set_do", l_sdns_set_do},
    {"set_tc", l_sdns_set_tc},
    {"set_qr", l_sdns_set_qr},
    {"set_id", l_sdns_set_id},
    {"set_rd", l_sdns_set_rd},
    {"set_ra", l_sdns_set_ra},
    {"set_aa", l_sdns_set_aa},
    {"set_cd", l_sdns_set_cd},
    {"set_rcode", l_sdns_set_rcode},
    {"get_answer", l_sdns_get_answer},
    {"get_authority", l_sdns_get_authority},
    {"get_additional", l_sdns_get_additional},
    {"get_question", l_sdns_get_question},
    {"send_udp", l_sdns_send_udp},
    {"send_tcp", l_sdns_send_tcp},
    {"create_response_from_query", l_sdns_create_response_from_query},
    // TODO: ADD more function here
    {NULL, NULL}
};

int luaopen_libsdns(lua_State * L){
    // initialize the metatable
    srand(time(NULL));
    luaL_newmetatable(L, "metasdnslib");
    
    lua_pushcfunction(L, l_sdns_free_context);
    lua_setfield(L, -2, "__gc");
    
    //lua_pop(L, 1);
    // This exists in lua version >= 5.2
    luaL_newlib(L, sdns_lib_expose);
    return 1;
}
