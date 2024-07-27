## Lua binding for sdns library

This page gives you all the necessary information about the Lua exposed API of sdns library.

I have tested the code with **Lua5.4**. It should work for
Lua5.3 and maybe Lua5.2 but it definitely not work with Lua5.1.

To use the Lua binding, you can make the package using **luarocks** or compile the library manually.

Here is the description of the provided functions in Lua:

* List of functions
    * [create_query() - Creates a new DNS packet](#create_queryquery_name-query_type-query_class)
    * [create_response_from_query() - Create a response DNS packet based on the given DNS packet](#create_response_from_querysdns_context)
    * [print_dns() - Print a DNS packet](#print_dnssdns_context)
    * [from_network() - Converts binary network data to a DNS packet](#from_networkdata)
    * [to_network() - Converts a DNS packet to network binary data](#to_networksdns_context)
    * [send_udp() - Sends a DNS packet over UDP](#send_udptbl-to-send)
    * [send_tcp() - Sends a DNS packet over TCP](#send_tcptbl-to-send)
    * [add_rr_A() - Adds A RR to a DNS packet](#add_rr_asdns_context-table-data)
    * [add_rr_AAAA() - Adds AAAA RR to a DNS packet](#add_rr_aaaasdns_context-table-data)
    * [add_rr_NS() - Adds NS RR to a DNS packet](#add_rr_nssdns_context-table-data)
    * [add_rr_SOA() - Adds SOA RR to a DNS packet](#add_rr_soasdns_context-table-data)
    * [add_rr_MX() - Adds MX RR to a DNS packet](#add_rr_mxsdns_context-table-data)
    * [add_rr_PTR() - Adds PTR RR to a DNS packet](#add_rr_ptrsdns_context-table-data)
    * [add_rr_SRV() - Adds SRV RR to a DNS packet](#add_rr_srvsdns_context-table-data)
    * [add_rr_HINFO() - Adds HINFO RR to a DNS packet](#add_rr_hinfosdns_context-table-data)
    * [add_rr_TXT() - Adds TXT RR to a DNS packet](#add_rr_txtsdns_context-table-data)
    * [add_nsid() - Adds NSID to EDNS0 section of the DNS packet](#add_nsidsdns_context-nsid)
    * [get_nsid() - Gets NSID value from a DNS packet](#get_nsidsdns_context)
    * [get_header() - Returns header of a DNS packet](#get_headersdns_context)
    * [get_question() - Returns the question section of the DNS packet](#get_questionsdns_context)
    * [get_answer() - Gets answer records of a DNS packet](#get_answersdns_context-num)
    * [get_additional() - Gets additional records of a DNS packet](#get_additionalsdns_context-num)
    * [get_authority() - Gets authority records of a DNS packet](#get_authoritysdns_context-num)
    * [set_do() - Sets or resets DO bit of a DNS packet](#set_dosdns_context-do_bit)
    * [set_tc() - Sets or resets TC bit of a DNS packet](#set_tcsdns_context-tc_bit)
    * [set_rd() - Sets or resets RD bit of a DNS packet](#set_rdsdns_context-rd_bit)
    * [set_ra() - Sets or resets RA bit of a DNS packet](#set_rasdns_context-ra_bit)
    * [set_aa() - Sets or resets AA bit of a DNS packet](#set_aasdns_context-aa_bit)
    * [set_cd() - Sets or resets CD bit of the EDNS0 in a DNS packet](#set_cdsdns_context-cd_bit)
    * [set_id() - Sets the ID of a DNS packet](#set_idsdns_context-id_num)
    * [set_rcode() - Sets the rcode value of a DNS packet](#set_rcodesdns_context-rcode)
    * [remove_ends() - Removes EDNS0 from a DNS packet](#remove_endssdns_context)


-------------------------------------------------------------------

#### __create_query__(query_name, query_type, query_class)

This function creates a DNS query packet ready to ask a question from a server. On a successful call, the function returns a DNS context which can be passed to other functions of the library. This method (by default), makes an EDNS0-aware DNS packet.
This means the packet has an empty edns0 in the additional section. If you want to remove the ENDS0 option from the packet (You can not have NSID, cookie, EDE, etc anymore!), you can use the function __remove_ends()__ to remove it from the DNS context.

    - returns:
        - (sdns_context, nil) on success
        - (nil, error-message) on failure
    - param:
        - query_name (string - mandatory): The is the FQDN we want to query. e.g., `google.com`
        - query_type (string - mandatory): The type of the query, e.g, `A`, `AAAA`, `HINFO`, `MX`, `SOA`, `NS`, `PTR`, and `SRV`
        - query_class (string - mandatory): The class of the query. e.g., `IN`, `CH`

------------------------------------------------------------------

#### __print_dns__(sdns_context)
    - returns: Nothing. This function just print the DNS packet neatly to the standard output.
    - params:
        - sdns_context: the context returned by __create_query()__ function.

This function is useful for mostly debugging purpose when you want to see the DNS packet you received or you created.

------------------------------------------------------------------
#### __from_network__(data)
    - returns:
        - (sdns_context, nil) on success
        - (nil, error-message) on failure
    - params:
        - data (string - mandatory): the data you received from socket and you want to convert it to a DNS packet.

This function receives the binary data and try to convert it to a DNS packet (if it's a valid DNS binary data). When we receive data from socket, we pass it to this function and on a successful call, we will receive the decoded DNS packet in a form of a sdns_context data. Checkout the examples to see how it is used.

------------------------------------------------------------------
#### __to_network__(sdns_context)
    - returns:
        - (byte-stream string, nil) on success
        - (nil, error-message-string) on failure
    - params:
        sdns_context: The context we created using __create_query()__ or __from_network()__ functions.

After creating our DNS packet, we need to convert it to binary data in order to send it over the network. This function converts DNS context to binary data ready to be sent.

------------------------------------------------------------------
#### __send_udp__(tbl-to-send)
    - returns:
        - (result-string, nil) on success
        - (nil, err-string) on failure
    - param:
        - tbl-to-send: This is the only input parameter and it's a table with 
        the following keys:
            - dstport: (integer): port number to send the data to
            - dnsip: (string): IP address of receiver of the data
            - timeout (integer): timeout to wait for socket operation
            - to_send: (string): the data you want to send over the socket
    
A very typical example of using this function is a scenario like this:
1. we create a DNS query packet using __create_query()__ function.
2. Converting the DNS query packet (step 1) to network data using __to_network()__
3. Using __send_udp()__, we send the data to cloudflare resolver
4. Convert the result of step 3 to DNS packet using __from_network()__
5. print out the DNS packet of step 4 by using __print_dns()__ function.

-------------------------------------------------------------------
#### __send_tcp__(tbl-to-send)
    - returns:
        - (result-string, nil) on success
        - (nil, err-string) on failure
    - param:
        - tbl-to-send: This is the only input parameter and it's a table with 
        the following keys:
            - dstport: (integer): port number to send the data to
            - dnsip: (string): IP address of receiver of the data
            - timeout (integer): timeout to wait for socket operation
            - to_send: (string): the data you want to send over the socket
    
This function works exactly like __send_udp()__ but uses TCP to send and receive
data. Note that this function is only good for DNS data since it adds two extra
bytes to the beginning of the DNS data to show the length of the data. Therefore,
it's not suitable for other types of TCP transactions.

Considering the scenario of __send_udp()__ function. After step 4, we can check the DNS header TC bit to see if we need to switch to TCP or not. if TC is equal to 1, it means that we need to use __send_tcp()__ to send the payload again.

-----------------------------------------------------------------


#### __add_rr_A__(sdns_context, table-data)
    - returns:
        - (0, nil) on success
        - (non-zero, error-msg) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `A` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the A record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the A record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains only 'ip' field which is the IP address you want to add.

Here is an example of calling this function.
```lua
    -- add the library
    local sdns = require("sdnslib")
    assert(sdns)

    -- create a DNS packet with a question
    dns, msg = sdns.create_query("google.com", "A", "IN")
    assert (dns ~= nil)
    assert (msg == nil)

    -- Adds an A record to the answer section of the packet
    -- you can call add_rr_A() several times to add
    -- several A record to different sections of the 
    -- DNS packet
    tbl_a = {
        name="google.com", ttl=300,
        section="answer",
        rdata={ip="1.2.3.4"}
    }
    res, msg = sdns.add_rr_A(dns, tbl_a)
    assert(res == 0)
    assert(msg == nil)

    -- create the binary data from DNS packet
    bindata, msg = sdns.to_network(dns)
    assert(bindata ~= nil)
    assert (msg == nil)

    -- now you can send 'bindata' over the socket

```
------------------------------------------------------------------

#### __add_rr_AAAA__(sdns_context, table-data)
    - returns:
        - (0, nil) on success
        - (non-zero, error-msg) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `AAAA` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the AAAA record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the AAAA record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains only 'ip' field which is the IP address you want to add.


To see and example of using this function, check the documentation of __add_rr_A__() function.

-------------------------------------------------------------------

#### __add_rr_NS__(sdns_context, table-data)
    - returns:
        - (0, nil) on success
        - (non-zero, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `NS` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the NS record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the NS record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains only 'nsname' field which is the nameserver you want to add.

example of calling this method:
```lua
    local tbl_ns = {
        name="google.com", ttl=300,
        section="additional",
        rdata={nsname="ns1.google.com"}
    }
    res, msg = sdns.add_rr_NS(dns, tbl_ns)
    assert(res == 0)
    assert (msg == nil)
```
------------------------------------------------------------------

#### __add_rr_SOA__(sdns_context, table-data)
    - returns:
        - (0, nil) on success
        - (non-zero, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `SOA` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the SOA record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the SOA record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains the following mandatory field:
                - *mname* (string)
                - *rname* (string)
                - *expire* (32bit unsigned integer)
                - *minimum* (32bit unsigned integer)
                - *retry* (32bit unsigned integer)
                - *refresh* (32bit unsigned integer)
                - *serial* (32bit unsigned integer)

For the description of each field of the 'rdata', you can read RFC1035 (SOA data format). Here is an example of calling this function:

```lua
    local tbl_soa = {
        name="google.com", ttl=300,
        section="authority",
        rdata={
            mname="ns1.google.com",
            rname="dns-admin.google.com.",
            refresh=900, retry=900,
            expire=1800, minimum=60,
            serial=652208131
        }
    } 
    -- using dig, this creates the following record
    -- google.com. 300	IN SOA ns1.google.com. dns-admin.google.com. 652208131 900 900 1800 60
    res, msg = sdns.add_rr_SOA(dns, tbl_soa)
    assert(res == 0)
    assert (msg == nil)
```
------------------------------------------------------------------

#### __add_rr_MX__(sdns_context, table-data)
    - returns:
        - (0, nil) on success
        - (non-zero, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `MX` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the MX record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the MX record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains the following mandatory field:
                - *exchange* (string)
                - *preference* (16bit unsigned integer)
                
For the description of each field of the 'rdata', you can read RFC1035 (MX data format). Here is an example of calling this function:

```lua
    local tbl_mx = {
        name="google.com", ttl=300,
        section="answer",
        rdata={
            exchange="smtp.google.com",
            preference=10,
        }
    } 
    -- using dig, this creates the following record
    -- google.com. 300	IN MX 10 smtp.google.com.
    res, msg = sdns.add_rr_MX(dns, tbl_mx)
    assert(res == 0)
    assert (msg == nil)
```
------------------------------------------------------------------

#### __add_rr_PTR__(sdns_context, table-data)
    - returns:
        - (0, nil) on success
        - (non-zero, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `PTR` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the PTR record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the PTR record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains the following mandatory field:
                - *ptrdname* (string)
                
For the description of each field of the 'rdata', you can read RFC1035 (PTR data format). Here is an example of calling this function:

```lua
    local tbl_ptr = {
        name="1.1.1.1.in-addr.arpa.", ttl=300,
        section="answer",
        rdata={
            ptrdname="one.one.one.one"
        }
    } 
    -- using dig, this creates the following record
    -- 1.1.1.1.in-addr.arpa. 300 IN PTR one.one.one.one
    res, msg = sdns.add_rr_PTR(dns, tbl_ptr)
    assert(res == 0)
    assert (msg == nil)
```
------------------------------------------------------------------

#### __add_rr_SRV__(sdns_context, table-data)
    - returns:
        - (0, nil) on success
        - (non-zero, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `SRV` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the SRV record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the SRV record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains the following mandatory field:
                - *target* (string)
                - *priority* (16bit unsigned integer)
                - *weight* (16bit unsigned integer)
                - *port* (16bit unsigned integer)
                
For the description of each field of the 'rdata', you can read RFC 2782 (SRV data format). Here is an example of calling this function:

```lua
    local tbl_srv = {
        name="google.com", ttl=300,
        section="answer",
        rdata={
            priority=10,
            weight=0,
            port=44,
            target="old-slow-box.example.com"
        }
    } 
    res, msg = sdns.add_rr_SRV(dns, tbl_srv)
    assert(res == 0)
    assert (msg == nil)
```
------------------------------------------------------------------

#### __add_rr_HINFO__(sdns_context, table-data)
    - returns:
        - (0, nil) on success
        - (non-zero, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `HINFO` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the HINFO record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the HINFO record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains the following mandatory field:
                - *os* (string): OS information
                - *cpu* (string): CPU information
                
For the description of each field of the 'rdata', you can read RFC 1035 (HINFO data format). Here is an example of calling this function:

```lua
    local tbl_hinfo = {
        name="google.com", ttl=300,
        section="answer",
        rdata={
            os="Linux",
            cpu="Intel"
        }
    } 
    res, msg = sdns.add_rr_hinfo(dns, tbl_hinfo)
    assert(res == 0)
    assert (msg == nil)
```
------------------------------------------------------------------

#### __add_rr_TXT__(sdns_context, table-data)
    - return:
        - (0, nil) on success
        - (non-zero, err-msg-string) on failure
    params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - table-data (table - mandatory): This input table contains the information regarding the `TXT` record you want to add to the DNS packet. It must contain all the following fields (all mandatory):
            - *name* (string): the domain name for the TXT record
            - *ttl* (integer): the TTL value of the resource record
            - *section* (string): the DNS section you want to add the TXT record. It can be one of the: `answer`, `authority` and/or `additional` values.
            - *rdata* (table): contains the following mandatory field:
                - *txtdata* (string): TXT data

Here is an example of using this function: 

```lua
    local tbl_txt = {
        name="txt.com", section="answer", ttl=100,
        rdata={txtdata="txt in answer section"}
    }
    err, msg = sdns.add_rr_TXT(dns, tbl_txt)
    assert(err == 0)
    assert(msg == nil)

```
------------------------------------------------------------------

#### __add_nsid__(sdns_context, nsid)
    - returns:
        - (0, nil) on success
        - (non-zero, err-msg) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - nsid (string - mandatory): The string you want to set as the NSID of the DNS packet. If you pass an empty string, the packet will be NSID-aware (this is good for making queries that ask NSID of the server).

Here is the example of create a NSID-aware packet to send it to google 8.8.8.8
```lua
    local sdns = require("sdnslib")
    assert (sdns)

    -- create a query for asking A record of google.com
    dns, msg = sdns.create_query("google.com", "A", "IN")
    assert (dns ~= nil)
    assert (msg == nil)

    -- make the packet NSID aware
    -- we pass empty string
    res, msg = sdns.add_nsid(dns, "")
    assert(res == 0)
    assert(msg == nil)

    bin_data, msg = sdns.to_network(dns)
    assert(bin ~= nil)
    assert(msg == nil)

    -- now you can send the packet to 8.8.8.8
```
------------------------------------------------------------------

#### __get_nsid__(sdns_context)
    - returns:
        - (nsid-string, nil) on success
        - (nil, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.

This function returns the NSID string of the DNS packet if there exists any. If there is no NSID string in the DNS packet, it returns an error message. Usually, you need to first ask for an NSID from the server so that the server send it back. Here is an example of creating an NSID-aware DNS packet, send it to the server and print the response NSID of the server.
```lua
    local sdns = require("sdnslib")
    assert (sdns)

    -- create a query for asking A record of google.com
    dns, msg = sdns.create_query("google.com", "A", "IN")
    assert (dns ~= nil)
    assert (msg == nil)

    -- make the packet NSID aware
    -- we pass empty string
    res, msg = sdns.add_nsid(dns, "")
    assert(res == 0)
    assert(msg == nil)

    bin_data, msg = sdns.to_network(dns)
    assert(bin ~= nil)
    assert(msg == nil)

    -- now you can send the packet to 8.8.8.8
    -- assuming that the binary result from 8.8.8.8
    -- is stored in 'result_data'

    response, msg = sdns.from_network(result_data)
    assert(response ~= nil)
    assert(msg == nil)

    nsid, msg = sdns.add_nsid(response)

    if (nsid != nil) then
        print("NSID: ", nsid)
    else
        print("ERROR in NSID data: ", msg)
    end
```
------------------------------------------------------------------
#### __get_header__(sdns_context)
    - returns:
        - (header-table, nil) on success
        - (nil, msg-err-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.

This function returns the header of the DNS packet as a Lua table. All the keys of the table are lowercase. Below, is an example of how to work with this API.

```lua
    -- load sdns and inspect modules
    local sdns = require "sdnslib"
    local inspect = require "inspect"

    -- create a query packet
    local dns = sdns.create_query("msn.com", "a", "in");
    assert(dns ~= nil)

    header, msg = sdns.get_header(dns)
    assert(msg == nil)
    assert(header ~= nil)

    print(inspect(header))
    -- here is the output
    --[[
    {
        aa = 0, ad = 0,
        ancount = 0, arcount = 1,
        cd = 0, id = 62238,
        nscount = 0, opcode = 0,
        qdcount = 1, qr = 0,
        ra = 0, rcode = 0,
        rd = 1, tc = 0,
        z = 0
    }
    --]]
```

------------------------------------------------------------------
#### __set_do__(sdns_context, do_bit)
    - returns:
        - (0, nil) on success
        - (non-zero, msg-err-string) on failure
    - param:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - do_bit: 0 or 1 to set or unset DO bit.

------------------------------------------------------------------
#### __set_tc__(sdns_context, tc_bit)
    - returns:
        - (0, nil) on success
        - (non-zero, msg-err-string) on failure
    - param:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - tc_bit: 0 or 1 to set or unset TC bit.

------------------------------------------------------------------
#### __set_rd__(sdns_context, rd_bit)
    - returns:
        - (0, nil) on success
        - (non-zero, msg-err-string) on failure
    - param:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - rd_bit: 0 or 1 to set or unset RD bit.

------------------------------------------------------------------
#### __set_ra__(sdns_context, ra_bit)
    - returns:
        - (0, nil) on success
        - (non-zero, msg-err-string) on failure
    - param:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - ra_bit: 0 or 1 to set or unset RA bit.

------------------------------------------------------------------
#### __set_aa__(sdns_context, aa_bit)
    - returns:
        - (0, nil) on success
        - (non-zero, msg-err-string) on failure
    - param:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - aa_bit: 0 or 1 to set or unset AA bit.

------------------------------------------------------------------
#### __set_cd__(sdns_context, cd_bit)
    - returns:
        - (0, nil) on success
        - (non-zero, msg-err-string) on failure
    - param:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - cd_bit: 0 or 1 to set or unset CD bit.


------------------------------------------------------------------
#### __set_id__(sdns_context, id_num)
    - returns:
        - (0, nil) on success
        - (non-zero, msg-err-string) on failure
    - param:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - id_num: a 16-bit unsigned integer number used as the ID of the DNS packet.

------------------------------------------------------------------
#### __remove_ends__(sdns_context)
    - returns:
        - (0, nil) on success
        - (non-zero, msg-err-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - id_num: a 16-bit unsigned integer number used as the ID of the DNS packet.
    
This function removes the EDNS0 option from the additional section of the DNS packet. When you use __create_query()__ function
to create a DNS context, it creates an EDNS0-aware DNS packet by adding OPT RR to the additional section of the package. If you 
don't want it (which is somehow weired!), you can use this function to safely remove it.

```lua
    local sdns = require "sdnslib"

    -- the packet we create here has empty EDNS0 
    -- in its additional section
    local dns = sdns.create_query("msn.com", "a", "in");
    assert (dns ~= nil)

    -- now we don't need edns0 and we want to remove it!
    assert(sdns.remove_edns(dns) == 0)

```

------------------------------------------------------------------

#### __get_answer__(sdns_context, num)
    - returns: 
        - (answer-table, nil) on success
        - (nil, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - num: The number of the answer to be retrieved from the answer section of the DNS context (starting from one).

Assuming that you asked for the A record of yahoo.com and the received packet has four RR in the answer section (all A records of yahoo.com). You can call this function 4 times passing _num_ parameter from 1 to 4 to get all the answer RRs. If you ask for the fifth RR in the answer section, you will get the error message (answer not found).

The returned result is a table exactly with the same syntax of the tables you pass to add_rr_* functions. Here is an example of asking SOA of google:

```lua
    local netlib = require "sdnsnetlib"
    local sdns = require "sdnslib"
    local inspect = require "inspect"

    -- create a query packet asking for SOA
    -- of google.com domain name
    dns = sdns.create_query("google.com", "soa", "in");
    assert (dns ~= nil)

    -- params for the UDP request
    local datatbl = {
        to_send=to_send, 
        dstip="1.1.1.1",
        dstport=53, timeout=3
    }
    -- send a UDP request to cloudflare DNS
    data, msg = netlib.send_udp(datatbl)
    assert(msg == nil)
    assert (data ~= nil)

    -- convert network data to DNS packet
    local response, msg = sdns.from_network(data)
    assert(response ~= nil)
    assert(msg == nil)

    -- getting the first (and only answer)
    ans, msg = sdns.get_answer(response, 1)
    print(inspect(ans))

    -- this is what you get in the output
    --[[
        {
            class = "IN",
            name = "google.com.",
            rdata = {
                expire = 1800,
                minimum = 60,
                mname = "ns1.google.com.",
                refresh = 900,
                retry = 900,
                rname = "dns-admin.google.com.",
                serial = 653161262
            },
            ttl = 32,
            type = "SOA"
        }
    --]]
```

Another example is printing all the TXT records of the google.com domain name:
```lua
local netlib = require "sdnsnetlib"
local sdns = require "sdnslib"
local inspect = require "inspect"

local dns = sdns.create_query("google.com", "txt", "in");
assert (dns ~= nil)

local err, msg;


to_send, msg = sdns.to_network(dns)
assert(msg == nil)
assert(to_send ~= nil)

local datatbl = {to_send=to_send, dstip="1.1.1.1",
                 dstport=53, timeout=3}

data, msg = netlib.send_udp(datatbl)
assert(msg == nil)
assert (data ~= nil)

local response, msg = sdns.from_network(data)
assert(response ~= nil)
assert(msg == nil)

-- we will use the header to get the number
-- of records in the answer section
header, msg = sdns.get_header(response);

-- enumerate the answer using ancount field of the header
for i=1, header.ancount do
    ans, msg = sdns.get_answer(response, i)
    assert(ans ~= nil)
    assert(msg == nil)
    print(i, ". ", ans.rdata.txtdata)
end
--[[
    The output of the code is:
    1. cisco-ci-domain-verification=479146de172eb01ddee38b1a455ab9e8bb51542ddd7f1fa298557dfa7b22d963
    2. docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e
    3. docusign=1b0a6754-49b1-4db5-8540-d2c12664b289
    4. v=spf1 include:_spf.google.com ~all
    5. apple-domain-verification=30afIBcvSuDV2PLX
    6. google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o
    7. onetrust-domain-verification=de01ed21f2fa4d8781cbc3ffb89cf4ef
    8. globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=
    9. MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB
    10. facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95
    11. google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ
--]]
```

------------------------------------------------------------------
#### __get_additional__(sdns_context, num)
    - returns: 
        - (additional-table, nil) on success
        - (nil, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - num: The number of the additional to be retrieved from the additional section of the DNS context (starting from one).

Assuming that you asked for the NS record of yahoo.com (from its authorative server) and the received packet has also 4 RRs in the additional section 
(all A records of yahoo.com). You can call this function 4 times passing _num_ parameter from 1 to 4 to get all the answer RRs.
If you ask for the fifth RR in the answer section, you will get the error message (answer not found).

**NOTE**: This function can not get the OPT RR part of the additional section as OPT has a different structure compared to other RRs.
To get the OPR RR information, you can use other functions like __get_nsid__() or __get_cookie__().

The returned result is a table exactly with the same syntax of the tables you pass to add_rr_* functions. Here is an example of asking for ns of google.com from
its authoritative name server.

```lua
-- loading the necessary libraries
local netlib = require "sdnsnetlib"
local sdns = require "sdnslib"
local inspect = require "inspect"

-- create a simple query packet asking for NS of Google
local dns = sdns.create_query("google.com", "ns", "in");
assert (dns ~= nil)

local err, msg;

-- creating byte-stream from the DNS context
to_send, msg = sdns.to_network(dns)
assert(msg == nil)
assert(to_send ~= nil)

-- this is the IP address of the ns1.google.com
-- since the server is authoritative, it also gives us the IP addresses
-- of google.com in the additional section
local datatbl = {to_send=to_send, dstip="216.239.32.10",
              dstport=53, timeout=3}

-- sending the request
data, msg = netlib.send_udp(datatbl)
assert(msg == nil)
assert (data ~= nil)

-- convert the socket response to DNS context
local response, msg = sdns.from_network(data)
assert(response ~= nil)
assert(msg == nil)

-- get the header to see how many RR we have in the additional section
header, msg = sdns.get_header(response);
print(string.format("The packet has %d records in the additional section", header.arcount))

-- iterate over the additional section to get the RRs
-- the last one is EDNS0 and the function returns (nil, nil)
-- and we don't print it.
for i=1, header.arcount do
    -- one of the additional records might be a OPT (e.g., cookie) which
    -- this function can not fetch it and will return nil
    ans, msg = sdns.get_additional(response, i)
    if (ans) then
        print(string.format("%d - %s", i, ans.rdata.ip))
    end
end

-- here is the output of the script
--[[
    The packet has 9 records in the additional section
    1 - 216.239.34.10
    2 - 2001:4860:4802:0034:0000:0000:0000:000a
    3 - 216.239.38.10
    4 - 2001:4860:4802:0038:0000:0000:0000:000a
    5 - 216.239.32.10
    6 - 2001:4860:4802:0032:0000:0000:0000:000a
    7 - 216.239.36.10
    8 - 2001:4860:4802:0036:0000:0000:0000:000a
--]]
```

------------------------------------------------------------------
#### __get_authority__(sdns_context, num)
    - returns: 
        - (answer-table, nil) on success
        - (nil, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create\_query()__ or __from_network()__ function.
        - num: The number of the authority RR to be retrieved from the authority section of the DNS context (starting from one).

This function exactly works like __get_answer__() function. The only difference is that it will be applied on the _authority_ section of the DNS context
instead of the answer section.

In the following example, I print the authority section of the respose of the query:
`dig google.com @j.gtld-servers.net. ns`

```lua
-- loads the necessary modules
local netlib = require "sdnsnetlib"
local sdns = require "sdnslib"
local inspect = require "inspect"

-- create a query DNS packet
local dns = sdns.create_query("google.com", "ns", "in");
assert (dns ~= nil)

local err, msg;

-- make the packet ready for the network
to_send, msg = sdns.to_network(dns)
assert(msg == nil)
assert(to_send ~= nil)

-- we send the data to 'j.gtld-servers.net' with
-- the IP address of '192.48.79.30'
local datatbl = {to_send=to_send, dstip="192.48.79.30",
              dstport=53, timeout=3}

-- sending the query
data, msg = netlib.send_udp(datatbl)
assert(msg == nil)
assert (data ~= nil)

-- parsing the response
local response, msg = sdns.from_network(data)
assert(response ~= nil)
assert(msg == nil)

-- printing the authority section of the response
header, msg = sdns.get_header(response);
for i=1, header.nscount do
    ans, msg = sdns.get_authority(response, i)
    print(string.format("%d - %s", i, ans.rdata.nsname))
end

```
------------------------------------------------------------------------
#### __set_rcode__(sdns_context, rcode)
    - returns: 
        - (0, nil) on success
        - (nil, err-msg-string) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.
        - rcode: The rcode specified in RFC 1035. This can be a value between 0 to 16 (excluded) as the rcode is only 4 bits.

This function is useful when you want to create a packet with different rcode values like NXDomain.

------------------------------------------------------------------------
#### __get_question__(sdns_context)
    - returns:
        - (table, nil) on success
        - (nil, err-msg-str) on failure
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.

This function returns the question section of a DNS packet as a table. In a successful call, the returned table
is like this:

```lua
-- this is what you receive from get_question()
local dns = sdns.create_query("google.com", "A", "IN")
assert(dns)
local qtbl, msg = sdns.get_question(dns)

-- the 'qtbl' variable is like:
--[[
    {
        qname="google.com",
        qtype="A",
        qclass="IN"
    }
--]]
```

------------------------------------------------------------------------
#### __create_response_from_query__(sdns_context)
    - returns:
        - (sdns_context, nil) on success
        - (nil, err-msg) on fail
    - params:
        - sdns_context: the DNS context created by __create_query()__ or __from_network()__ function.

Assuming that you received a query from network, usually here is the things you should do to create a response packet:

1. create a new DNS packet
2. change the ID of the new packet to the query you received
3. set the qr bit of the new packet to 1
4. check if the query packet supports EDNS0 or not and based on that, add or remove EDNS0 to/from the new packet.
5. copy the question section of the query packet to the response packet.
6. add appropriate answers, authorities or additional data as you wish.
7. convert the DNS packet to network data
8. send it back to the client.

This function performs the first 5 steps for you!

------------------------------------------------------------------------
