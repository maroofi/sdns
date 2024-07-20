#!/usr/bin/lua

local netlib = require "sdnsnetlib"
local sdns = require "sdnslib"
local inspect = require "inspect"

local dns = sdns.create_query("msn.com", "a", "in");
assert (dns ~= nil)

--[[
tbl_a = {
    name="google.com", ttl=300,
    section="additional",
    rdata={ip="1.2.3.4"}
}
res, msg = sdns.add_rr_A(dns, tbl_a)
assert(res == 0)
assert(msg == nil)

assert(sdns.add_nsid(dns, "") == 0)

tbl_ns = {
    name="google.com", ttl=300,
    section="additional",
    rdata={nsname="ns1.google.com"}
}
res, msg = sdns.add_rr_NS(dns, tbl_ns)
assert(res == 0)
assert(msg == nil)


sdns.print_dns(dns)

sdns.remove_edns(dns)
sdns.print_dns(dns)

--]]

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
header, msg = sdns.get_header(response);
assert(header ~= nil);
assert(msg == nil);

sdns.print_dns(response)
-- let's remove edns0 part
assert(sdns.remove_edns(response) == 0)
sdns.print_dns(response)

--[[
if header.tc == 1 then
    print("We need to issue the query using TCP....")
    data, msg = netlib.send_tcp(datatbl)
    assert(data ~= nil)
    assert(msg == nil)
    response, msg = sdns.from_network(data);
    assert(response ~= nil)
    assert(msg == nil)
    sdns.print_dns(response)
else
    sdns.print_dns(response)
end
--]]

