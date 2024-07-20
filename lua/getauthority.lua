#!/usr/bin/env lua

local netlib = require "sdnsnetlib"
local sdns = require "sdnslib"
local inspect = require "inspect"

local dns = sdns.create_query("google.com", "ns", "in");
assert (dns ~= nil)

local err, msg;


to_send, msg = sdns.to_network(dns)
assert(msg == nil)
assert(to_send ~= nil)

local datatbl = {to_send=to_send, dstip="192.48.79.30",     -- asking j.gtld-servers.net
              dstport=53, timeout=3}

data, msg = netlib.send_udp(datatbl)
assert(msg == nil)
assert (data ~= nil)

local response, msg = sdns.from_network(data)
assert(response ~= nil)
assert(msg == nil)


header, msg = sdns.get_header(response);
for i=1, header.nscount do
    ans, msg = sdns.get_authority(response, i)
    print(string.format("%d - %s", i, ans.rdata.nsname))
end

