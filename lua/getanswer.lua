--[[
-- Here we provide this example to show the usecase of the lua binding
-- for sdns library.
--
-- The code creates a DNS query packet asking for TXT record of 
-- google.com. The it sends the packet to cloudflare 1.1.1.1
-- and print the answer on the console.
--
-- We used several functions here:
--
-- 1. create_query(): to make a DNS query packet
-- 2. to_network(): to convert the DNS query packet to bytestream 
-- ready for the socket.
-- 3. send_udp(): Sends the packet to 1.1.1.1 server
-- 4. from_network(): covert the answer of 1.1.1.1 to a DNS packet.
-- 5. get_header(): get the DNS header from the response packet
-- 6. get_answer(): iterate over the answer section of th DNS and print them out.
--
-- Compiled and tested on a 64-bit Ubuntu 24.04
--
--]]
local sdns = require "libsdns"
local inspect = require "inspect"

local dns = sdns.create_query("google.com", "txt", "in");
assert (dns ~= nil)

local err, msg;


to_send, msg = sdns.to_network(dns)
assert(msg == nil)
assert(to_send ~= nil)

local datatbl = {to_send=to_send, dstip="1.1.1.1",
              dstport=53, timeout=3}

data, msg = sdns.send_udp(datatbl)
assert(msg == nil)
assert (data ~= nil)

local response, msg = sdns.from_network(data)
assert(response ~= nil)
assert(msg == nil)


header, msg = sdns.get_header(response);

for i=1, header.ancount do
    ans, msg = sdns.get_answer(response, i)
    assert(ans ~= nil)
    assert(msg == nil)
    print(string.format("%d. %s", i, ans.rdata.txtdata))
end

