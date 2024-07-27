--[[
-- This example shows a mini-dig written in Lua with
-- the help of libsdns.so.
--
-- Usage: lua minidig.lua <domain-name> RR
--
-- example:
--      lua minidig.lua google.com A
--      or
--      lua minidig.lua google.com TXT
--
--  it performs both UDP and TCP lookup to answer your question.
--  In case you don't specify the RR, it will be 'A' by default.
--
--
--  Tested and compiled on a 64-bit Ubuntu 24.04 machine.
--
--]]

--make sure the library is loaded
local sdns = require("libsdns")
assert(sdns)

-- this will print the usage of the code
function print_usage()
    print("Usage: lua minidig.lua <domain-name> [RR]")
    print("example: lua minidig.lua google.com TXT")
    print("If you don't specify [RR], it will be 'A' by default")
    print("")
end

-- print error and exit
function print_and_exit(val, msg, exit_code)
    if (val == nil) then
        print("ERROR:", msg);
        os.exit(exit_code)
    end
end

-- we do the heavy load here
function do_query(domain, rr)
    local err, msg, data, dns, answer, header
    
    dns, msg = sdns.create_query(domain, rr, "IN")
    print_and_exit(dns, msg, 1)

    data, msg = sdns.to_network(dns)
    print_and_exit(data, msg, 2)

    local tbl_send = {
        dstport=53, timeout=3,
        dstip="1.1.1.1", to_send= data
    }

    answer, msg = sdns.send_udp(tbl_send)
    print_and_exit(answer, msg, 3)

    answer, msg = sdns.from_network(answer)
    print_and_exit(answer, msg, 4)

    header, msg = sdns.get_header(answer)
    print_and_exit(header, msg, 5)
    
    if header.tc == 1 then
        -- we need to resend the query but this time using TCP
        print(";; Truncated answer....using TCP")
        answer, msg = sdns.send_tcp(tbl_send)
        print_and_exit(answer, msg, 6)
        
        answer, msg = sdns.from_network(answer)
        print_and_exit(answer, msg, 7)
    end
    
    sdns.print_dns(answer)
    return 0;
end



--------------------------------------------------
-- main driver starts from here
-- ----------------------------------------------

-- print usage() and exit if length of command-line arguments is 0
if #arg == 0 then
    print_usage()
    os.exit(1)
end

-- get domain name and RR from command-line
local domain = arg[1] or nil
local rr = arg[2] or 'A'

-- print usage and exit if domain name is empty
if domain == nil then
    print_usage()
    os.exit(1)
end

-- call query function with params and exit
os.exit(do_query(domain, rr));


























