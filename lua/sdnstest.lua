#!/usr//bin/lua

local sdns = require("sdnslib")
local inspect = require("inspect")

function hex_dump(buf)
  for i=1,math.ceil(#buf/16) * 16 do
     if (i-1) % 16 == 0 then io.write(string.format('%08X  ', i-1)) end
     io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
     if i %  8 == 0 then io.write(' ') end
     if i % 16 == 0 then io.write( buf:sub(i-16+1, i):gsub('%c','.'), '\n' ) end
  end
 end

function routine1()
    local err, msg
    local dns = sdns.create_query("google.com", "A", "IN")


    err, msg = sdns.add_rr_AAAA(dns, {name="ipv6.com", section="answer", ttl=100, rdata={ip="::1"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_AAAA(dns, {name="ipv6.com", section="authority", ttl=100, rdata={ip="fe80::377d:50f8:64d3:ffe"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_AAAA(dns, {name="ipv6-additional.com", section="additional", ttl=100, rdata={ip="fe80::377d:50f8:64d3:ffe"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_NID(dns, {name="nidie.com", section="answer", ttl=100, rdata={nodeid="\x00\x00\x12\x45\x43\x6a\xaa\xbb", preference=10}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_CNAME(dns, {name="cname.com", section="answer", ttl=100, rdata={cname="validcname.com"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="txt.com", section="answer", ttl=100, rdata={txtdata="txt in answer section"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="txt.com", section="answer", ttl=100, rdata={txtdata="txt with \0 NULL char"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="verylongtxt.com", section="answer", ttl=100, rdata={txtdata="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="txt.com", section="authority", ttl=100, rdata={txtdata="txt in answer section"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="txt.com", section="authority", ttl=100, rdata={txtdata="txt with \0 NULL char"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="verylongtxt.com", section="authority", ttl=100, rdata={txtdata="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="txt.com", section="additional", ttl=100, rdata={txtdata="txt in answer section"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="txt.com", section="additional", ttl=100, rdata={txtdata="txt with \0 NULL char"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_TXT(dns, {name="verylongtxt.com", section="additional", ttl=100, rdata={txtdata="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}})
    assert(err == 0)
    assert(msg == nil)

    err, msg = sdns.add_rr_A(dns, {name="google.com", section="answer", ttl=300, rdata={ip="1.2.3.4"}})
    if (err ~= 0) then
        print("ERROR in add A record to answer section:", err, msg)
        return 1;
    end

    err, msg = sdns.add_rr_NS(dns, {name="google.net", ttl=300, 
                                    rdata={nsname="ns1.yahoo.com"}, 
                                    section="authority"})
    if (err ~= 0) then
        print("ERROR in add NS record to answer section:", err, msg)
        return 1;
    end
    
    err, msg = sdns.add_rr_MX(dns, {name="google.net", ttl=300, 
                                    rdata={preference=10, exchange="mx1.baidu.com"}, 
                                    section="additional"})
    if (err ~= 0) then
        print("ERROR in add MX record to additional section:", err, msg)
        return 1;
    end

    err, msg = sdns.add_rr_SOA(dns, {name="google.net", ttl=300, 
                                    rdata={mname="ns1.google.com", rname="dns-admin.google.com.",
                                    refresh=900, retry=900, expire=1800, minimum=60, serial=652208131}, 
                                    section="authority"})
    if (err ~= 0) then
        print("ERROR in add SOA record to additional section:", err, msg)
        return 1;
    end




    err, msg = sdns.add_rr_SRV(dns, {name="google.net", ttl=300, 
                                    rdata={priority=1, weight=2, port=3, target="target.com"}, 
                                    section="additional"})
    if (err ~= 0) then
        print("ERROR in add SRV record to additional section:", err, msg)
        return 1;
    end

    err, msg = sdns.add_rr_PTR(dns, {name="ptrname.net", ttl=300, 
                                    rdata={ptrdname="googleptr"}, 
                                    section="additional"})
    if (err ~= 0) then
        print("ERROR in add PTR record to additional section:", err, msg)
        return 1;
    end

    err, msg = sdns.add_rr_HINFO(dns, {name="oscpu.net", ttl=200, 
                                    rdata={os="Linux Ubuntu 24.04", cpu="AMD"}, 
                                    section="additional"})
    if (err ~= 0) then
        print("ERROR in add HINFO record to additional section:", err, msg)
        return 1;
    end

    err, msg = sdns.add_nsid(dns, "Sourena");

    sdns.print_dns(dns)

    local a;
    a, msg = sdns.to_network(dns)
    if (a == nil and msg ~= nil) then
        print("ERROR in to_network(): ", msg)
        return 1;
    end
    

    dns, msg = sdns.from_network(a)
    if (dns == nil) then
        print("ERROR:", msg)
        return 1;
    end
    print("Let's print the packet.....")
    sdns.print_dns(dns)
end


routine1()

