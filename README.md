# C++ DNS Caching Server

The goal of this project is to implement a simple DNS recursive caching server,
mostly to improve my C++ skills and get a better understanding of DNS on a
protocol level.

The server itself will be simple, it will only be able to properly handle
and cache A & CNAME record requests, using another hardcoded recursive server
as it's backend (Google DNS, 8.8.8.8).  Basically it should be able to respond
to simple `dig` and `nslookup` requests.

DNS Protocol Reference: [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt)

## Build & Run

Please install biicode to build, found [here](https://www.biicode.com/).

Then simply run the following commands to build & run:
```
> bii build
> sudo ./bin/user_dns_src_main
```

You should now be able to `dig` and `nslookup` commands on the locally running server, make sure you point them to the loopback ip address.

## Stretch Goals

Some nice things to implement for more fun:

- Do recursive looks up itself properly.  Ping root and authorative dns servers, following the proper hops and not rely on another recursive dns server.
- Read configuration via file.
- Read configuration from other interesting sources (sql db, etcd, etc.)
- Load/Performance test and make improvements based off that.
- Act as an authorative dns server.
- Handle all DNS request and response types.
