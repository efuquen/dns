# C++ DNS Caching Server

The goal of this project is to implement a simple DNS recursive caching server,
mostly to improve my C++ skills and get a better understanding of DNS on a
protocol level.

The server itself will be super simple, it will only be able to properly handle
and cache A & CNAME record requests, using another hardcoded recursive server
as it's backend (Google DNS, 8.8.8.8).  Basically it should be able to respond
to simple `dig` and `nslookup` requests.

## Stretch Goals

Some nice things to implement for more fun:

- Do recursive looks up itself properly.  Ping root and authorative dns servers, following the proper hops and not rely on another recursive dns server.
- Read configuration via file.
- Read configuration from other interesting sources (sql db, etcd, etc.)
- Load/Performance test and make improvements based off that.
- Act as an authorative dns server.
- Handle all DNS request and response types.
