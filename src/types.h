#pragma once

#include <cstdint>
#include <iostream>
#include <list>

enum DNSQType : uint16_t {
  A     = 1,
  NS    = 2,
  MD    = 3,
  MF    = 4,
  CNAME = 5,
  SOA   = 6,
  MB    = 7,
  MG    = 8,
  MR    = 9,
  NIL   = 10,
  WKS   = 11,
  PTR   = 12,
  HINFO = 13,
  MINFO = 14,
  MX    = 15,
  TXT   = 16,
  //QType only
  AXFR  = 252,
  MAILB = 253,
  MAILA = 254,
  ALL   = 255
};

enum DNSQClass : uint16_t {
  IN  = 1,
  CS  = 2,
  CH  = 3,
  HS  = 4,
  //QClass only
  ANY = 255
};

class DNSHeader {
public:
  static const uint16_t SIZE = 12;

  uint16_t id;
  bool qr;
  uint8_t opcode;
  bool aa;
  bool tc;
  bool rd;
  bool ra;
  uint8_t rcode;

  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;

  DNSHeader(const uint8_t* header);
	void toBytes(uint8_t* buffer, int offset);

private:
  friend std::ostream& operator<<(std::ostream&, const DNSHeader&);
};

class DNSQuestion {
public:
  std::list<std::string> qnames;
  uint16_t qtype;
  uint16_t qclass;
  uint16_t size = 0;

  DNSQuestion(const uint8_t* buffer, int offset);
	void toBytes(uint8_t* buffer, int offset);
	std::string getName();

private:
  friend std::ostream& operator<<(std::ostream&, const DNSQuestion&);
};

class DNSResourceRecord {
  public:
    std::list<std::string> names;
		uint8_t compressed[2] = {0, 0};
    //TODO: Should have some DNSType, which only includes subset of QType
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
    uint16_t rdlength;
		uint8_t  *rdata;

    uint16_t size = 0;

    DNSResourceRecord(const uint8_t* buffer, int offset);
		~DNSResourceRecord();
  	void toBytes(uint8_t* buffer, int offset);

  private:
    friend std::ostream& operator<<(std::ostream&, const DNSResourceRecord&);
};

class DNSPacket {
public:
  DNSHeader header;
  std::list<DNSQuestion> questions;
  std::list<DNSResourceRecord> answers;
	uint16_t size = 0;

  DNSPacket(const uint8_t* buffer);
	uint8_t* toBytes();
	std::string cacheKey() const;

private:
    friend std::ostream& operator<<(std::ostream&, const DNSPacket&);
};
