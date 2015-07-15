#include "Poco/Net/DatagramSocket.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Exception.h"

#include <iostream>
#include <stdexcept>
#include <cstdint>
#include <list>

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

  DNSHeader(const std::uint8_t* header) {
    id = ((uint16_t)header[0] << 8) | header[1];

    uint16_t headerPart = ntohs(header[1]);
    qr = (header[2] & 0x80) == 0x80;
    opcode = (header[2] >> 3) & 0x0F;
    aa = (header[2] & 0x04) == 0x04;
    tc = (header[2]& 0x02) == 0x02;
    rd = (header[2] & 0x01) == 0x01;
    ra = (header[3] & 0x80) == 0x80;
    //TODO: verify z is 0?
    rcode = header[3] & 0x0F;

    qdcount = ((uint16_t)header[4] << 8) | header[5];
    ancount = ((uint16_t)header[6] << 8) | header[7];
    nscount = ((uint16_t)header[8] << 8) | header[9];
    arcount = ((uint16_t)header[10] << 8) | header[11];

  }

private:
  friend std::ostream& operator<<(std::ostream&, const DNSHeader&);
};

std::ostream& operator<<(std::ostream &strm, const DNSHeader &dnsh) {
    return strm << "DNSHeader(id: " << dnsh.id << " qr: " << dnsh.qr <<
      " opcode: " << unsigned(dnsh.opcode) << " aa: " << dnsh.aa << " tc: " <<
      dnsh.tc << " rd: " << dnsh.rd << " ra: " << dnsh.ra << " rcode: " <<
      unsigned(dnsh.rcode) << " qdcount: " << dnsh.qdcount << " ancount: " <<
      dnsh.ancount << " nscount: " << dnsh.nscount << " arcount: " <<
      dnsh.arcount << ")";
}

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

//Extract names from buffer, starting at offset.  Return octects moved through buffer.
int setNames(const std::uint8_t* buffer, int offset, std::list<std::string>* names) {
  //Refers to previous name, call to grab with specified location. Only 2 octects consumed.
  //TODO: optimize by storing already processed names keyed by offset.
  if ((buffer[offset] & 0xc0) == 0xc0) {
    int nameOffset = ((int)(buffer[offset] & 0x3F) << 8) + buffer[offset + 1];
    setNames(buffer, nameOffset, names);
    return 2;
  } else {
    std::uint8_t qnameSize = buffer[offset];
    int size = 1;

    while (qnameSize > 0) {
      char qnameLabel[qnameSize + 1];
      for (int i = 0; i < qnameSize; i++) {
        qnameLabel[i] = buffer[offset + size + i];
      }
      qnameLabel[qnameSize] = '\0';
      size += (qnameSize + 1);
      names->push_back(qnameLabel);
      qnameSize = buffer[offset + size - 1];
    }

    return size;
  }
}

uint16_t readShort(const uint8_t* buffer, int offset) {
  return ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
}

uint32_t readInt(const uint8_t* buffer, int offset) {
  return ((uint32_t)buffer[offset] << 24) | ((uint32_t)buffer[offset + 1] << 16) |
         ((uint32_t)buffer[offset + 2] << 8) | buffer[offset + 3];
}

class DNSQuestion {
public:
  std::list<std::string> qnames;
  uint16_t qtype;
  uint16_t qclass;
  uint16_t size = 0;

  DNSQuestion(const std::uint8_t* buffer, int offset) {
    int nameSize = setNames(buffer, offset, &qnames);
    qtype  = static_cast<DNSQType>(readShort(buffer, offset + nameSize));
    qclass = static_cast<DNSQClass>(readShort(buffer, offset + nameSize + 2));
    size = nameSize + 4;
  }

private:
  friend std::ostream& operator<<(std::ostream&, const DNSQuestion&);
};

std::ostream& operator<<(std::ostream &stream, const DNSQuestion &dnsq) {
  stream << "DNSQuestion(qnames: [";
  for(std::list<std::string>::const_iterator i = dnsq.qnames.begin(); i != dnsq.qnames.end(); ++i) {
    stream << i->c_str() << ", ";
  }
  return stream << "], qtype: " << dnsq.qtype << " qclass: " << dnsq.qclass <<
    " size: " << dnsq.size << ")";
}

class DNSResourceRecord {
  public:
    std::list<std::string> names;
    //TODO: Should have some DNSType, which only includes subset of QType
    uint16_t type;
    uint16_t clazz;
    uint32_t  ttl;
    uint16_t  rdlength;

    uint16_t size = 0;

    DNSResourceRecord(const uint8_t* buffer, int offset) {
      int nameSize = setNames(buffer, offset, &names);
      type = static_cast<DNSQType>(readShort(buffer, offset + nameSize));
      clazz = static_cast<DNSQClass>(readShort(buffer, offset + nameSize + 2));
      ttl = readInt(buffer, offset + nameSize + 4);
      rdlength = readShort(buffer, offset + nameSize + 8);
      size = nameSize + 10 + rdlength;
    }

  private:
    friend std::ostream& operator<<(std::ostream&, const DNSResourceRecord&);
};

std::ostream& operator<<(std::ostream &stream, const DNSResourceRecord &dnsrr) {
  stream << "DNSResourceRecord(names: [";
  for(std::list<std::string>::const_iterator i = dnsrr.names.begin(); i != dnsrr.names.end(); ++i) {
    stream << i->c_str() << ", ";
  }
  return stream << "], type: " << dnsrr.type << ", class: " << dnsrr.clazz <<
  ", ttl: " << dnsrr.ttl << ", rdlength: " << dnsrr.rdlength << ", size: " << dnsrr.size << ")";
}

class DNSPacket {
public:
  DNSHeader *header;
  std::list<DNSQuestion> questions;
  std::list<DNSResourceRecord> answers;

  DNSPacket(const std::uint8_t* buffer) {
    header = new DNSHeader(buffer);
    std::cout << *header << std::endl;
    int offset = DNSHeader::SIZE;
    for (int i = 0; i < header->qdcount; i++) {
      DNSQuestion dnsq(buffer, offset);
      questions.push_back(dnsq);
      std::cout << dnsq << std::endl;
      offset += dnsq.size;
    }
    for (int i = 0; i < header->ancount; i++) {
      DNSResourceRecord dnsrr(buffer, offset);
      answers.push_back(dnsrr);
      std::cout << dnsrr << std::endl;
      offset += dnsrr.size;
    }
  }

  ~DNSPacket() {
    delete header;
  }
};

int main(int argc, char **argv) {
  try {
    Poco::Net::SocketAddress sa("0.0.0.0", 53);
    Poco::Net::DatagramSocket dgs;

    dgs.bind(sa);

    std::uint8_t buffer[2048];

    Poco::Net::SocketAddress nsSA("8.8.8.8", 53);
    Poco::Net::DatagramSocket nsDGS;
    nsDGS.connect(nsSA);

    for (;;) {
      Poco::Net::SocketAddress sender;
      int bytesReceived = dgs.receiveFrom(buffer, sizeof(buffer), sender);
      DNSPacket dnsp(buffer);

      //TODO: check cache for answers
      nsDGS.sendBytes(buffer, bytesReceived);
      bytesReceived = nsDGS.receiveBytes(buffer, sizeof(buffer));
      DNSPacket dnsrp(buffer);
      //TODO: cache answers
      dgs.sendTo(buffer, bytesReceived, sender);
    }

    return 0;
  } catch (const Poco::Exception& e) {
    std::cerr << e.displayText() << std::endl;
    return -1;
  } catch(const std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
    return -1;
  }
}
