#include "Poco/Net/DatagramSocket.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Exception.h"

#include <iostream>
#include <stdexcept>
#include <cstdint>
#include <list>

class DNSHeader {
public:
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

class DNSQuestion {
public:
  std::list<std::string> qnames;
  uint16_t qtype;
  uint16_t qclass;
  uint16_t size = 0;

  DNSQuestion(const std::uint8_t* buffer) {
    std::uint8_t qnameSize = buffer[0];
    int offset = 1;

    while (qnameSize > 0) {
      std::cout << " qnameSize: " << unsigned(qnameSize) << std::endl;
      char qnameLabel[qnameSize + 1];
      for (int i = 0; i < qnameSize; i++) {
        qnameLabel[i] = buffer[offset + i];
      }
      qnameLabel[qnameSize] = '\0';
      offset += (qnameSize + 1);
      std::cout << "qnameLabel: " << qnameLabel << std::endl;
      qnames.push_back(qnameLabel);
      qnameSize = buffer[offset - 1];
    }
    qtype  = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
    qclass = ((uint16_t)buffer[offset + 2] << 8) | buffer[offset + 3];
    size = offset + 4;
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

int main(int argc, char **argv) {
  try {
    Poco::Net::SocketAddress sa("127.0.0.1", 53);
    Poco::Net::DatagramSocket dgs;

    dgs.bind(sa);

    std::uint8_t buffer[2048];

    for (;;) {
      Poco::Net::SocketAddress sender;
      int n = dgs.receiveFrom(buffer, sizeof(buffer), sender);
      std::cout << "for buffer read: " << n << std::endl;
      DNSHeader dnsh(buffer);
      std::cout << dnsh << std::endl;
      DNSQuestion dnsq(&(buffer[12]));
      std::cout << dnsq << std::endl;
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
