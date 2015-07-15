#include "types.h"

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

DNSHeader::DNSHeader(const uint8_t* header) {
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

std::ostream& operator<<(std::ostream &strm, const DNSHeader &dnsh) {
    return strm << "DNSHeader(id: " << dnsh.id << " qr: " << dnsh.qr <<
      " opcode: " << unsigned(dnsh.opcode) << " aa: " << dnsh.aa << " tc: " <<
      dnsh.tc << " rd: " << dnsh.rd << " ra: " << dnsh.ra << " rcode: " <<
      unsigned(dnsh.rcode) << " qdcount: " << dnsh.qdcount << " ancount: " <<
      dnsh.ancount << " nscount: " << dnsh.nscount << " arcount: " <<
      dnsh.arcount << ")";
}

DNSQuestion::DNSQuestion(const std::uint8_t* buffer, int offset) {
    int nameSize = setNames(buffer, offset, &qnames);
    qtype  = static_cast<DNSQType>(readShort(buffer, offset + nameSize));
    qclass = static_cast<DNSQClass>(readShort(buffer, offset + nameSize + 2));
    size = nameSize + 4;
}

std::ostream& operator<<(std::ostream &stream, const DNSQuestion &dnsq) {
  stream << "DNSQuestion(qnames: [";
  for(std::list<std::string>::const_iterator i = dnsq.qnames.begin(); i != dnsq.qnames.end(); ++i) {
    stream << i->c_str() << ", ";
  }
  return stream << "], qtype: " << dnsq.qtype << " qclass: " << dnsq.qclass <<
    " size: " << dnsq.size << ")";
}

DNSResourceRecord::DNSResourceRecord(const uint8_t* buffer, int offset) {
	  int nameSize = setNames(buffer, offset, &names);
	  type = static_cast<DNSQType>(readShort(buffer, offset + nameSize));
	  clazz = static_cast<DNSQClass>(readShort(buffer, offset + nameSize + 2));
	  ttl = readInt(buffer, offset + nameSize + 4);
	  rdlength = readShort(buffer, offset + nameSize + 8);
	  size = nameSize + 10 + rdlength;
}

std::ostream& operator<<(std::ostream &stream, const DNSResourceRecord &dnsrr) {
  stream << "DNSResourceRecord(names: [";
  for(std::list<std::string>::const_iterator i = dnsrr.names.begin(); i != dnsrr.names.end(); ++i) {
    stream << i->c_str() << ", ";
  }
  return stream << "], type: " << dnsrr.type << ", class: " << dnsrr.clazz <<
  ", ttl: " << dnsrr.ttl << ", rdlength: " << dnsrr.rdlength << ", size: " << dnsrr.size << ")";
}

DNSPacket::DNSPacket(const std::uint8_t* buffer) {
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

DNSPacket::~DNSPacket() {
	  delete header;
}
