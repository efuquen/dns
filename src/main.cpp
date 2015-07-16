#include "Poco/Net/DatagramSocket.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Exception.h"

#include "types.h"
#include "cache.h"

#include <iostream>
#include <stdexcept>
#include <cstdint>
#include <map>

int main(int argc, char **argv) {
  try {
    Poco::Net::SocketAddress sa("0.0.0.0", 53);
    Poco::Net::DatagramSocket dgs;

    dgs.bind(sa);

    uint8_t buffer[2048];

    Poco::Net::SocketAddress nsSA("8.8.8.8", 53);
    Poco::Net::DatagramSocket nsDGS;
    nsDGS.connect(nsSA);

    DNSCache cache;

    for (;;) {
      Poco::Net::SocketAddress sender;
      int bytesReceived = dgs.receiveFrom(buffer, sizeof(buffer), sender);
      DNSPacket dnsp(buffer);
      std::cout << "Question Packet: " << dnsp << std::endl;

      DNSPacket* dnsrp = cache.get(&dnsp);
      if(dnsrp == NULL){
        nsDGS.sendBytes(buffer, bytesReceived);
        bytesReceived = nsDGS.receiveBytes(buffer, sizeof(buffer));
        dnsrp = new DNSPacket(buffer);
        cache.put(dnsrp);
        std::cout << "Got From Server: " << dnsrp->header << std::endl;
      } else {
        dnsrp->header.id = dnsp.header.id;
        std::cout << "Got From Cache: " << dnsrp->header << std::endl;
      }

      dgs.sendTo(dnsrp->toBytes(), dnsrp->size, sender);
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
