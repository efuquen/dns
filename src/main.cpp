#include "Poco/Net/DatagramSocket.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Exception.h"

#include "types.h"

#include <iostream>
#include <stdexcept>
#include <cstdint>

int main(int argc, char **argv) {
  try {
    Poco::Net::SocketAddress sa("0.0.0.0", 53);
    Poco::Net::DatagramSocket dgs;

    dgs.bind(sa);

    uint8_t buffer[2048];

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
