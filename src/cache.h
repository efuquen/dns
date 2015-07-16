#pragma once

#include "types.h"

#include <map>
#include <ctime>

class DNSCache {
public:
  DNSPacket* get(DNSPacket*);
  void put(DNSPacket*);
private:
  std::map<std::string, DNSPacket*> cache;
  std::map<std::string, time_t> cacheTimes;
};
