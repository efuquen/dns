#include "types.h"
#include "cache.h"

#include <ctime>

bool hasExpired(DNSPacket* packet, int seconds) {
  std::list <DNSResourceRecord>::iterator answer;
  for(answer = packet->answers.begin(); answer != packet->answers.end(); ++answer) {
    if (seconds > answer->ttl) {
      return true;
    } else {
      //Update ttl so client pings cache server at correct time.
      answer->ttl -= seconds;
    }
  }
  return false;
}

DNSPacket* DNSCache::get(DNSPacket* packet) {
  time_t now = time(nullptr);
  std::string key = packet->cacheKey();
  if(cache.count(key) > 0) {
    DNSPacket* cachedPacket = cache[key];
    time_t cachedTime = cacheTimes[key];
    double seconds = difftime(now, cachedTime);
    if(hasExpired(cachedPacket, seconds)) {
      cache.erase(key);
      delete cachedPacket;
      return NULL;
    } else {
      //We updated ttls on cached packets, time needs to be now as a result.
      cacheTimes[key] = now;
      return cachedPacket;
    }
  } else {
    return NULL;
  }
}

void DNSCache::put(DNSPacket* packet) {
  //Will never expire unless we have answers with ttl
  if (packet->answers.size() > 0) {
    std::string key = packet->cacheKey();
    cache[key] = packet;
    cacheTimes[key] = time(nullptr);
  }
}
