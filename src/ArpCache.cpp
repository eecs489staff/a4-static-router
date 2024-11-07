#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<RoutingTable> routingTable)
    : packetSender(std::move(packetSender))
      , routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ArpCache::tick() {
    // TODO: Your code here


    // TODO: Your code should end here

    // Remove entries that have been in the cache for too long
    for (auto it = entries.begin(); it != entries.end();) {
        if (std::chrono::steady_clock::now() - it->second.timeAdded >= std::chrono::seconds(15)) {
            it = entries.erase(it);
        }
        else {
            ++it;
        }
    }
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // TODO: Your code below

}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    // TODO: Your code below

    return std::nullopt; // Placeholder
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    // TODO: Your code below

}