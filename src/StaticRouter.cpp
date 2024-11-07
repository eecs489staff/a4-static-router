#include "StaticRouter.h"
#include "protocol.h"
#include "PacketSender.h"
#include "utils.h"
#include <spdlog/spdlog.h>
#include <cstring>

#include "utils.h"

StaticRouter::StaticRouter(std::shared_ptr<RoutingTable> routingTable, std::shared_ptr<IPacketSender> packetSender)
: routingTable(routingTable)
, packetSender(packetSender)
, arpCache(packetSender, routingTable)
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    // TODO: Your code below

}