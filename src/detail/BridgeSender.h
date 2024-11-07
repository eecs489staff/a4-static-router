#ifndef BRIDGESENDER_H
#define BRIDGESENDER_H
#include <router_bridge.pb.h>

#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>

#include "PacketSender.h"
#include "PCAPDumper.h"

class BridgeSender : public IPacketSender {
    using RouterPacket = router_bridge::RouterPacket;
    using WSClient = websocketpp::client<websocketpp::config::asio_client>;
public:
    BridgeSender(std::shared_ptr<WSClient> client, WSClient::connection_ptr connection, std::string pcapPrefix = "sr_capture");

    void sendPacket(Packet packet, const std::string& iface) override;

private:
    void send(const router_bridge::ProtocolMessage& message) {
        client->send(connection, message.SerializeAsString(), websocketpp::frame::opcode::binary);
    }

    std::shared_ptr<WSClient> client;
    WSClient::connection_ptr connection;

    PcapDumper dumper;
};



#endif //BRIDGESENDER_H