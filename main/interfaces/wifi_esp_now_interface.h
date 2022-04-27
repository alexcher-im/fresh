#pragma once


#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <esp_wifi_types.h>
#include <cstring>
#include <unordered_map>
#include "../mesh_base_interface.h"
#include "../mesh_controller.h"


namespace NsWifiEspNowInterface
{
    struct MacAddr {
        ubyte raw[6];

        MacAddr(const ubyte (&mac_)[6]) {memcpy(raw, mac_, 6);}
        MacAddr() {memset(raw, 0, 6);}
    } __attribute__((packed));

    inline bool operator==(const MacAddr& src, const MacAddr& dst) {
        return !memcmp(src.raw, dst.raw, 6);
    }

    inline bool operator!=(const MacAddr& src, const MacAddr& dst) {
        return !(src == dst);
    }

    using SessionManager = SimpleSecureMeshInterfaceSessionManager<MacAddr>;

    class EspNowPeerManager
    {
    public:
        bool add_peer(const ubyte* mac, ubyte channel);

        bool remove_peer(const ubyte* mac);
    };
}

namespace std {
    template<>
    struct hash<NsWifiEspNowInterface::MacAddr> {
        inline std::size_t operator()(const NsWifiEspNowInterface::MacAddr& mac) const {
            return (*(uint*)mac.raw) ^ (*(uint*)(&mac.raw[2]));
        }
    };
}


class WifiEspNowMeshInterface : public MeshInterface
{
public:
    static const int MAX_QUEUED_RX_PACKETS = 8;
    static const int FAR_MTU = 250;

    NsWifiEspNowInterface::EspNowPeerManager peer_manager;
    NsWifiEspNowInterface::SessionManager session_manager;
    xQueueHandle rx_queue{};
    NsWifiEspNowInterface::MacAddr self_addr;

    WifiEspNowMeshInterface();

    void check_packets() override;

    bool accept_near_packet(MeshPhyAddrPtr phy_addr, const MeshProto::MeshPacket* packet, uint size) override;

    MeshProto::MeshPacket* alloc_near_packet(MeshProto::MeshPacketType type, uint size) override;

    MeshProto::MeshPacket* realloc_near_packet(MeshProto::MeshPacket* packet,
                                               MeshProto::MeshPacketType old_type,
                                               MeshProto::MeshPacketType new_type,
                                               uint new_size) override;

    void free_near_packet(MeshProto::MeshPacket* packet) override;

    void send_packet(MeshPhyAddrPtr phy_addr, const MeshProto::MeshPacket* packet, uint size) override;

    MeshInterfaceProps get_props() override;

    void send_hello(MeshPhyAddrPtr phy_addr) override;

    void write_addr_bytes(MeshPhyAddrPtr phy_addr, void* out_buf) override;

    ~WifiEspNowMeshInterface() override;

    MeshProto::far_addr_t derive_far_addr_uint32();
};
