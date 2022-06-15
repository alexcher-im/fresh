#pragma once


#include "../mesh_base_interface.h"
#include "platform/p2p/base.h"


namespace NsP2PUnsecuredShortInterface
{
    class SessionManager : public MeshInterfaceSessionManager
    {
    public:
        PeerInterfaceInfoInsecure insecure_session;

        PeerSessionInfo* get_or_create_session(MeshPhyAddrPtr phy_addr) override {
            return (PeerSessionInfo*) &insecure_session;
        }

        PeerSessionInfo* get_or_none_session(MeshPhyAddrPtr phy_addr) override {
            return (PeerSessionInfo*) &insecure_session;
        };

        void remove_session(MeshPhyAddrPtr phy_addr) override { }

        void register_far_addr(MeshProto::far_addr_t far_addr, MeshPhyAddrPtr phy_addr) override { }

        void unregister_far_addr(MeshProto::far_addr_t far_addr) override { }

        MeshPhyAddrPtr get_phy_addr(MeshProto::far_addr_t far_addr) override {
            return nullptr;
        }
    };

    struct CacheEntry
    {
        void* data;
        ubyte size;
        CacheEntry* next = nullptr;
    };

    class PacketCache
    {
    public:
        CacheEntry* first_entry = nullptr;
        CacheEntry* last_entry = nullptr;
        uint length;

        void add_entry(const void* data, ubyte size);
    };
}


// ESP32 has 128 bytes of UART RX buffer. so, sending more without making sure device finished reading may corrupt buffer
// this code can send 1 ack signal and data packet, while they both have to fit in the same 128 bytes
// packet consists of 1 byte header+size and some payload
// because of this, the maximum payload size is 126 bytes, and this is the MTU of this interface
class P2PUnsecuredShortInterface : public MeshInterface
{
public:
    static const uint FAR_MTU = 126;

    NsP2PUnsecuredShortInterface::SessionManager sessions;
    bool is_self_rx_buf_infinite;
    bool is_opponent_rx_buf_infinite;
    BaseSerial& read_stream;
    BaseSerial& write_stream;

    ubyte curr_buf[127];
    ubyte remain_read = 0;
    ubyte curr_read_amount = 0;
    bool ack_received = true; // like binary semaphore, but have no callback on someone waiting

    NsP2PUnsecuredShortInterface::PacketCache cache;

    // negative size to set unlimited buffers
    P2PUnsecuredShortInterface(bool is_self_rx_buf_infinite_, bool is_opponent_rx_buf_infinite_,
                               BaseSerial& read_stream_, BaseSerial& write_stream_);

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

    // internal function for immediately sending data over UART
    void send_packet_data(const void* data, ubyte size);

    // only used when !is_opponent_rx_buf_infinite
    void process_next_queue_element();

    void send_ack();
};
