#pragma once


#include "../mesh_base_interface.h"


namespace NsPcStdUartInterface
{
    // todo uart interface session manager
    class SessionManager : public MeshInterfaceSessionManager
    {
    public:
        //MeshController** controller_ptr;
        PeerInterfaceInfoInsecure insecure_session;

        PeerSessionInfo* get_or_create_session(MeshPhyAddrPtr phy_addr) override {
            return (PeerSessionInfo*) &insecure_session;
        }

        PeerSessionInfo* get_or_none_session(MeshPhyAddrPtr phy_addr) override {
            return (PeerSessionInfo*) &insecure_session;
        };

        void remove_session(MeshPhyAddrPtr phy_addr) override { }

        void register_far_addr(MeshProto::far_addr_t far_addr, MeshPhyAddrPtr phy_addr) override {
            //far_to_phy_map[far_addr] = *(TPhyAddr*)phy_addr;
        }

        void unregister_far_addr(MeshProto::far_addr_t far_addr) override { }

        MeshPhyAddrPtr get_phy_addr(MeshProto::far_addr_t far_addr) override {
            //auto iter = far_to_phy_map.find(far_addr);
            //return iter == far_to_phy_map.end() ? nullptr : (MeshPhyAddrPtr) &iter->second;
            return nullptr;
        }
    };
}


class PcStdUartInterface : public MeshInterface
{
public:
    NsPcStdUartInterface::SessionManager sessions;

    // todo pass uart settings such as buffers size, active/passive mode
    PcStdUartInterface();

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
};
