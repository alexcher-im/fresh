#pragma once

#include "types.h"
#include "mesh_protocol.h"
#include "mesh_base_interface_session.h"


/*struct MeshInterfaceProps
{
    ushort mtu;
    bool requires_encryption;
};


struct PeerSecureSessionEstablishmentInfo;
union PeerInterfaceInfo;


class BaseInterfaceSessionManager
{
public:
    virtual PeerInterfaceInfo* get_or_create_session(void* phy_addr) = 0;

    virtual PeerInterfaceInfo* get_or_none_session(void* phy_addr) = 0;

    virtual void remove_session(void* phy_addr) = 0;

    virtual PeerSecureSessionEstablishmentInfo* get_or_create_est_session(void* phy_addr) = 0;

    virtual PeerSecureSessionEstablishmentInfo* get_or_none_est_session(void* phy_addr) = 0;

    virtual void remove_est_session(void* phy_addr) = 0;
};


class BaseMeshInterface
{
public:
    virtual void check_packets() = 0;

    virtual void send_packet(MeshProto::far_addr_t far_addr, MeshProto::MeshPacket* packet, uint size) = 0;

    virtual void on_near_packet(MeshProto::MeshPacket* packet, uint size) = 0;

    virtual void send_phy() = 0;

    virtual MeshInterfaceProps get_properties() = 0;
};*/


struct MeshInterfaceProps
{
    MeshInterfaceSessionManager* sessions;
    uint far_mtu;
    ubyte address_size; // in bytes
    bool need_secure;
};


// todo documentation on creating your own interfaces
class MeshController;
class MeshInterface
{
public:
    uint id;
    MeshController* controller;

    virtual void check_packets() = 0;

    virtual bool accept_near_packet(MeshPhyAddrPtr phy_addr, const MeshProto::MeshPacket* packet, uint size) = 0;

    virtual MeshProto::MeshPacket* alloc_near_packet(MeshProto::MeshPacketType type, uint size) = 0;

    virtual MeshProto::MeshPacket* realloc_near_packet(MeshProto::MeshPacket* packet,
                                                       MeshProto::MeshPacketType old_type,
                                                       MeshProto::MeshPacketType new_type,
                                                       uint new_size) = 0;

    virtual void free_near_packet(MeshProto::MeshPacket* packet) = 0;

    virtual void send_packet(MeshPhyAddrPtr phy_addr, const MeshProto::MeshPacket* packet, uint size) = 0;

    virtual void send_hello(MeshPhyAddrPtr phy_addr) = 0; // if phy_addr==NULL - send broadcast

    virtual void write_addr_bytes(MeshPhyAddrPtr phy_addr, void* out_buf) = 0;

    virtual MeshInterfaceProps get_props() = 0;

    virtual ~MeshInterface() = default;
};
