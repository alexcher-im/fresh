#pragma once

#include <unordered_map>
#include "mesh_protocol.h"


enum class PeerSecureSessionEstablishmentStage
{
    UNKNOWN = 0,
    WAITING_FOR_HELLO_INIT,
    WAITING_FOR_HELLO_AUTH,
    WAITING_FOR_HELLO_JOINED
};


// interface will provide this structure to controller
struct PeerInterfaceInfoSecure
{
    MeshProto::far_addr_t peer_far_addr;
    MeshProto::timestamp_t prev_peer_timestamp;
    MeshProto::session_key_t session_key;
};


struct PeerInterfaceInfoInsecure
{
    MeshProto::far_addr_t peer_far_addr;
};


union PeerSessionInfo
{
    PeerInterfaceInfoSecure secure;
    PeerInterfaceInfoInsecure insecure;
};


struct PeerSecureSessionEstablishmentInfo
{
    MeshProto::nonce_t peer_nonce;
    u64 time_start;
    PeerInterfaceInfoSecure session_info;
    PeerSecureSessionEstablishmentStage stage = PeerSecureSessionEstablishmentStage::UNKNOWN;

    static const u64 SESSION_MAX_LIVE_TIME = 2000000;
};


typedef struct MeshPhyAddr_s* MeshPhyAddrPtr;


class MeshInterfaceSessionManager
{
public:
    virtual PeerSessionInfo* get_or_create_session(MeshPhyAddrPtr phy_addr) = 0;

    virtual PeerSessionInfo* get_or_none_session(MeshPhyAddrPtr phy_addr) = 0;

    virtual void remove_session(MeshPhyAddrPtr phy_addr) = 0;

    virtual PeerSecureSessionEstablishmentInfo* get_or_create_est_session(MeshPhyAddrPtr phy_addr) = 0;

    virtual PeerSecureSessionEstablishmentInfo* get_or_none_est_session(MeshPhyAddrPtr phy_addr) = 0;

    virtual void remove_est_session(MeshPhyAddrPtr phy_addr) = 0;

    virtual void register_far_addr(MeshProto::far_addr_t far_addr, MeshPhyAddrPtr phy_addr) = 0;

    virtual void unregister_far_addr(MeshProto::far_addr_t far_addr) = 0;

    virtual MeshPhyAddrPtr get_phy_addr(MeshProto::far_addr_t far_addr) = 0;
};


template <typename TPhyAddr>
class SimpleSecureMeshInterfaceSessionManager : public MeshInterfaceSessionManager
{
public:
    std::unordered_map<TPhyAddr, PeerSecureSessionEstablishmentInfo> est_sessions;
    std::unordered_map<TPhyAddr, PeerSessionInfo> sessions;
    std::unordered_map<MeshProto::far_addr_t, TPhyAddr> far_to_phy_map;

    PeerSessionInfo* get_or_create_session(MeshPhyAddrPtr phy_addr) override {
        return &sessions[*(TPhyAddr*)phy_addr];
    }

    PeerSessionInfo* get_or_none_session(MeshPhyAddrPtr phy_addr) override {
        auto iter = sessions.find(*(TPhyAddr*)phy_addr);
        return iter == sessions.end() ? nullptr : &iter->second;
    };

    void remove_session(MeshPhyAddrPtr phy_addr) override {
        sessions.erase(*(TPhyAddr*)phy_addr);
    }

    PeerSecureSessionEstablishmentInfo* get_or_create_est_session(MeshPhyAddrPtr phy_addr) override {
        return &est_sessions[*(TPhyAddr*)phy_addr];
    }

    PeerSecureSessionEstablishmentInfo* get_or_none_est_session(MeshPhyAddrPtr phy_addr) override {
        auto iter = est_sessions.find(*(TPhyAddr*)phy_addr);
        return iter == est_sessions.end() ? nullptr : &iter->second;
    }

    void remove_est_session(MeshPhyAddrPtr phy_addr) override {
        est_sessions.erase(*(TPhyAddr*)phy_addr);
    }

    void register_far_addr(MeshProto::far_addr_t far_addr, MeshPhyAddrPtr phy_addr) override {
        far_to_phy_map[far_addr] = *(TPhyAddr*)phy_addr;
    }

    void unregister_far_addr(MeshProto::far_addr_t far_addr) override {
        far_to_phy_map.erase(far_addr);
    }

    MeshPhyAddrPtr get_phy_addr(MeshProto::far_addr_t far_addr) override {
        auto iter = far_to_phy_map.find(far_addr);
        return iter == far_to_phy_map.end() ? nullptr : (MeshPhyAddrPtr) &iter->second;
    }
};
