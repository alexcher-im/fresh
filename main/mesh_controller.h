#pragma once

#include <list>
#include <vector>
#include "types.h"
#include <functional>
#include "mesh_protocol.h"
#include "mesh_base_interface.h"
#include "platform/api.h"


namespace NsMeshController
{
    struct DataStreamIdentity
    {
        MeshProto::far_addr_t src_addr;
        MeshProto::far_addr_t dst_addr;
        decltype(MeshProto::PacketFarDataFirst::stream_id) stream_id;

    private:
        ubyte _useless[0]; // to make this struct a non-standard layout and allow compiler to re-order fields
    };

    inline bool operator==(const DataStreamIdentity& a, const DataStreamIdentity& b) {
        return a.src_addr == b.src_addr && a.dst_addr == b.dst_addr && a.stream_id == b.stream_id;
    }
}


namespace std {
    template<>
    struct hash<NsMeshController::DataStreamIdentity> {
        inline std::size_t operator()(const NsMeshController::DataStreamIdentity& a) const {
            return a.src_addr ^ a.dst_addr ^ a.stream_id;
        }
    };
}


class MeshController;

namespace NsMeshController
{
    struct InterfaceInternalParams
    {
        MeshInterface* interface;
        MeshInterfaceSessionManager* sessions;
        uint mtu;
        ubyte address_size; // in bytes
        bool is_secured;
    };

    struct Peer
    {
        MeshInterface* interface{};
        Peer* next{};
    };

    struct Route
    {
        MeshProto::far_addr_t gateway_addr;
        ubyte distance; // how many transit routers are on the way
    };

    enum struct RouteState : ubyte
    {
        UNKNOWN = 0,
        INSPECTING,
        ESTABLISHED,
        INEXISTING
    };

    struct RouteInfo
    {
        static const int MAX_ROUTES = 2;
        static const u64 ROUTE_DISCOVERY_TIMEOUT = 10'000'000;

        RouteState state = RouteState::UNKNOWN;
        ubyte route_cnt{}; // amount of routes
        union {
            u64 time_started;          // for `INSPECTING/INEXISTING` state: timestamp when this state was set`
            Route routes[MAX_ROUTES];  // for `ESTABLISHED` state: best routes, sorted by their priority (first is best)
        };
    };

    struct CachedTxDataStreamPart
    {
        uint size;
        uint offset;
        ubyte* data{};
        CachedTxDataStreamPart* next{}; // yes, a duplicate `next`. used to store list of packets in a single stream
    };

    struct CachedTxDataStreamInfo
    {
        CachedTxDataStreamPart part;
        decltype(MeshProto::DataStream::first.stream_id) stream_id;
        uint stream_size;
    };

    struct CachedTxStandalonePacket
    {
        uint size;
        MeshProto::MeshPacket* data;

        CachedTxStandalonePacket(MeshProto::MeshPacket* data_, uint size_) : size(size_), data(data_) {}
        CachedTxStandalonePacket() = default;
    };

    struct CachedTxDataInfo
    {
        CachedTxDataInfo() {};

        enum class CachedDataType : ubyte {
            UNKNOWN = 0,
            DATA_STREAM,
            STANDALONE_PACKET
        } type{};
        union {
            CachedTxStandalonePacket standalone;
            CachedTxDataStreamInfo data_stream;
        };
        CachedTxDataInfo* next{}; // ptr to next data stream or standalone packet. multiple parts of a single
                                  //  data stream are referred by CachedDataStreamPart::next
    };

    struct CachedRxDataStreamPart
    {
        uint size;
        uint offset;
        ubyte* data;
        CachedRxDataStreamPart* next{};

        ubyte broadcast_ttl; // unused in unicast packets
    };

    struct CachedRxDataInfo
    {
        u64 last_modif_timestamp;
        CachedRxDataStreamPart part;

        bool is_expired(u64 new_time) const {
            return new_time > last_modif_timestamp + MAX_RX_CACHE_ENTRY_LIVE_TIME;
        }
    };

    class PacketCache
    {
    public:
        std::unordered_map<MeshProto::far_addr_t, CachedTxDataInfo> tx_cache;
        std::unordered_map<DataStreamIdentity, CachedRxDataInfo> rx_stream_cache;

        void add_tx_packet(MeshProto::far_addr_t dst_addr, CachedTxStandalonePacket&& packet);
    };

    class Router
    {
    public:
        MeshController& controller;

        std::unordered_map<MeshProto::far_addr_t, Peer> peers;
        std::unordered_map<MeshProto::far_addr_t, RouteInfo> routes;
        PacketCache packet_cache;

        explicit Router(MeshController& controller_) : controller(controller_) {}

        void add_route(MeshProto::far_addr_t dst, MeshProto::far_addr_t gateway, ubyte distance);

        void check_packet_cache();

        void check_packet_cache(MeshProto::far_addr_t dst);

        auto check_packet_cache(decltype(packet_cache.tx_cache)::iterator cache_iter, MeshProto::far_addr_t dst)
                -> decltype(packet_cache.tx_cache)::iterator;

        // available_size must always be >= size, UB instead
        // returns true if packet sent or cached successfully, false if its size exceeds peers MTU
        bool send_packet(MeshProto::MeshPacket* packet, uint size, uint available_size);

        void discover_route(MeshProto::far_addr_t dst);

        void add_peer(MeshProto::far_addr_t peer, MeshInterface* interface);

        // sends data only if it will take the full packet or if force_send == true
        // it will alloc memory on its own using super-fast pool-allocators
        // stream_size specifies overall stream size if this will be a beginning of the stream (offset == 0), otherwise ignored
        // broadcast_ttl specifies TTL for broadcast (dst == BROADCAST_FAR_ADDR), otherwise ignored
        uint write_data_stream_bytes(MeshProto::far_addr_t dst, uint offset, const ubyte* data, uint size,
                                     bool force_send, ubyte stream_id, uint stream_size, ubyte broadcast_ttl,
                                     MeshProto::far_addr_t broadcast_src_addr);

        uint write_data_stream_bytes(MeshProto::far_addr_t dst, uint offset, const ubyte* data, uint size,
                                     bool force_send, ubyte stream_id, uint stream_size, ubyte broadcast_ttl,
                                     MeshProto::far_addr_t broadcast_src_addr, Route& route, Peer& peer);
    };

    class DataStream
    {
    public:
        ubyte* stream_data;
        uint stream_size;
        ushort recv_parts[DATA_STREAM_RECV_PAIR_CNT][2]{};
        u64 last_modif_timestamp;

        DataStream(uint size, u64 creation_time) : stream_data(size ? (ubyte*) malloc(size) : nullptr), stream_size(size),
                                                   last_modif_timestamp(creation_time) {}

        bool add_data(ushort offset, const ubyte* data, ushort size);

        bool is_completed() const {
            return stream_data != nullptr && (recv_parts[0][0] == 0 && recv_parts[0][1] == stream_size);
        }

        bool is_expired(u64 timestamp, bool is_broadcast = false) const {
            return timestamp > last_modif_timestamp + (is_broadcast ? DATA_STREAM_BROADCAST_KEEP_TIME : DATA_STREAM_MAX_PACKET_WAIT);
        }

        ~DataStream() {
            free(stream_data);
        }

    private:
        bool remake_parts(ushort start, ushort end);
    };
}


class MeshController
{
public:
    ubyte network_name[16];
    ubyte pre_shared_key[16];
    std::vector<NsMeshController::InterfaceInternalParams> interfaces;
    NsMeshController::Router router{*this};
    MeshProto::far_addr_t self_addr;
    Os::TaskHandle check_packets_task_handle;
    std::unordered_map<NsMeshController::DataStreamIdentity, NsMeshController::DataStream> data_streams; // this should be in Router

    std::function<void(MeshProto::far_addr_t, const ubyte*, ushort)> user_stream_handler = default_stream_handler;

    MeshController(const char* netname, MeshProto::far_addr_t self_addr_);

    void on_packet(uint interface_id, MeshPhyAddrPtr phy_addr, MeshProto::MeshPacket* packet, uint size);

    [[noreturn]] static void task_check_packets(void* userdata);

    void add_interface(MeshInterface* interface);

    void remove_interface(MeshInterface* interface);

    void set_psk_password(const char* password);

    inline bool netname_cmp(const ubyte* name) const {
        for (int i = 0; i < 16; ++i) {
            if (network_name[i] != name[i])
                return false;
            if (name[i] == '\0')
                return true;
        }
        return true;
    }

    ~MeshController();

protected:
    void check_data_streams();

    static void default_stream_handler(MeshProto::far_addr_t src_addr, const ubyte* data, ushort size) {
        printf("Received a data stream!\n");
    }
};
