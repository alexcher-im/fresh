#pragma once

#include "types.h"
#include "mesh_protocol.h"
#include "mesh_base_interface.h"
#include "platform/api.h"

#include <list>
#include <vector>
#include <functional>


class PacketLog;


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
        friend class ::MeshController;
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

    protected:
        void add_rx_data_packet_to_cache(DataStreamIdentity identity, uint offset, ubyte* data, uint size,
                                         ubyte broadcast_ttl = 0);
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
    std::array<ubyte, 16> network_name{};
    std::array<ubyte, 16> pre_shared_key{};
    std::vector<NsMeshController::InterfaceInternalParams> interfaces;
    NsMeshController::Router router{*this};
    MeshProto::far_addr_t self_addr;
    Os::TaskHandle check_packets_task_handle;
    std::unordered_map<NsMeshController::DataStreamIdentity, NsMeshController::DataStream> data_streams; // this should be in Router

    struct Callbacks {
        // todo pass ownership of packet memory to this handler
        std::function<void(MeshProto::far_addr_t, const ubyte*, ushort)> on_data_packet = default_data_handler;
        std::function<void(const char*)> packet_tracing_log = default_packet_tracing_log_handler;
        std::function<void(MeshProto::far_addr_t)> new_peer = default_new_peer_handler;
    } callbacks;

    // todo these two one are deprecated, use callbacks.on_data_packet and callbacks.new_peer
    std::function<void(MeshProto::far_addr_t, const ubyte*, ushort)> user_stream_handler = default_data_handler;
    std::function<void(MeshProto::far_addr_t)> new_peer_callback = default_new_peer_handler;

    MeshController(const char* netname, MeshProto::far_addr_t self_addr_, bool run_thread_poll_task = true);

    void run_thread_poll_task();

    void on_packet(uint interface_id, MeshPhyAddrPtr phy_addr, MeshProto::MeshPacket* packet, uint size);

    [[noreturn]] static void task_check_packets(void* userdata);

    void add_interface(MeshInterface* interface);

    void remove_interface(MeshInterface* interface);

    void set_psk_password(const char* password);

    inline bool netname_cmp(const u8le* name) const {
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
    friend class NsMeshController::Router;

    void check_data_streams();

    static void default_packet_tracing_log_handler(const char* string) {
        printf("tracing: %s\n", string);
    }

    static void default_data_handler(MeshProto::far_addr_t src_addr, const ubyte* data, ushort size) {
        printf("Received a data stream!\n");
    }

    static void default_new_peer_handler(MeshProto::far_addr_t peer_addr) {
        printf("New peer! %u\n", (uint) peer_addr);
    }

    void handle_near_secure(uint interface_id, MeshPhyAddrPtr phy_addr, MeshProto::MeshPacket* packet, uint size,
                            PacketLog& packet_log);

    void handle_near_insecure(uint interface_id, MeshPhyAddrPtr phy_addr, MeshProto::MeshPacket* packet, uint size,
                              PacketLog& packet_log);

    bool handle_data_first_packet(MeshProto::PacketFarDataFirst* packet, uint payload_size,
                                  MeshProto::far_addr_t src, MeshProto::far_addr_t dst, PacketLog& packet_log);

    bool handle_data_part_packet(MeshProto::PacketFarDataPart8* packet, uint payload_size,
                                 MeshProto::far_addr_t src, MeshProto::far_addr_t dst, PacketLog& packet_log);

    void retransmit_packet_first_broadcast(MeshProto::MeshPacket* packet, uint packet_size, uint allocated_packet_size,
                                           MeshProto::far_addr_t src_addr, uint payload_size, PacketLog& packet_log);

    void retransmit_packet_part_broadcast(MeshProto::MeshPacket* packet, uint packet_size, uint allocated_packet_size,
                                          MeshProto::far_addr_t src_addr, uint payload_size, PacketLog& packet_log);

    bool check_stream_completeness(const NsMeshController::DataStreamIdentity& identity,
                                   NsMeshController::DataStream& stream);

    void compete_data_stream(ubyte* data, uint size, MeshProto::far_addr_t src_addr, MeshProto::far_addr_t dst_addr);

    MeshProto::hashdigest_t calc_packet_signature(const PeerSessionInfo* session,
                                                  MeshProto::MeshPacket* packet, uint size, u64 timestamp) const;

    void generate_packet_signature(const PeerSessionInfo* session, MeshProto::MeshPacket* packet, uint size) const;
};
