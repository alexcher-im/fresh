#pragma once

#include <list>
#include <vector>
#include "types.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <bitset>
#include "mesh_protocol.h"
#include "mesh_base_interface.h"
#include "utils.h"


/*struct InterfaceDescription
{
    BaseMeshInterface* interface;
    BaseInterfaceSessionManager* sessions;
    bool is_secured; // whether to use packet security or not
    bool is_low_mtu; // means to use DATA_PART16 instead of DATA_PART8
};


class MeshController
{
public:
    std::list<BaseMeshInterface*> interfaces;
    ubyte network_name[16];
    InterfaceDescription interfaces_arr[4];
    MeshProto::far_addr_t self_addr;
    uint packets_sent = 0;

    MeshController();

    //void add_near_peer(MeshProto::far_addr_t far_addr, void* interface);

    //int on_near_packet(MeshProto::MeshPacket* packet, uint size);

    int on_far_packet(size_t interface, PeerInterfaceInfo* peer, MeshProto::MeshPacket* packet, uint size);

    int on_secure_session_est_packet(size_t interface, void* phy_addr, MeshProto::MeshPacket* packet, uint size);

    int on_insecure_session_est_packet(size_t interface, MeshProto::MeshPacket* packet, uint size);

    static void task_check_pending_packets(void* param);

    inline bool netname_cmp(const ubyte* name) const {
        for (uint i = 0; i < 16; ++i) {
            if (network_name[i] != name[i])
                return false;
            if (name[i] == '\0')
                return true;
        }
        return true;
    }
};*/


class MeshController;

namespace NsMeshController
{
    struct InterfaceInternalParams
    {
        MeshInterface* interface;
        MeshInterfaceSessionManager* sessions;
        uint mtu;
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

    struct CachedDataStreamPart
    {
        uint size;
        uint offset;
        ubyte* data{};
        CachedDataStreamPart* next{}; // yes, a duplicate `next`
    };

    struct CachedTxDataStream
    {
        CachedDataStreamPart part;
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
            CachedTxDataStream data_stream;
        };
        CachedTxDataInfo* next{}; // ptr to next data stream or standalone packet. multiple parts of a single
                                  //  data stream are referred by CachedDataStreamPart::next
    };

    class PacketCache
    {
    public:
        std::unordered_map<MeshProto::far_addr_t, CachedTxDataInfo> tx_cache;

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

        void send_packet(MeshProto::MeshPacket* packet, uint size);

        void discover_route(MeshProto::far_addr_t dst);

        void add_peer(MeshProto::far_addr_t peer, MeshInterface* interface);

        // sends data only if it will take the full packet or if force_send == true
        // it will alloc memory on its own, but that's not a problem because of super-fast pool-allocators
        // stream_size specifies overall stream size if this will be a beginning of the stream (offset == 0), otherwise ignored
        uint write_data_stream_bytes(MeshProto::far_addr_t dst, uint offset, const ubyte* data, uint size,
                                     bool force_send, ubyte stream_id, uint stream_size);

        uint write_data_stream_bytes(MeshProto::far_addr_t dst, uint offset, const ubyte* data, uint size,
                                     bool force_send, ubyte stream_id, uint stream_size, Route& route, Peer& peer);
    };

    struct DataStreamIdentity
    {
        MeshProto::far_addr_t src_addr;
        MeshProto::far_addr_t dst_addr;
        decltype(MeshProto::PacketFarDataFirst::stream_id) stream_id;

    private:
        [[maybe_unused]] ubyte _useless[0]; // to make this struct a non-standard layout and allow compiler to re-order fields
    };

    inline bool operator==(const DataStreamIdentity& a, const DataStreamIdentity& b) {
        return a.src_addr == b.src_addr && a.dst_addr == b.dst_addr && a.stream_id == b.stream_id;
    }

    class DataStream
    {
    public:
        static const int RECV_PAIR_CNT = 8;
        static const u64 MAX_PACKET_WAIT = 3'000'000; // in microseconds
        static const u64 BROADCAST_KEEP_TIME = 5'000'000;

        ubyte* stream_data;
        uint stream_size;
        uint filled_bytes{};
        ushort recv_parts[RECV_PAIR_CNT][2]{};
        u64 last_modif_timestamp;

        DataStream(uint size, u64 creation_time) : stream_data((ubyte*) malloc(size)), stream_size(size),
                                                   last_modif_timestamp(creation_time) {}

        void add_data(ushort offset, const ubyte* data, ushort size);

        bool is_completed() const {
            return stream_size == filled_bytes;
        }

        bool is_exhausted(u64 timestamp) const {
            return timestamp > last_modif_timestamp + MAX_PACKET_WAIT;
        }

        ~DataStream() {
            free(stream_data);
        }

    private:
        bool remake_parts(ushort start, ushort end);
    };
}


namespace std {
    template<>
    struct hash<NsMeshController::DataStreamIdentity> {
        inline std::size_t operator()(const NsMeshController::DataStreamIdentity& a) const {
            return a.src_addr ^ a.dst_addr ^ a.stream_id;
        }
    };
}


class MeshController
{
public:
    static const int CHECK_PACKETS_TASK_STACK_SIZE = 4096;
    static const int CHECK_PACKETS_TASK_PRIORITY = -7;
    static const BaseType_t CHECK_PACKETS_TASK_AFFINITY = tskNO_AFFINITY;
    static const int HANDLE_PACKET_TASK_STACK_SIZE = 8192;
    static const int HANDLE_PACKET_TASK_PRIORITY = -5;
    static const BaseType_t HANDLE_PACKET_TASK_AFFINITY = tskNO_AFFINITY;
    static const int DEFAULT_TTL = 5;

    ubyte network_name[16];
    ubyte pre_shared_key[16];
    std::vector<NsMeshController::InterfaceInternalParams> interfaces;
    NsMeshController::Router router{*this};
    MeshProto::far_addr_t self_addr;
    xTaskHandle check_packets_task_handle;
    std::unordered_map<NsMeshController::DataStreamIdentity, NsMeshController::DataStream> data_streams; // this should be in Router
    // todo add timestamp for data_parts (RX cache)
    std::unordered_map<NsMeshController::DataStreamIdentity, NsMeshController::CachedDataStreamPart> data_parts_cache; // this should be in PacketCache
    CircularQueue<decltype(MeshProto::MeshPacket::broadcast_id), 8> last_broadcast_ids;

    void (*user_stream_handler)(MeshProto::far_addr_t, const ubyte*, ushort, void*);
    void* user_stream_handler_userdata = nullptr;

    MeshController(const char* netname, MeshProto::far_addr_t self_addr_);

    void on_packet(uint interface_id, MeshPhyAddrPtr phy_addr, MeshProto::MeshPacket* packet, uint size);

    [[noreturn]] static void task_check_packets(void* userdata);

    void add_interface(MeshInterface* interface);

    void remove_interface(MeshInterface* interface);

    void set_psk_password(const char* password);

    inline bool netname_cmp(const ubyte* name) const {
        for (uint i = 0; i < 16; ++i) {
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

    void default_stream_handler(MeshProto::far_addr_t src_addr, const ubyte* data, ushort size, void* userdata) {
        printf("Received a data stream!\n");
    }
};
