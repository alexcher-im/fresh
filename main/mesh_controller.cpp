#include "mesh_controller.h"
#include "net_utils.h"
#include <new>


using namespace MeshProto;
using namespace NsMeshController;


#pragma pack(push, 1)
struct MessageHashConcatParams
{
    uint packet_size;
    timestamp_t timestamp;
    decltype(MeshController::pre_shared_key) psk;
    session_key_t session_key;
};
#pragma pack(pop)


static bool generate_packet_signature(const MeshController* controller, const PeerSessionInfo* session,
                                      MeshPacket* packet, uint size) {
    auto sign = (MessageSign*) ((ubyte*) packet + size);
    auto timestamp = Os::get_microseconds();

    MessageHashConcatParams hash_concat_params;
    net_store(hash_concat_params.packet_size, size);
    net_store(hash_concat_params.timestamp, timestamp);
    net_loadstore_nonscalar(hash_concat_params.psk, controller->pre_shared_key);
    net_loadstore_nonscalar(hash_concat_params.session_key, session->secure.session_key);

    ubyte correct_signature[32];
    auto hash_ctx = Os::create_sha256();
    Os::update_sha256(&hash_ctx, packet, size);
    Os::update_sha256(&hash_ctx, &hash_concat_params, sizeof(MessageHashConcatParams));
    Os::finish_sha256(&hash_ctx, correct_signature);

    if constexpr (sizeof(hashdigest_t) > sizeof(correct_signature))
        memset((ubyte*) &sign->hash + sizeof(correct_signature), 0, sizeof(correct_signature) - sizeof(hashdigest_t));

    net_memcpy(&sign->hash, correct_signature, std::min(sizeof(correct_signature), sizeof(hashdigest_t)));
    net_loadstore_nonscalar(sign->timestamp, timestamp);
    return true;
}


struct CompletedStreamInfo
{
    ubyte* data;
    uint size;
    far_addr_t src_addr;
    far_addr_t dst_addr;
    MeshController* controller;
    Os::TaskHandle curr_task;
};

static void task_handle_packet(void* userdata) {
    auto info = (CompletedStreamInfo*) userdata;
    info->controller->user_stream_handler(info->src_addr, info->data, info->size);

    free(info->data);
    Os::detach_task(info->curr_task);
    info->~CompletedStreamInfo();
    free(info);
    Os::end_self_task();
}


static inline void print_bytes(const ubyte* buf, uint size) {
    for (int i = 0; i < size; ++i) {
        printf("%02x", buf[i]);
        if (i != size - 1)
            printf(":");
    }
    printf("\n");
}


static void compete_data_stream(MeshController& controller, ubyte* data, uint size, far_addr_t src_addr, far_addr_t dst_addr) {
    auto compl_info = (CompletedStreamInfo*) malloc(sizeof(CompletedStreamInfo));
    new (compl_info) CompletedStreamInfo();
    compl_info->controller = &controller;
    compl_info->data = data;
    compl_info->size = size;
    compl_info->src_addr = src_addr;
    compl_info->dst_addr = dst_addr;
    Os::create_task(task_handle_packet, HANDLE_DATA_PACKET_NAME, HANDLE_PACKET_TASK_STACK_SIZE,
                    compl_info, HANDLE_PACKET_TASK_PRIORITY, &compl_info->curr_task, HANDLE_PACKET_TASK_AFFINITY);
}

static bool check_stream_completeness(MeshController& controller, const DataStreamIdentity& identity,
                                      NsMeshController::DataStream& stream) {
    if (!stream.is_completed())
        return false;

    auto stream_data = stream.stream_data;
    stream.stream_data = nullptr;
    // todo put a barrier (fence) here
    compete_data_stream(controller, stream_data, stream.stream_size, identity.src_addr, identity.dst_addr);

    // broadcasts are never deleted immediately. at this point, .is_completed() will return if stream handler
    // should be called, but stream itself will only expire (deleted in Router::check_packet_cache())
    if (identity.dst_addr != BROADCAST_FAR_ADDR)
        controller.data_streams.erase(identity);
    return true;
}

// todo add controller.router.routes() (router.add_route()) for new peers
static inline void handle_near_secure(MeshController& controller, uint interface_id, MeshPhyAddrPtr phy_addr,
                                      MeshPacket* packet, uint size) {
    auto& interface_descr = controller.interfaces[interface_id];
    auto interface = interface_descr.interface;
    auto packet_type = net_load(packet->type);

    if (packet_type == MeshPacketType::NEAR_HELLO) {
        if (!MESH_FIELD_ACCESSIBLE(near_hello_secure, size))
            return;
        if (!controller.netname_cmp(packet->near_hello_secure.network_name))
            return;

        // checks
        auto est_session = interface_descr.sessions->get_or_create_est_session(phy_addr);
        if (est_session->stage != PeerSecureSessionEstablishmentStage::UNKNOWN)
            return;

        if (!interface->accept_near_packet(phy_addr, packet, size)) {
            interface_descr.sessions->remove_est_session(phy_addr);
            return;
        }
        // setting est session
        est_session->stage = PeerSecureSessionEstablishmentStage::WAITING_FOR_HELLO_AUTH;
        est_session->time_start = Os::get_microseconds();
        Os::fill_random(&est_session->peer_nonce, sizeof(nonce_t));

        // generating response packet
        auto packet_size = MESH_CALC_SIZE(near_hello_init);
        auto init_packet = interface->alloc_near_packet(MeshPacketType::NEAR_HELLO_INIT, packet_size);
        net_loadstore_nonscalar(init_packet->near_hello_init.member_nonce, est_session->peer_nonce);

        interface->send_packet(phy_addr, init_packet, packet_size);
        interface->free_near_packet(init_packet);
        printf("time after hello handler: %llu\n", Os::get_microseconds());
    }

    else if (packet_type == MeshPacketType::NEAR_HELLO_INIT) {
        if (!MESH_FIELD_ACCESSIBLE(near_hello_init, size))
            return;

        // checks
        auto est_session = interface_descr.sessions->get_or_create_est_session(phy_addr);
        if (est_session->stage != PeerSecureSessionEstablishmentStage::UNKNOWN)
            return;

        if (!interface->accept_near_packet(phy_addr, packet, size)) {
            interface_descr.sessions->remove_est_session(phy_addr);
            return;
        }
        // setting est session
        est_session->stage = PeerSecureSessionEstablishmentStage::WAITING_FOR_HELLO_JOINED;
        Os::fill_random(&est_session->session_info.session_key, sizeof(session_key_t));

        // generating response packet
        auto packet_size = MESH_CALC_SIZE(near_hello_authorize);
        auto auth_packet = interface->alloc_near_packet(MeshPacketType::HEAR_HELLO_AUTHORIZE, packet_size);
        net_loadstore_nonscalar(auth_packet->near_hello_authorize.session_key, est_session->session_info.session_key);
        net_store(auth_packet->near_hello_authorize.self_far_addr, controller.self_addr);
        net_store(auth_packet->near_hello_authorize.initial_timestamp, Os::get_microseconds());

        // generating hash (packet sign)
        ubyte hash_digest[32];
        auto hash_src_size = offsetof(MeshPacket, near_hello_authorize.hash) + sizeof(controller.pre_shared_key);
        ubyte hash_src[hash_src_size];
        net_memcpy(hash_src, auth_packet, offsetof(MeshPacket, near_hello_authorize.hash));
        memcpy(&hash_src[offsetof(MeshPacket, near_hello_authorize.hash)], &controller.pre_shared_key, sizeof(controller.pre_shared_key));
        Os::sha256(hash_src, hash_src_size, hash_digest);

        net_memcpy(&auth_packet->near_hello_authorize.hash, hash_digest, sizeof(hashdigest_t));

        // send
        interface->send_packet(phy_addr, auth_packet, packet_size);
        interface->free_near_packet(auth_packet);
        printf("time after init handler: %llu\n", Os::get_microseconds());
    }

    else if (packet_type == MeshPacketType::HEAR_HELLO_AUTHORIZE) {
        if (!MESH_FIELD_ACCESSIBLE(near_hello_authorize, size))
            return;

        // checks
        auto est_session = interface_descr.sessions->get_or_none_est_session(phy_addr);
        if (est_session == nullptr || est_session->stage != PeerSecureSessionEstablishmentStage::WAITING_FOR_HELLO_AUTH)
            return;

        // generating verification hash
        ubyte hash_digest[32];
        auto hash_src_size = offsetof(MeshPacket, near_hello_authorize.hash) + sizeof(controller.pre_shared_key);
        ubyte hash_src[hash_src_size];
        net_memcpy(hash_src, packet, offsetof(MeshPacket, near_hello_authorize.hash));
        memcpy(&hash_src[offsetof(MeshPacket, near_hello_authorize.hash)], &controller.pre_shared_key, sizeof(controller.pre_shared_key));
        Os::sha256(hash_src, hash_src_size, hash_digest);

        if (!!net_memcmp(hash_digest, &packet->near_hello_authorize.hash, sizeof(hashdigest_t)))
            return;

        // checks
        if (!interface->accept_near_packet(phy_addr, packet, size))
            return;

        // setting session
        auto session = interface_descr.sessions->get_or_create_session(phy_addr);
        net_loadstore_nonscalar(session->secure.session_key, packet->near_hello_authorize.session_key);
        session->secure.peer_far_addr = net_load(packet->near_hello_authorize.self_far_addr);
        session->secure.prev_peer_timestamp = net_load(packet->near_hello_authorize.initial_timestamp);

        // generating response packet
        auto packet_size = MESH_CALC_SIZE(near_hello_joined_secure);
        auto joined_packet = interface->alloc_near_packet(MeshPacketType::NEAR_HELLO_JOINED, packet_size);
        net_store(joined_packet->near_hello_joined_secure.initial_timestamp, Os::get_microseconds());
        net_store(joined_packet->near_hello_joined_secure.self_far_addr, controller.self_addr);

        // generating hash (packet sign)
        auto hash_j_size = offsetof(MeshPacket, near_hello_joined_secure.hash) + sizeof(controller.pre_shared_key);
        ubyte hash_j[hash_j_size];
        net_memcpy(hash_j, joined_packet, offsetof(MeshPacket, near_hello_joined_secure.hash));
        memcpy(&hash_j[offsetof(MeshPacket, near_hello_joined_secure.hash)], &controller.pre_shared_key, sizeof(controller.pre_shared_key));
        Os::sha256(hash_j, hash_j_size, hash_digest);

        net_memcpy(&joined_packet->near_hello_joined_secure.hash, hash_digest, sizeof(hashdigest_t));

        // send
        interface->send_packet(phy_addr, joined_packet, packet_size);
        interface->free_near_packet(joined_packet);

        // registering peer and removing session establishment info
        interface_descr.sessions->remove_est_session(phy_addr);
        printf("time after auth handler: %llu\n", Os::get_microseconds());
        printf("peer session done: from auth (other addr: %d)\n", session->secure.peer_far_addr);

        interface_descr.sessions->register_far_addr(session->secure.peer_far_addr, phy_addr);
        controller.router.add_peer(session->secure.peer_far_addr, interface);
    }

    else if (packet_type == MeshPacketType::NEAR_HELLO_JOINED) {
        if (!MESH_FIELD_ACCESSIBLE(near_hello_joined_secure, size))
            return;

        // checks
        auto est_session = interface_descr.sessions->get_or_none_est_session(phy_addr);
        if (est_session == nullptr || est_session->stage != PeerSecureSessionEstablishmentStage::WAITING_FOR_HELLO_JOINED)
            return;

        // generating verification hash
        ubyte hash_digest[32];
        auto hash_j_size = offsetof(MeshPacket, near_hello_joined_secure.hash) + sizeof(controller.pre_shared_key);
        ubyte hash_src[hash_j_size];
        net_memcpy(hash_src, packet, offsetof(MeshPacket, near_hello_joined_secure.hash));
        memcpy(&hash_src[offsetof(MeshPacket, near_hello_joined_secure.hash)], &controller.pre_shared_key, sizeof(controller.pre_shared_key));
        Os::sha256(hash_src, hash_j_size, hash_digest);

        if (!!net_memcmp(hash_digest, &packet->near_hello_joined_secure.hash, sizeof(hashdigest_t)))
            return;

        // checks
        if (!interface->accept_near_packet(phy_addr, packet, size))
            return;

        // setting session
        auto session = interface_descr.sessions->get_or_create_session(phy_addr);
        net_loadstore_nonscalar(session->secure.session_key, est_session->session_info.session_key);
        session->secure.peer_far_addr = net_load(packet->near_hello_joined_secure.self_far_addr);
        session->secure.prev_peer_timestamp = net_load(packet->near_hello_joined_secure.initial_timestamp);

        interface_descr.sessions->remove_est_session(phy_addr);
        printf("time after joined handler: %llu\n", Os::get_microseconds());
        printf("peer session done: from joined (other addr: %d)\n", session->secure.peer_far_addr);

        interface_descr.sessions->register_far_addr(session->secure.peer_far_addr, phy_addr);
        controller.router.add_peer(session->secure.peer_far_addr, interface);
    }
}

static inline void handle_near_insecure(MeshController& controller, uint interface_id, MeshPhyAddrPtr phy_addr,
                                        MeshPacket* packet, uint size) {
    auto& interface_descr = controller.interfaces[interface_id];
    auto interface = interface_descr.interface;
    auto packet_type = net_load(packet->type);

    if (packet_type == MeshPacketType::NEAR_HELLO) {
        if (!MESH_FIELD_ACCESSIBLE(near_hello_insecure, size))
            return;
        if (!controller.netname_cmp(packet->near_hello_insecure.network_name))
            return;

        auto session = interface_descr.sessions->get_or_create_session(phy_addr);
        session->insecure.peer_far_addr = net_load(packet->near_hello_insecure.self_far_addr);

        if (!interface->accept_near_packet(phy_addr, packet, size)) {
            return;
        }

        auto packet_size = MESH_CALC_SIZE(near_hello_joined_insecure);
        auto joined_packet = interface->alloc_near_packet(MeshPacketType::NEAR_HELLO_JOINED, packet_size);
        net_store(joined_packet->near_hello_joined_insecure.self_far_addr, controller.self_addr);
        interface->send_packet(phy_addr, joined_packet, packet_size);
        interface->free_near_packet(joined_packet);

        controller.router.add_peer(session->insecure.peer_far_addr, interface);
        printf("got insecure near hello (opponent addr: %d)\n", session->insecure.peer_far_addr);
        fflush(stdout);
    }

    else if (packet_type == MeshPacketType::NEAR_HELLO_JOINED) {
        if (!MESH_FIELD_ACCESSIBLE(near_hello_joined_insecure, size))
            return;

        auto session = interface_descr.sessions->get_or_create_session(phy_addr);
        session->insecure.peer_far_addr = net_load(packet->near_hello_joined_insecure.self_far_addr);
        controller.router.add_peer(session->insecure.peer_far_addr, interface);

        printf("got insecure near joined (opponent addr: %d)\n", session->insecure.peer_far_addr);
        fflush(stdout);
    }
}

static inline void add_rx_data_packet_to_cache(MeshController& controller, DataStreamIdentity identity,
                                               uint offset, ubyte* data, uint size, ubyte broadcast_ttl = 0) {
    auto& cached_stream = controller.router.packet_cache.rx_stream_cache[identity];
    auto& entry = cached_stream.part;
    cached_stream.last_modif_timestamp = Os::get_microseconds();

    if (entry.data) {
        auto new_entry = (CachedRxDataStreamPart*) malloc(sizeof(CachedRxDataStreamPart));
        *new_entry = entry;
        entry.next = new_entry;
    }
    entry.offset = offset;
    entry.size = size;
    entry.data = (ubyte*) malloc(size);
    entry.broadcast_ttl = broadcast_ttl;
    net_memcpy(entry.data, data, size);
}

static inline bool handle_data_first_packet(MeshController& controller, PacketFarDataFirst* packet, uint payload_size,
                                            far_addr_t src, far_addr_t dst) {
    auto stream_size = net_load(packet->stream_size);

    // retransmit packet if it is not for us
    if (dst != controller.self_addr && dst != BROADCAST_FAR_ADDR) {
        controller.router.write_data_stream_bytes(dst, 0, packet->payload, payload_size, true,
                                                  net_load(packet->stream_id),
                                                  net_load(packet->stream_size), 0, src);
        return false;
    }

    // fast path: do not create stream if it will be single-packet
    if (payload_size >= stream_size && dst != BROADCAST_FAR_ADDR) {
        auto stream_content = (ubyte*) malloc(stream_size);
        net_memcpy(stream_content, packet->payload, stream_size);
        compete_data_stream(controller, stream_content, stream_size, src, dst);
        return true;
    }
    // create stream and add packet to it
    else {
        DataStreamIdentity identity;
        identity.src_addr = src;
        identity.dst_addr = dst;
        identity.stream_id = net_load(packet->stream_id);
        auto& stream = controller.data_streams.try_emplace(identity, stream_size, Os::get_microseconds()).first->second;

        auto result = stream.add_data(0, packet->payload, payload_size);
        check_stream_completeness(controller, identity, stream);
        return result;
    }
}

static inline bool handle_data_part_packet(MeshController& controller, PacketFarDataPart8* packet, uint payload_size,
                                           far_addr_t src, far_addr_t dst) {
    DataStreamIdentity identity;
    identity.src_addr = src;
    identity.dst_addr = dst;
    identity.stream_id = packet->stream_id;

    auto offset = net_load(packet->offset);
    if (!offset)
        return false;

    // retransmit packet if it is not for us
    if (dst != controller.self_addr && dst != BROADCAST_FAR_ADDR) {
        controller.router.write_data_stream_bytes(dst, offset, packet->payload, payload_size, true,
                                                  net_load(packet->stream_id), 0, 0, src);
        return false;
    }

    // find existing stream to add packet to, or cache the packet until it expires or stream appears
    auto stream_iter = controller.data_streams.find(identity);
    if (stream_iter == controller.data_streams.end()) {
        add_rx_data_packet_to_cache(controller, identity, offset, packet->payload, payload_size);
        return false;
    }
    auto& stream = stream_iter->second;

    // add data and check if stream can be finished
    auto result = stream.add_data(offset, packet->payload, payload_size);
    if (result)
        stream.last_modif_timestamp = Os::get_microseconds();
    check_stream_completeness(controller, identity, stream);
    return result;
}

static inline void retransmit_packet_first_broadcast(MeshController& controller, MeshPacket* packet, uint size,
                                                     uint allocated_packet_size, far_addr_t src_addr, uint payload_size) {
    // temporary malloced memory that is large enough to fit packet + security payload in it (if it is required)
    MeshPacket* oversize_storage = nullptr;

    for (auto [peer_addr, peer] : controller.router.peers) {
        auto interface = peer.interface;
        auto mtu = controller.interfaces[interface->id].mtu;

        if (controller.interfaces[interface->id].is_secured)
            mtu -= MESH_SECURE_PACKET_OVERHEAD;

        // when oversize_storage becomes available, it is always used to better utilize cpu caches
        // (`packet` may go out of cache and will not be used anymore in this function)
        auto curr_packet_ptr = oversize_storage ? oversize_storage : packet;

        if (size > mtu) {
            controller.router.write_data_stream_bytes(BROADCAST_FAR_ADDR, 0, curr_packet_ptr->far_data.first.payload,
                                                      payload_size, true,
                                                      net_load(curr_packet_ptr->far_data.first.stream_id),
                                                      net_load(curr_packet_ptr->far_data.first.stream_size),
                                                      net_load(curr_packet_ptr->ttl), src_addr); // ttl already decreased
        }

        else {
            auto phy_addr = controller.interfaces[interface->id].sessions->get_phy_addr(peer_addr);

            if (controller.interfaces[interface->id].is_secured) {
                // creating oversize_storage if required and not created earlier
                if (size + MESH_SECURE_PACKET_OVERHEAD > allocated_packet_size && !oversize_storage) {
                    oversize_storage = (MeshPacket*) malloc(size + MESH_SECURE_PACKET_OVERHEAD);
                    net_memcpy(curr_packet_ptr, packet, size);
                    curr_packet_ptr = oversize_storage;
                }

                // signing packet
                auto session = controller.interfaces[interface->id].sessions->get_or_none_session(phy_addr);
                generate_packet_signature(&controller, session, curr_packet_ptr, size);
                size += MESH_SECURE_PACKET_OVERHEAD;
            }

            // sending directly into interface
            interface->send_packet(phy_addr, curr_packet_ptr, size);
        }
    }

    if (oversize_storage)
        free(oversize_storage); // yes, free(nullptr) is valid and compilers may emit this if, but i'd better
                                // do it manually to make sure unnecessary function call optimized out
}

static inline void retransmit_packet_part_broadcast(MeshController& controller, MeshPacket* packet, uint size,
                                                    uint allocated_packet_size, far_addr_t src_addr, uint payload_size) {
    // temporary malloced memory that is large enough to fit packet + security payload in it (if it is required)
    MeshPacket* oversize_storage = nullptr;

    for (auto [peer_addr, peer] : controller.router.peers) {
        auto interface = peer.interface;
        auto mtu = controller.interfaces[interface->id].mtu;

        if (controller.interfaces[interface->id].is_secured)
            mtu -= MESH_SECURE_PACKET_OVERHEAD;

        // when oversize_storage becomes available, it is always used to better utilize cpu caches
        // (`packet` may go out of cache and will not be used anymore in this function)
        auto curr_packet_ptr = oversize_storage ? oversize_storage : packet;

        if (size > mtu) {
            controller.router.write_data_stream_bytes(BROADCAST_FAR_ADDR, net_load(curr_packet_ptr->far_data.part_8.offset),
                                                      curr_packet_ptr->far_data.first.payload,
                                                      payload_size, true,
                                                      net_load(curr_packet_ptr->far_data.first.stream_id), 0,
                                                      net_load(curr_packet_ptr->ttl), src_addr); // ttl already decreased
        }

        else {
            auto phy_addr = controller.interfaces[interface->id].sessions->get_phy_addr(peer_addr);

            if (controller.interfaces[interface->id].is_secured) {
                // creating oversize_storage if required and not created earlier
                if (size + MESH_SECURE_PACKET_OVERHEAD > allocated_packet_size && !oversize_storage) {
                    oversize_storage = (MeshPacket*) malloc(size + MESH_SECURE_PACKET_OVERHEAD);
                    net_memcpy(curr_packet_ptr, packet, size);
                    curr_packet_ptr = oversize_storage;
                }

                // signing packet
                auto session = controller.interfaces[interface->id].sessions->get_or_none_session(phy_addr);
                generate_packet_signature(&controller, session, curr_packet_ptr, size);
                size += MESH_SECURE_PACKET_OVERHEAD;
            }

            // sending directly into interface
            interface->send_packet(phy_addr, curr_packet_ptr, size);
        }
    }

    if (oversize_storage)
        free(oversize_storage); // yes, free(nullptr) is valid and compilers may emit this if, but i'd better
                                // do it manually to make sure unnecessary function call optimized out
}


// mesh controller
MeshController::MeshController(const char* netname, far_addr_t self_addr_) : self_addr(self_addr_) {
    memset(network_name, 0, sizeof(network_name));
    memcpy(network_name, netname, std::min(strlen(netname), sizeof(network_name)));

    memset(pre_shared_key, 0, sizeof(pre_shared_key));

    Os::create_task(task_check_packets, CHECK_PACKETS_TASK_NAME, CHECK_PACKETS_TASK_STACK_SIZE, this,
                    CHECK_PACKETS_TASK_PRIORITY, &check_packets_task_handle, CHECK_PACKETS_TASK_AFFINITY);
}

// todo remove them when debugging done
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

void MeshController::on_packet(uint interface_id, MeshPhyAddrPtr phy_addr, MeshPacket* packet, uint size) {
    if (!MESH_FIELD_ACCESSIBLE(type, size))
        return;
    if (phy_addr) {
        printf("got a packet from (" MACSTR "): type=%d, size=%d\n", MAC2STR((ubyte*) phy_addr), (int) packet->type, size);
        fflush(stdout);
    }
    else {
        printf("got a packet from unknown address: type=%d, size=%d\n", (int) packet->type, size);
        fflush(stdout);
    }
    // todo handle non-secured interfaces as well
    // todo add encryption for data streams
    auto& interface_descr = interfaces[interface_id];
    auto interface = interface_descr.interface;

    far_addr_t tx_addr;
    PeerSessionInfo* session;
    uint allocated_packet_size = size;
    auto packet_type = net_load(packet->type);

    // gathering secure/insecure session info and checking packet signature
    if (interface_descr.is_secured) {
        if (packet_type >= MeshPacketType::FIRST_NEAR_PACKET_NUM) {
            handle_near_secure(*this, interface_id, phy_addr, packet, size);
            return;
        }

        session = interface_descr.sessions->get_or_none_session(phy_addr);
        if (!session)
            return;

        auto sign_offset = (int) size - (int) MESH_SECURE_PACKET_OVERHEAD;
        //if (sign_offset < esp_cpu_process_stack_pc(size))
        if (sign_offset <= 0)
            return;
        auto sign = (MessageSign*) ((ubyte*) packet + sign_offset);

        auto timestamp = net_load(sign->timestamp);
        hashdigest_t packet_signature;
        net_memcpy(&packet_signature, &sign->hash, sizeof(hashdigest_t));
        tx_addr = session->secure.peer_far_addr;

        if (timestamp < session->secure.prev_peer_timestamp)
            return;

        MessageHashConcatParams hash_concat_params;
        hash_concat_params.packet_size = sign_offset;
        net_store(hash_concat_params.timestamp, timestamp);
        net_loadstore_nonscalar(hash_concat_params.psk, pre_shared_key);
        net_loadstore_nonscalar(hash_concat_params.session_key, session->secure.session_key);

        ubyte correct_signature[32];
        auto hash_ctx = Os::create_sha256();
        Os::update_sha256(&hash_ctx, packet, sign_offset);
        Os::update_sha256(&hash_ctx, &hash_concat_params, sizeof(MessageHashConcatParams));
        Os::finish_sha256(&hash_ctx, correct_signature);

        if (!!net_memcmp(&correct_signature, &packet_signature, std::min(sizeof(hashdigest_t), sizeof(correct_signature))))
            return;

        printf("packet hash correct!\n");
        fflush(stdout);

        // finish
        session->secure.prev_peer_timestamp = timestamp;
        size = sign_offset;
    }
    else {
        if (packet_type >= MeshPacketType::FIRST_NEAR_PACKET_NUM) {
            handle_near_insecure(*this, interface_id, phy_addr, packet, size);
            return;
        }

        session = interface_descr.sessions->get_or_none_session(phy_addr);
        if (!session)
            return;
        tx_addr = session->insecure.peer_far_addr;
        printf("packet hash not required\n");
        fflush(stdout);
    }

    // check optimized far data packets
    if (packet_type == MeshPacketType::FAR_OPTIMIZED_DATA_FIRST) {
        if (!MESH_FIELD_ACCESSIBLE(opt_data.first, size))
            return;

        auto payload_size = size - MESH_CALC_SIZE(opt_data.first.payload);
        handle_data_first_packet(*this, &packet->opt_data.first, payload_size, tx_addr, self_addr);
        return;
    }

    if (packet_type == MeshPacketType::FAR_OPTIMIZED_DATA_PART) {
        if (!MESH_FIELD_ACCESSIBLE(opt_data.part_8, size))
            return;

        auto payload_size = size - MESH_CALC_SIZE(opt_data.part_8.payload);
        handle_data_part_packet(*this, &packet->opt_data.part_8, payload_size, tx_addr, self_addr);
        return;
    }

    // parse common far packets
    if (!MESH_FIELD_ACCESSIBLE(dst_addr, size))
        return;
    far_addr_t src = net_load(packet->src_addr);
    far_addr_t dst = net_load(packet->dst_addr);

    if (src == self_addr)
        return;

    if (packet->type == MeshPacketType::FAR_PING) {
        if (!MESH_FIELD_ACCESSIBLE(far_ping, size))
            return;
        if (!net_pre_decrement(packet->ttl))
            return;

        if (interface_descr.mtu < net_load(packet->far_ping.min_mtu)) {
            net_store(packet->far_ping.min_mtu, interface_descr.mtu);
            net_store(packet->far_ping.router_num_with_min_mtu, packet->far_ping.routers_passed);
        }
        net_pre_increment(packet->far_ping.routers_passed);

        if (dst == self_addr) {
            net_store(packet->type, MeshPacketType::FAR_PING_RESPONSE);
            net_store(packet->ttl, (decltype(packet->ttl)) (packet->far_ping.routers_passed + 1)); // the "perfect" ttl, based on route length
            net_store(packet->dst_addr, packet->src_addr);
            net_store(packet->src_addr, self_addr);

            if (interface_descr.is_secured)
                generate_packet_signature(this, session, packet, size);
            // size is always enough because sending packet through the same interface by which the packet was received
            interface->send_packet(phy_addr, packet, size + MESH_SECURE_PACKET_OVERHEAD);
        }
        else {
            //
        }

        router.add_route(src, tx_addr, net_load(packet->far_ping.routers_passed));
        return;
    }

    // retransmitting packet (some required-to-retransmit packets go further and will be retransmitted
    // inside it's handlers (handle_data_first_packet(), handle_data_part_packet())
    if (dst != self_addr && dst != BROADCAST_FAR_ADDR) {
        if (!net_pre_decrement(packet->ttl))
            return;

        // retransmit if packet fits the peers MTU (any non-data packet do)
        if (router.send_packet(packet, size, allocated_packet_size))
            return;
    }

    if (packet->type == MeshPacketType::FAR_PING_RESPONSE) {
        if (!MESH_FIELD_ACCESSIBLE(far_ping_response, size))
            return;
        if (!net_pre_decrement(packet->ttl))
            return;

        router.add_route(src, tx_addr, packet->far_ping_response.routers_passed);
    }

    if (packet->type == MeshPacketType::FAR_DATA_FIRST) {
        if (!MESH_FIELD_ACCESSIBLE(far_data.first, size))
            return;
        if (!net_pre_decrement(packet->ttl))
            return;

        auto payload_size = size - MESH_CALC_SIZE(far_data.first.payload);
        if (handle_data_first_packet(*this, &packet->far_data.first, payload_size, src, dst) && dst == BROADCAST_FAR_ADDR) {
            retransmit_packet_first_broadcast(*this, packet, size, allocated_packet_size, src, payload_size);
        }
        return;
    }

    if (packet->type == MeshPacketType::FAR_DATA_PART) {
        if (!MESH_FIELD_ACCESSIBLE(far_data.part_8, size))
            return;
        if (!net_pre_decrement(packet->ttl))
            return;

        auto payload_size = size - MESH_CALC_SIZE(far_data.part_8.payload);
        if (handle_data_part_packet(*this, &packet->far_data.part_8, payload_size, src, dst) && dst == BROADCAST_FAR_ADDR) {
            retransmit_packet_part_broadcast(*this, packet, size, allocated_packet_size, src, payload_size);
        }
        return;
    }
}

[[noreturn]] void MeshController::task_check_packets(void* userdata) {
    auto self = (MeshController*) userdata;
    while (true) {
        for (auto& interface : self->interfaces) {
            interface.interface->check_packets();
            interface.sessions->check_caches(Os::get_microseconds());
        }
        self->check_data_streams();
        self->router.check_packet_cache();
        Os::yield_non_starving();
    }
}

void MeshController::add_interface(MeshInterface* interface) {
    interface->id = interfaces.size();
    interface->controller = this;
    auto props = interface->get_props();
    interfaces.push_back({interface, props.sessions, props.far_mtu, props.need_secure});
    interface->send_hello(nullptr);
}

void MeshController::remove_interface(MeshInterface* interface) {
    interface->controller = nullptr;
    auto last_elem = interfaces[interfaces.size() - 1];
    last_elem.interface->id = interface->id;
    if (interface != last_elem.interface) // to prevent from being moved to itself
        interfaces[interface->id] = last_elem;
    interfaces.pop_back();
}

void MeshController::set_psk_password(const char* password) {
    const char salt[] = "1n5aNeEeEeE CuCuMbErS and HYSTERICAL magicircles!";
    auto hash_src = (ubyte*) alloca(sizeof(salt) + strlen(password));
    memcpy(hash_src, password, strlen(password) + 1);
    memcpy(&hash_src[strlen(password) + 1], salt, sizeof(salt) - 1);

    ubyte hash_digest[32];
    Os::sha256(hash_src, sizeof(salt) + strlen(password), hash_digest);
    memcpy(pre_shared_key, hash_digest, std::min(sizeof(pre_shared_key), sizeof(hash_digest)));
}

MeshController::~MeshController() {
    // fixme memory and cpu issues with removing currently processed task
    Os::end_task(check_packets_task_handle);
}

void MeshController::check_data_streams() {
    auto time = Os::get_microseconds();

    for (auto i = data_streams.begin(); i != data_streams.end();) {
        auto& identity = i->first;
        auto& stream = i->second;

        if (check_stream_completeness(*this, identity, stream))
            continue;
        if (stream.is_expired(time, identity.dst_addr == BROADCAST_FAR_ADDR)) {
            i = data_streams.erase(i);
            continue;
        }
        ++i;
    }
}









// router
void Router::add_route(far_addr_t dst, far_addr_t gateway, ubyte distance) {
    auto& route = routes[dst];
    if (route.state == RouteState::INSPECTING) {
        route.route_cnt = 0;
    }
    route.state = RouteState::ESTABLISHED;
    route.route_cnt = 1;
    route.routes[0].gateway_addr = gateway;
    route.routes[0].distance = distance;
    check_packet_cache(dst);
    for (int i = 0; i < route.route_cnt; ++i) {
        //
        //kek(12);
        //kek("12");
    }
    //faccessat()
    // todo implement adding route
}

bool Router::send_packet(MeshPacket* packet, uint size, uint available_size) {
    // there are no broadcast packets, except for data packets, that are sent by another function

    far_addr_t dst_addr = net_load(packet->dst_addr);

    // routing table lookup
    auto route_iter = routes.find(dst_addr);
    // no route: save packet and discover the route
    if (route_iter == routes.end()) {
        // save the packet
        auto saved_packet = (MeshPacket*) malloc(size + MESH_SECURE_PACKET_OVERHEAD);
        net_memcpy(saved_packet, packet, size);
        packet_cache.add_tx_packet(dst_addr, {saved_packet, size});

        // discover the route
        auto& route = routes[dst_addr];
        route.state = RouteState::INSPECTING;
        route.time_started = Os::get_microseconds();

        discover_route(dst_addr);
        return true;
    }
    // route is being inspected: save the packet
    if (route_iter->second.state == RouteState::INSPECTING) {
        // save the packet
        auto saved_packet = (MeshPacket*) malloc(size + MESH_SECURE_PACKET_OVERHEAD);
        net_memcpy(saved_packet, packet, size);
        packet_cache.add_tx_packet(dst_addr, {saved_packet, size});
        return true;
    }

    // routing table lookup
    auto gateway_far_addr = route_iter->second.routes[0].gateway_addr;
    net_store(packet->ttl, route_iter->second.routes[0].distance + 1);

    // peer table lookup
    auto interface = peers[gateway_far_addr].interface;
    auto interface_descr = controller.interfaces[interface->id];

    // packet size exceeds the interface MTU
    if (size + (interface_descr.is_secured * MESH_SECURE_PACKET_OVERHEAD) > interface_descr.mtu) {
        return false;
    }

    auto phy_addr = interface_descr.sessions->get_phy_addr(gateway_far_addr);

    bool needs_free = false;
    if (interface_descr.is_secured) {
        // if no space for security payload
        if (available_size - size < MESH_SECURE_PACKET_OVERHEAD) {
            auto new_packet = (MeshPacket*) malloc(size + MESH_SECURE_PACKET_OVERHEAD); // todo should use manual fast allocator
            net_memcpy(new_packet, packet, size);
            packet = new_packet;
            needs_free = true;
        }

        // generate signature
        auto session = interface_descr.sessions->get_or_none_session(phy_addr);
        generate_packet_signature(&controller, session, packet, size);

        size += MESH_SECURE_PACKET_OVERHEAD;
    }

    // send
    interface->send_packet(phy_addr, packet, size);

    // free auxiliary memory if allocated
    if (needs_free)
        free(packet);

    return true;
}

void Router::discover_route(far_addr_t dst) {
    auto far_ping = (MeshPacket*) malloc(MESH_CALC_SIZE(far_ping) + MESH_SECURE_PACKET_OVERHEAD);
    net_store(far_ping->type, MeshPacketType::FAR_PING);
    net_store(far_ping->ttl, CONTROLLER_DEFAULT_PACKET_TTL);
    net_store(far_ping->far_ping.routers_passed, 0);
    net_store(far_ping->far_ping.router_num_with_min_mtu, 0);
    net_store(far_ping->src_addr, controller.self_addr);
    net_store(far_ping->dst_addr, dst);

    for (auto& [far, peer] : peers) {
        auto peer_list = &peer;

        while (peer_list) {
            auto interface = peer_list->interface;
            auto interface_descr = controller.interfaces[interface->id];
            net_store(far_ping->far_ping.min_mtu, interface_descr.mtu);
            auto phy_addr = interface_descr.sessions->get_phy_addr(far);

            if (interface_descr.is_secured) {
                // session is always a valid ptr
                auto session = interface_descr.sessions->get_or_none_session(phy_addr);
                generate_packet_signature(&controller, session, far_ping, MESH_CALC_SIZE(far_ping));
            }

            interface->send_packet(phy_addr, far_ping, MESH_CALC_SIZE(far_ping) + MESH_SECURE_PACKET_OVERHEAD);

            peer_list = peer_list->next;
        }
    }

    free(far_ping);
}

auto Router::check_packet_cache(decltype(packet_cache.tx_cache)::iterator cache_iter, far_addr_t dst)
        -> decltype(packet_cache.tx_cache)::iterator {
    auto start_entry = &cache_iter->second;
    auto entry = start_entry;

    // route object is already created when something came into cache
    auto route = routes[dst];
    if (route.state == RouteState::ESTABLISHED) {
        while (entry) {
            if (entry->type == CachedTxDataInfo::CachedDataType::STANDALONE_PACKET) {
                send_packet(entry->standalone.data, entry->standalone.size, entry->standalone.size + MESH_SECURE_PACKET_OVERHEAD);
                free(entry->standalone.data);
            }

            if (entry->type == CachedTxDataInfo::CachedDataType::DATA_STREAM) {
                auto curr_part = &entry->data_stream.part;
                auto peer = peers[route.routes[0].gateway_addr];

                while (curr_part) {
                    // fixme this is not optimal to set force_send=true on part packets, however it is a rare case
                    //  (maybe create a temporary buffer for accumulating unsent data and try to merge new data in it?)
                    //  ugh please no, it's not worth it, i think
                    write_data_stream_bytes(dst, curr_part->offset, curr_part->data, curr_part->size,
                                            true, entry->data_stream.stream_id, entry->data_stream.stream_size, 0, {},
                                            route.routes[0], peer);

                    free(curr_part->data);
                    auto old_part = curr_part;
                    curr_part = curr_part->next;
                    if (old_part != &entry->data_stream.part) // do not free the first part because it's placed in map, not malloced
                        free(old_part);
                }
            }

            auto old_entry = entry;
            entry = entry->next;
            if (old_entry != start_entry) // do not free the first part because it's placed in map, not malloced
                free(old_entry);
        }

        return packet_cache.tx_cache.erase(cache_iter);
    }

    if (route.state == RouteState::INSPECTING &&
        Os::get_microseconds() > route.time_started + RouteInfo::ROUTE_DISCOVERY_TIMEOUT) {
        route.state = RouteState::INEXISTING;
    }

    if (route.state == RouteState::INEXISTING) {
        while (entry) {
            if (entry->type == CachedTxDataInfo::CachedDataType::STANDALONE_PACKET) {
                free(entry->standalone.data);
            }

            if (entry->type == CachedTxDataInfo::CachedDataType::DATA_STREAM) {
                auto curr_part = &entry->data_stream.part;
                while (curr_part) {
                    free(curr_part->data);
                    auto old_part = curr_part;
                    curr_part = curr_part->next;
                    if (old_part != &entry->data_stream.part)
                        free(old_part);
                }
            }

            auto old_entry = entry;
            entry = entry->next;
            if (old_entry != start_entry)
                free(old_entry);
        }

        return packet_cache.tx_cache.erase(cache_iter);
    }

    return ++cache_iter;
}

void Router::check_packet_cache(far_addr_t dst) {
    auto cache_iter = packet_cache.tx_cache.find(dst);
    if (cache_iter == packet_cache.tx_cache.end())
        return;
    check_packet_cache(cache_iter, dst);
}

void Router::check_packet_cache() {
    // tx cache
    for (auto i = packet_cache.tx_cache.begin(); i != packet_cache.tx_cache.end();) {
        i = check_packet_cache(i, i->first);
    }

    auto time = Os::get_microseconds();

    // rx stream cache
    for (auto i = packet_cache.rx_stream_cache.begin(); i != packet_cache.rx_stream_cache.end();) {
        auto& identity = i->first;
        auto& cached_stream = i->second;

        DataStream* stream;

        ubyte fake_stream_storage[sizeof(DataStream)]; // no, destructor is called later, but actually useless

        // looking up for stream or creating fake one if packets need to be deleted
        auto streams_iter = controller.data_streams.find(identity);
        if (streams_iter == controller.data_streams.end()) {
            if (!cached_stream.is_expired(time)) {
                ++i;
                continue;
            }

            stream = (DataStream*) fake_stream_storage;
            new (stream) DataStream(0, 0);
        }
        else
            stream = &streams_iter->second;

        auto part = &cached_stream.part;
        stream->last_modif_timestamp = time;

        // adding packets to stream and retransmitting, if they are broadcasts
        while (part) {
            auto res = stream->add_data(part->offset, part->data, part->size);

            // retransmitting if broadcast
            if (identity.dst_addr == BROADCAST_FAR_ADDR && res) {
                write_data_stream_bytes(identity.dst_addr, part->offset, part->data, part->size, true,
                                        identity.stream_id, 0, part->broadcast_ttl, identity.src_addr);
            }

            free(part->data);
            auto old_part = part;
            part = part->next;
            if (old_part != &cached_stream.part)
                free(old_part);
        }

        if (streams_iter == controller.data_streams.end()) {
            ((DataStream*) fake_stream_storage)->~DataStream(); // actually useless, because only does free(nullptr)
        }
        else {
            check_stream_completeness(controller, identity, *stream);
        }
        i = packet_cache.rx_stream_cache.erase(i);
    }
}

uint Router::write_data_stream_bytes(MeshProto::far_addr_t dst, uint offset, const ubyte* data, uint size,
                                     bool force_send, ubyte stream_id, uint stream_size, ubyte broadcast_ttl,
                                     far_addr_t broadcast_src_addr) {
    if (dst == BROADCAST_FAR_ADDR) {
        Route tmp_route;
        uint min_bytes_written = 0;
        for (auto& [peer_addr, peer] : peers) {
            tmp_route.gateway_addr = peer_addr;
            auto current_written = write_data_stream_bytes(dst, offset, data, size, force_send, stream_id, stream_size,
                                                           broadcast_ttl, broadcast_src_addr, tmp_route, peer);
            min_bytes_written = std::min(min_bytes_written, current_written);
        }
        return min_bytes_written;
    }

    auto route = routes[dst];

    if (route.state == RouteState::ESTABLISHED) {
        return write_data_stream_bytes(dst, offset, data, size, force_send, stream_id, stream_size, 0, 0,
                                       route.routes[0], peers[route.routes[0].gateway_addr]);
    }

    // drop the data
    if (route.state == RouteState::INEXISTING) {
        return size;
    }

    // start discovering route, save data
    if (route.state == RouteState::UNKNOWN) {
        route.state = RouteState::INSPECTING;
        route.time_started = Os::get_microseconds();
        discover_route(dst);
    }

    // save data to packet_cache.tx_cache (linked list of streams/standalone packets, and stream in a linked list of its parts)
    if (route.state == RouteState::INSPECTING) {
        auto saved_data = malloc(size);
        memcpy(saved_data, data, size);

        auto& first_entry = packet_cache.tx_cache[dst];
        auto entry = &first_entry;

        while (entry && !(entry->type == CachedTxDataInfo::CachedDataType::DATA_STREAM &&
                          entry->data_stream.stream_id == stream_id)) {
            entry = entry->next;
        }

        // reached end (not found existing entry)
        if (!entry) {
            entry = &first_entry;
            // if some node existed in cache, but is not suitable for us - create new node and place before the existing one
            if (entry->type != CachedTxDataInfo::CachedDataType::UNKNOWN) {
                auto new_entry = (CachedTxDataInfo*) malloc(sizeof(CachedTxDataInfo));
                *new_entry = *entry;
                entry->next = new_entry;
            }

            // set up a new node (created by malloc or operator[] on unordered_map)
            entry->type = CachedTxDataInfo::CachedDataType::DATA_STREAM;
            entry->data_stream.stream_size = stream_size;
            entry->data_stream.stream_id = stream_id;
            entry->data_stream.part.offset = offset;
            entry->data_stream.part.size = size;
            entry->data_stream.part.data = (ubyte*) saved_data;
            entry->data_stream.part.next = nullptr;

            return size;
        }

        // found existing stream
        else {
            auto new_entry = (CachedTxDataStreamPart*) malloc(sizeof(CachedTxDataStreamPart));
            *new_entry = entry->data_stream.part;
            entry->data_stream.part.next = new_entry;

            entry->data_stream.part.offset = offset;
            entry->data_stream.part.size = size;
            entry->data_stream.part.data = (ubyte*) saved_data;

            return size;
        }
    }
    return 0;
}

uint Router::write_data_stream_bytes(far_addr_t dst, uint offset, const ubyte* data, uint size,
                                     bool force_send, ubyte stream_id, uint stream_size, ubyte broadcast_ttl,
                                     far_addr_t broadcast_src_addr, Route& route, Peer& peer) {
    auto gateway = route.gateway_addr;
    auto interface = peer.interface;
    auto interface_descr = controller.interfaces[interface->id];
    auto phy_addr = interface_descr.sessions->get_phy_addr(gateway);
    auto mtu = interface_descr.mtu;

    // todo this ought to be allocated from pool allocator
    // for far/optimized/broadcast
    MeshPacketType first_packet_type;
    MeshPacketType part_packet_type;
    MeshProto::DataStream* data_ptr;
    MeshPacket* packet;

    // for far/optimized/broadcasts
    if (dst == gateway) {
        // can use optimized far
        auto packet_overhead_size =
                std::max(offsetof(MeshPacket, opt_data.part_8.payload),
                         (offset == 0 ? offsetof(MeshPacket, opt_data.first.payload) : 0)) +
                (interface_descr.is_secured ? MESH_SECURE_PACKET_OVERHEAD : 0);

        // not a full packet
        if (packet_overhead_size + size < mtu && !force_send)
            return 0;

        packet = (MeshPacket*) malloc(std::min((size_t) mtu, size + packet_overhead_size));

        first_packet_type = MeshPacketType::FAR_OPTIMIZED_DATA_FIRST;
        part_packet_type = MeshPacketType::FAR_OPTIMIZED_DATA_PART;
        data_ptr = &packet->opt_data;
    }
    else {
        // common far otherwise
        auto packet_overhead_size =
                std::max(offsetof(MeshPacket, far_data.part_8.payload),
                         (offset == 0 ? offsetof(MeshPacket, far_data.first.payload) : 0)) +
                (interface_descr.is_secured ? MESH_SECURE_PACKET_OVERHEAD : 0);

        // not a full packet
        if (packet_overhead_size + size < mtu && !force_send)
            return 0;

        packet = (MeshPacket*) malloc(std::min((size_t) mtu, size + packet_overhead_size));

        first_packet_type = MeshPacketType::FAR_DATA_FIRST;
        part_packet_type = MeshPacketType::FAR_DATA_PART;
        data_ptr = &packet->far_data;

        net_store(packet->src_addr, dst == BROADCAST_FAR_ADDR ? broadcast_src_addr : controller.self_addr);
        net_store(packet->dst_addr, dst);
        net_store(packet->ttl, dst == BROADCAST_FAR_ADDR ? broadcast_ttl : route.distance + 1);
    }

    auto data_offset = (ubyte*) data_ptr - (ubyte*) packet;

    // send loop
    uint total_written = 0;
    while (size) {
        uint send_size = data_offset;
        send_size += offset == 0 ? offsetof(MeshProto::DataStream, first.payload) :
                                   offsetof(MeshProto::DataStream, part_8.payload);
        send_size += interface_descr.is_secured ? MESH_SECURE_PACKET_OVERHEAD : 0;
        auto chunk_size = std::min(size, mtu - send_size);
        send_size += chunk_size;

        // here we can exit this function because there's not enough data to fill the entire packet
        if (send_size < mtu && !force_send)
            break;

        // for first/part
        if (offset == 0) { // first packet
            net_store(packet->type, first_packet_type);
            net_store(data_ptr->first.stream_id, stream_id);
            net_store(data_ptr->first.stream_size, stream_size);
            net_memcpy(&data_ptr->first.payload, data, chunk_size);
        }
        else { // part packet
            net_store(packet->type, part_packet_type);
            net_store(data_ptr->part_8.stream_id, stream_id);
            net_store(data_ptr->part_8.offset, offset);
            memcpy(&data_ptr->part_8.payload, data, chunk_size);
        }

        // for secure/insecure
        if (interface_descr.is_secured) {
            // session is always non-null
            generate_packet_signature(&controller, interface_descr.sessions->get_or_none_session(phy_addr), packet,
                                      send_size - MESH_SECURE_PACKET_OVERHEAD);
        }
        else {
            //
        }

        interface->send_packet(phy_addr, packet, send_size);

        size -= chunk_size;
        offset += chunk_size;
        data += chunk_size;
        total_written += chunk_size;
    }

    free(packet);

    return total_written;
}

void Router::add_peer(MeshProto::far_addr_t peer, MeshInterface* interface) {
    // todo sort interfaces by mtu or something
    auto& stored = peers[peer];
    if (stored.interface) {
        auto new_peer = (Peer*) malloc(sizeof(Peer));
        *new_peer = stored;
        stored.next = new_peer;
    }
    stored.interface = interface;
}

bool NsMeshController::DataStream::add_data(ushort offset, const ubyte* data, ushort size) {
    if ((uint) offset + size > stream_size)
        return false;
    if (!remake_parts(offset, offset + size))
        return false;
    net_memcpy(&stream_data[offset], data, size);
    return true;
}

bool NsMeshController::DataStream::remake_parts(ushort start, ushort end) {
    // code for adding new segment to collection of existing ones

    bool begin_found = false, end_found = false;
    ushort new_segment[2]{start, end}; // new segment boundaries. may extend if merged with existing segments

    ushort new_collection[DATA_STREAM_RECV_PAIR_CNT + 1][2];
    uint new_collection_fill_level = 0;

    for (int i = 0; i < DATA_STREAM_RECV_PAIR_CNT; ++i) {
        if (recv_parts[i][0] == recv_parts[i][1]) {
            new_collection[i][0] = new_collection[i][1] = 0;
            continue;
        }

        // setting lower boundary of new segment
        if (recv_parts[i][0] <= start && start <= recv_parts[i][1]) {
            begin_found = true;
            new_segment[0] = recv_parts[i][0]; // merging with existing segment: changing lower boundary
        }
        else if (start < recv_parts[i][0] && !begin_found)
            begin_found = true;

        // adding existing part if it's not getting merged with new segment
        if (begin_found == end_found)
            memcpy(new_collection[new_collection_fill_level++], recv_parts[i], sizeof(recv_parts[i]));

        // setting upper boundary of new segment. when upper boundary is found, lower boundary is always set, so adding new segment
        if (recv_parts[i][0] <= end && end <= recv_parts[i][1]) {
            end_found = true;
            new_segment[1] = recv_parts[i][1]; // merging with existing segment: changing upper boundary
            memcpy(new_collection[new_collection_fill_level++], new_segment, sizeof(new_segment));
        }
        else if (end < recv_parts[i][0] && !end_found) {
            end_found = true;
            memcpy(new_collection[new_collection_fill_level++], new_segment, sizeof(new_segment));
        }
    }

    // if reached end of existing segment collection, but didn't find the upper boundary
    if (!end_found)
        memcpy(new_collection[new_collection_fill_level++], new_segment, sizeof(new_segment));

    // requires storing more segments than possible. error.
    if (new_collection_fill_level > DATA_STREAM_RECV_PAIR_CNT) {
        return false;
    }

    // exiting if collection is not changed
    if (!memcmp(recv_parts, new_collection, sizeof(recv_parts)))
        return false;

    memcpy(recv_parts, new_collection, sizeof(recv_parts));
    return true;
}

void PacketCache::add_tx_packet(MeshProto::far_addr_t dst_addr, CachedTxStandalonePacket&& packet) {
    auto& storage = tx_cache[dst_addr];
    if (storage.type != CachedTxDataInfo::CachedDataType::UNKNOWN) {
        auto new_cache_entry = (CachedTxDataInfo*) malloc(sizeof(CachedTxDataInfo));
        *new_cache_entry = storage;
        storage.next = new_cache_entry;
    }
    storage.type = CachedTxDataInfo::CachedDataType::STANDALONE_PACKET;
    storage.standalone = packet;
}
