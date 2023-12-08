#include "mesh_controller.h"
#include "log_utils.h"

#include <new>
#include <string_view>


using namespace MeshProto;
using namespace NsMeshController;

// todo move this function somewhere outside
// todo do not create tasks for every packet, make another api
// todo send NEAR_HELLO frames through some interfaces (such as wifi) to discover new clients in case of their packet loss
static inline void print_bytes(const ubyte* buf, uint size) {
    for (int i = 0; i < size; ++i) {
        printf("%02x", buf[i]);
        if (i != size - 1)
            printf(":");
    }
    printf("\n");
}

// todo add sniffing api


#pragma pack(push, 1)
struct MessageHashConcatParams
{
    uint packet_size;
    timestamp_t timestamp;
    decltype(MeshController::pre_shared_key) psk;
    session_key_t session_key;
};
#pragma pack(pop)


// todo versify that size excludes secure interface overhead (but packet is allocated to have enough space for signature)
hashdigest_t MeshController::calc_packet_signature(const PeerSessionInfo* session,
                                                   MeshPacket* packet, uint size, u64 timestamp) const {
    MessageHashConcatParams hash_concat_params{size, timestamp, pre_shared_key, session->secure.session_key};

    auto hash_ctx = Os::Sha256Hasher();
    hash_ctx.update(packet, size);
    hash_ctx.update(&hash_concat_params, sizeof(MessageHashConcatParams));
    return hash_ctx.finish<hashdigest_t>();
}

void MeshController::generate_packet_signature(const PeerSessionInfo* session, MeshPacket* packet, uint size) const {
    auto sign = (MessageSign*) ((ubyte*) packet + size);
    auto timestamp = Os::get_microseconds();

    auto correct_signature = calc_packet_signature(session, packet, size, timestamp);

    memcpy(&sign->hash, &correct_signature, sizeof(correct_signature));
    sign->timestamp = timestamp;
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
    if (info->controller->callbacks.on_data_packet)
        info->controller->callbacks.on_data_packet(info->src_addr, info->data, info->size);

    free(info->data);
    Os::detach_task(info->curr_task);
    info->~CompletedStreamInfo();
    free(info);
    Os::end_self_task();
}


void MeshController::compete_data_stream(ubyte* data, uint size, far_addr_t src_addr, far_addr_t dst_addr) {
    auto compl_info = (CompletedStreamInfo*) malloc(sizeof(CompletedStreamInfo));
    new (compl_info) CompletedStreamInfo();
    compl_info->controller = this;
    compl_info->data = data;
    compl_info->size = size;
    compl_info->src_addr = src_addr;
    compl_info->dst_addr = dst_addr;
    Os::create_task(task_handle_packet, HANDLE_DATA_PACKET_NAME, HANDLE_PACKET_TASK_STACK_SIZE,
                    compl_info, HANDLE_PACKET_TASK_PRIORITY, &compl_info->curr_task, HANDLE_PACKET_TASK_AFFINITY);
}

bool MeshController::check_stream_completeness(const DataStreamIdentity& identity,
                                               NsMeshController::DataStream& stream) {
    if (!stream.is_completed())
        return false;

    auto stream_data = stream.stream_data;
    stream.stream_data = nullptr;
    compete_data_stream(stream_data, stream.stream_size, identity.src_addr, identity.dst_addr);

    // broadcasts are never deleted immediately. at this point, .is_completed() will return if stream handler
    // should be called, but stream itself will only expire (deleted in Router::check_packet_cache())
    if (identity.dst_addr != BROADCAST_FAR_ADDR)
        data_streams.erase(identity);
    return true;
}

// todo add controller.router.routes() (router.add_route()) for new peers
void MeshController::handle_near_secure(uint interface_id, MeshPhyAddrPtr phy_addr, MeshPacket* packet, uint size,
                                        PacketLog& packet_log) {
    auto& interface_descr = interfaces[interface_id];
    auto interface = interface_descr.interface;
    auto packet_type = packet->type;

    if (packet_type == MeshPacketType::NEAR_HELLO) {
        packet_log.write("NEAR_HELLO");

        if (!MESH_FIELD_ACCESSIBLE(near_hello_secure, size)) {
            packet_log.write("DISCARD (small size: near_hello_secure is not accessible)");
            return;
        }
        if (!netname_cmp(packet->near_hello_secure.network_name)) {
            packet_log.write("DISCARD (network name mismatched: {:s})",
                             std::string_view((char*) packet->near_hello_secure.network_name,
                                              sizeof(packet->near_hello_secure.network_name)));
            return;
        }

        // checks
        auto est_session = interface_descr.sessions->get_or_create_est_session(phy_addr);
        if (est_session->stage != PeerSecureSessionEstablishmentStage::UNKNOWN) {
            packet_log.write("DISCARD (est session for this sender is already associated)");
            return;
        }

        if (!interface->accept_near_packet(phy_addr, packet, size)) {
            packet_log.write("DISCARD (interface did not accept packet)");
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
        init_packet->near_hello_init.member_nonce = est_session->peer_nonce;

        // sending
        packet_log.write("sending NEAR_HELLO_INIT");
        write_log(self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: sending secure NEAR_HELLO_INIT");
        interface->send_packet(phy_addr, init_packet, packet_size);
        interface->free_near_packet(init_packet);
        printf("time after hello handler: %llu\n", Os::get_microseconds());
    }

    else if (packet_type == MeshPacketType::NEAR_HELLO_INIT) {
        packet_log.write("NEAR_HELLO_INIT");

        if (!MESH_FIELD_ACCESSIBLE(near_hello_init, size)) {
            packet_log.write("DISCARD (small size: near_hello_init is not accessible)");
            return;
        }

        // checks
        auto est_session = interface_descr.sessions->get_or_create_est_session(phy_addr);
        if (est_session->stage != PeerSecureSessionEstablishmentStage::UNKNOWN) {
            packet_log.write("DISCARD (est session for this sender is already associated)");
            return;
        }

        if (!interface->accept_near_packet(phy_addr, packet, size)) {
            packet_log.write("DISCARD (interface did not accept packet)");
            interface_descr.sessions->remove_est_session(phy_addr);
            return;
        }
        // setting est session
        est_session->stage = PeerSecureSessionEstablishmentStage::WAITING_FOR_HELLO_JOINED;
        est_session->time_start = Os::get_microseconds();
        Os::fill_random(&est_session->session_info.session_key, sizeof(session_key_t));

        // generating response packet
        auto packet_size = MESH_CALC_SIZE(near_hello_authorize);
        auto auth_packet = interface->alloc_near_packet(MeshPacketType::HEAR_HELLO_AUTHORIZE, packet_size);
        auth_packet->near_hello_authorize.session_key = est_session->session_info.session_key;
        auth_packet->near_hello_authorize.self_far_addr = self_addr;
        auth_packet->near_hello_authorize.initial_timestamp = Os::get_microseconds();

        // generating hash (packet signature)
        auto hash_src_size = offsetof(MeshPacket, near_hello_authorize.hash) + sizeof(pre_shared_key);
        ubyte hash_src[hash_src_size];
        memcpy(&hash_src, auth_packet, offsetof(MeshPacket, near_hello_authorize.hash));
        memcpy(&hash_src[offsetof(MeshPacket, near_hello_authorize.hash)], &pre_shared_key, sizeof(pre_shared_key));
        auth_packet->near_hello_authorize.hash = Os::Sha256Hasher::hash<hashdigest_t>(&hash_src, hash_src_size);

        // sending
        packet_log.write("sending HEAR_HELLO_AUTHORIZE");
        write_log(self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: sending secure HEAR_HELLO_AUTHORIZE");
        interface->send_packet(phy_addr, auth_packet, packet_size);
        interface->free_near_packet(auth_packet);
        printf("time after init handler: %llu\n", Os::get_microseconds());
    }

    else if (packet_type == MeshPacketType::HEAR_HELLO_AUTHORIZE) {
        packet_log.write("HEAR_HELLO_AUTHORIZE");

        if (!MESH_FIELD_ACCESSIBLE(near_hello_authorize, size)) {
            packet_log.write("DISCARD (small size: near_hello_authorize is not accessible)");
            return;
        }

        // checking if we were waiting for this packet (from this address and with this type)
        auto est_session = interface_descr.sessions->get_or_none_est_session(phy_addr);
        if (est_session == nullptr || est_session->stage != PeerSecureSessionEstablishmentStage::WAITING_FOR_HELLO_AUTH) {
            packet_log.write("DISCARD (no est session associated with sender or a different est session state found)");
            return;
        }

        // generating verification hash
        auto hash_src_size = offsetof(MeshPacket, near_hello_authorize.hash) + sizeof(pre_shared_key);
        ubyte hash_src[hash_src_size];
        memcpy(&hash_src, packet, offsetof(MeshPacket, near_hello_authorize.hash));
        memcpy(&hash_src[offsetof(MeshPacket, near_hello_authorize.hash)], &pre_shared_key, sizeof(pre_shared_key));
        auto computed_verif_hash = Os::Sha256Hasher::hash<hashdigest_t>(&hash_src, hash_src_size);

        if (computed_verif_hash != packet->near_hello_authorize.hash) {
            packet_log.write("DISCARD (security hash is not valid)");
            return;
        }

        // checks
        if (!interface->accept_near_packet(phy_addr, packet, size)) {
            packet_log.write("DISCARD (interface did not accept packet)");
            return;
        }

        // setting session
        auto session = interface_descr.sessions->get_or_create_session(phy_addr);
        session->secure.session_key = packet->near_hello_authorize.session_key;
        session->secure.peer_far_addr = packet->near_hello_authorize.self_far_addr;
        session->secure.prev_peer_timestamp = packet->near_hello_authorize.initial_timestamp;

        // generating response packet
        auto packet_size = MESH_CALC_SIZE(near_hello_joined_secure);
        auto joined_packet = interface->alloc_near_packet(MeshPacketType::NEAR_HELLO_JOINED, packet_size);
        joined_packet->near_hello_joined_secure.initial_timestamp = Os::get_microseconds();
        joined_packet->near_hello_joined_secure.self_far_addr = self_addr;

        // generating hash (packet sign)
        auto hash_j_size = offsetof(MeshPacket, near_hello_joined_secure.hash) + sizeof(pre_shared_key);
        ubyte hash_j[hash_j_size];
        memcpy(&hash_j, joined_packet, offsetof(MeshPacket, near_hello_joined_secure.hash));
        memcpy(&hash_j[offsetof(MeshPacket, near_hello_joined_secure.hash)], &pre_shared_key, sizeof(pre_shared_key));
        joined_packet->near_hello_joined_secure.hash = Os::Sha256Hasher::hash<hashdigest_t>(&hash_j, hash_j_size);

        packet_log.write("sending NEAR_HELLO_INIT");
        packet_log.write("authorized peer");

        // sending
        write_log(self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: sending secure NEAR_HELLO_JOINED");
        interface->send_packet(phy_addr, joined_packet, packet_size);
        interface->free_near_packet(joined_packet);

        // registering peer and removing session establishment info
        interface_descr.sessions->remove_est_session(phy_addr);
        printf("time after auth handler: %llu\n", Os::get_microseconds());
        printf("peer session done: from auth (other addr: %u)\n", (uint) session->secure.peer_far_addr);

        interface_descr.sessions->register_far_addr(session->secure.peer_far_addr, phy_addr);
        router.add_peer(session->secure.peer_far_addr, interface);
    }

    else if (packet_type == MeshPacketType::NEAR_HELLO_JOINED) {
        packet_log.write("NEAR_HELLO_JOINED");

        if (!MESH_FIELD_ACCESSIBLE(near_hello_joined_secure, size)) {
            packet_log.write("DISCARD (small size: near_hello_joined_secure is not accessible)");
            return;
        }

        // checking if we were waiting for this packet (from this address and with this type)
        auto est_session = interface_descr.sessions->get_or_none_est_session(phy_addr);
        if (est_session == nullptr || est_session->stage != PeerSecureSessionEstablishmentStage::WAITING_FOR_HELLO_JOINED) {
            packet_log.write("DISCARD (no est session associated with sender or a different est session state found)");
            return;
        }

        // generating verification hash
        auto hash_j_size = offsetof(MeshPacket, near_hello_joined_secure.hash) + sizeof(pre_shared_key);
        ubyte hash_src[hash_j_size];
        memcpy(&hash_src, packet, offsetof(MeshPacket, near_hello_joined_secure.hash));
        memcpy(&hash_src[offsetof(MeshPacket, near_hello_joined_secure.hash)], &pre_shared_key, sizeof(pre_shared_key));
        auto computed_verif_hash = Os::Sha256Hasher::hash<hashdigest_t>(&hash_src, hash_j_size);

        if (computed_verif_hash != packet->near_hello_joined_secure.hash) {
            packet_log.write("DISCARD (security hash is not valid)");
            return;
        }

        // checks
        if (!interface->accept_near_packet(phy_addr, packet, size)) {
            packet_log.write("DISCARD (interface did not accept packet)");
            return;
        }

        packet_log.write("authorized peer");

        // setting session
        auto session = interface_descr.sessions->get_or_create_session(phy_addr);
        session->secure.session_key = est_session->session_info.session_key;
        session->secure.peer_far_addr = packet->near_hello_joined_secure.self_far_addr;
        session->secure.prev_peer_timestamp = packet->near_hello_joined_secure.initial_timestamp;

        interface_descr.sessions->remove_est_session(phy_addr);
        printf("time after joined handler: %llu\n", Os::get_microseconds());
        printf("peer session done: from joined (other addr: %u)\n", (uint) session->secure.peer_far_addr);

        interface_descr.sessions->register_far_addr(session->secure.peer_far_addr, phy_addr);
        router.add_peer(session->secure.peer_far_addr, interface);
    }
}

void MeshController::handle_near_insecure(uint interface_id, MeshPhyAddrPtr phy_addr, MeshPacket* packet, uint size,
                                          PacketLog& packet_log) {
    auto& interface_descr = interfaces[interface_id];
    auto interface = interface_descr.interface;
    auto packet_type = packet->type;

    if (packet_type == MeshPacketType::NEAR_HELLO) {
        packet_log.write("NEAR_HELLO");

        if (!MESH_FIELD_ACCESSIBLE(near_hello_insecure, size)) {
            packet_log.write("DISCARD (small size: near_hello_insecure is not accessible)");
            return;
        }
        if (!netname_cmp(packet->near_hello_insecure.network_name)) {
            packet_log.write("DISCARD (network name mismatched: {:s})",
                             std::string_view((char*) packet->near_hello_insecure.network_name,
                                              sizeof(packet->near_hello_insecure.network_name)));
            return;
        }

        auto session = interface_descr.sessions->get_or_create_session(phy_addr);
        session->insecure.peer_far_addr = packet->near_hello_insecure.self_far_addr;

        if (!interface->accept_near_packet(phy_addr, packet, size)) {
            packet_log.write("DISCARD (interface did not accept packet)");
            return;
        }

        packet_log.write("sending NEAR_HELLO_JOINED");
        packet_log.write("authorized peer");

        auto packet_size = MESH_CALC_SIZE(near_hello_joined_insecure);
        auto joined_packet = interface->alloc_near_packet(MeshPacketType::NEAR_HELLO_JOINED, packet_size);
        joined_packet->near_hello_joined_insecure.self_far_addr = self_addr;
        write_log(self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: sending insecure NEAR_HELLO_JOINED");
        interface->send_packet(phy_addr, joined_packet, packet_size);
        interface->free_near_packet(joined_packet);

        router.add_peer(session->insecure.peer_far_addr, interface);
        printf("got insecure near hello (opponent addr: %u)\n", (uint) session->insecure.peer_far_addr);
        fflush(stdout);
    }

    else if (packet_type == MeshPacketType::NEAR_HELLO_JOINED) {
        packet_log.write("NEAR_HELLO_JOINED");

        if (!MESH_FIELD_ACCESSIBLE(near_hello_joined_insecure, size)) {
            packet_log.write("DISCARD (small size: near_hello_joined_insecure is not accessible)");
            return;
        }

        auto session = interface_descr.sessions->get_or_create_session(phy_addr);
        session->insecure.peer_far_addr = packet->near_hello_joined_insecure.self_far_addr;
        router.add_peer(session->insecure.peer_far_addr, interface);

        packet_log.write("authorized peer");

        printf("got insecure near joined (opponent addr: %u)\n", (uint) session->insecure.peer_far_addr);
        fflush(stdout);
    }
}

void Router::add_rx_data_packet_to_cache(DataStreamIdentity identity, uint offset,
                                         ubyte* data, uint size, ubyte broadcast_ttl) {
    auto& cached_stream = packet_cache.rx_stream_cache[identity];
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
    memcpy(entry.data, data, size);
}

bool MeshController::handle_data_first_packet(PacketFarDataFirst* packet, uint payload_size,
                                              far_addr_t src, far_addr_t dst, PacketLog& packet_log) {
    auto stream_size = packet->stream_size;

    // retransmit packet if it is not for us
    if (dst != self_addr && dst != BROADCAST_FAR_ADDR) {
        packet_log.write("FORWARD (as data forward)");
        router.write_data_stream_bytes(dst, 0, packet->payload, payload_size, true,
                                       packet->stream_id,
                                       packet->stream_size, 0, src);
        return false;
    }

    // fast path: do not create stream if it will be single-packet
    if (payload_size >= stream_size && dst != BROADCAST_FAR_ADDR) {
        auto stream_content = (ubyte*) malloc(stream_size);
        memcpy(stream_content, packet->payload, stream_size);
        packet_log.write("COMPLETE (fast path: single packet, unicast)");
        compete_data_stream(stream_content, stream_size, src, dst);
        return true;
    }

    // create stream and add packet to it
    else {
        packet_log.write("DATA ADD (stream created/found and data added)");

        DataStreamIdentity identity;
        identity.src_addr = src;
        identity.dst_addr = dst;
        identity.stream_id = packet->stream_id;
        auto& stream = data_streams.try_emplace(identity, stream_size, Os::get_microseconds()).first->second;

        auto result = stream.add_data(0, packet->payload, payload_size);
        check_stream_completeness(identity, stream);
        return result;
    }
}

bool MeshController::handle_data_part_packet(PacketFarDataPart8* packet, uint payload_size,
                                             far_addr_t src, far_addr_t dst, PacketLog& packet_log) {
    DataStreamIdentity identity;
    identity.src_addr = src;
    identity.dst_addr = dst;
    identity.stream_id = packet->stream_id;

    auto offset = packet->offset;
    if (!offset)
        return false;

    // retransmit packet if it is not for us
    if (dst != self_addr && dst != BROADCAST_FAR_ADDR) {
        packet_log.write("FORWARD (as data forward)");
        router.write_data_stream_bytes(dst, offset, packet->payload, payload_size, true,
                                       packet->stream_id, 0, 0, src);
        return false;
    }

    // find existing stream to add packet to, or cache the packet until it expires or stream appears
    auto stream_iter = data_streams.find(identity);
    if (stream_iter == data_streams.end()) {
        packet_log.write("RX_CACHE (saving packet: no stream created for this ID)");
        router.add_rx_data_packet_to_cache(identity, offset, packet->payload, payload_size);
        return false;
    }
    auto& stream = stream_iter->second;

    // add data and check if stream can be finished
    packet_log.write("DATA ADD (stream found and data added)");
    auto result = stream.add_data(offset, packet->payload, payload_size);
    if (result)
        stream.last_modif_timestamp = Os::get_microseconds();
    check_stream_completeness(identity, stream);
    return result;
}

void MeshController::retransmit_packet_first_broadcast(MeshPacket* packet, uint packet_size, uint allocated_packet_size,
                                                       far_addr_t src_addr, uint payload_size, PacketLog& packet_log) {
    // temporary malloced memory that is large enough to fit packet + security payload in it (if it is required)
    MeshPacket* oversize_storage = nullptr;

    for (auto [peer_addr, peer] : router.peers) {
        auto send_size = packet_size;
        auto interface = peer.interface;
        auto mtu = interfaces[interface->id].mtu;

        if (interfaces[interface->id].is_secured)
            mtu -= MESH_SECURE_PACKET_OVERHEAD;

        // when oversize_storage becomes available, it is always used to better utilize cpu caches
        // (`packet` may go out of cache and will not be used anymore in this function)
        auto curr_packet_ptr = oversize_storage ? oversize_storage : packet;

        if (send_size > mtu) {
            packet_log.write("FORWARD (broadcast retransmission with reshaping (size={}, mtu={})", send_size, mtu);
            router.write_data_stream_bytes(BROADCAST_FAR_ADDR, 0, curr_packet_ptr->far.data.first.payload,
                                           payload_size, true,
                                           curr_packet_ptr->far.data.first.stream_id,
                                           curr_packet_ptr->far.data.first.stream_size,
                                           curr_packet_ptr->far.ttl, src_addr); // ttl already decreased
        }

        else {
            auto phy_addr = interfaces[interface->id].sessions->get_phy_addr(peer_addr);

            if (interfaces[interface->id].is_secured) {
                // creating oversize_storage if required and not created earlier
                if (send_size + MESH_SECURE_PACKET_OVERHEAD > allocated_packet_size && !oversize_storage) {
                    oversize_storage = (MeshPacket*) malloc(send_size + MESH_SECURE_PACKET_OVERHEAD);
                    memcpy(curr_packet_ptr, packet, send_size);
                    curr_packet_ptr = oversize_storage;
                }

                // signing packet
                auto session = interfaces[interface->id].sessions->get_or_none_session(phy_addr);
                generate_packet_signature(session, curr_packet_ptr, send_size);
                send_size += MESH_SECURE_PACKET_OVERHEAD;
            }

            // sending directly into interface
            packet_log.write("FORWARD (broadcast retransmission as is (size={}, mtu={})", send_size, mtu);
            write_log(self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: retransmitting broadcast to far(%u)",
                      (uint) peer_addr);
            interface->send_packet(phy_addr, curr_packet_ptr, send_size);
        }
    }

    if (oversize_storage)
        free(oversize_storage); // yes, free(nullptr) is valid and compilers may emit this if, but i'd better
                                // do it manually to make sure unnecessary function call optimized out
}

void MeshController::retransmit_packet_part_broadcast(MeshPacket* packet, uint packet_size, uint allocated_packet_size,
                                                      far_addr_t src_addr, uint payload_size, PacketLog& packet_log) {
    // temporary malloced memory that is large enough to fit packet + security payload in it (if it is required)
    MeshPacket* oversize_storage = nullptr;

    for (auto [peer_addr, peer] : router.peers) {
        auto send_size = packet_size;
        auto interface = peer.interface;
        auto mtu = interfaces[interface->id].mtu;

        if (interfaces[interface->id].is_secured)
            mtu -= MESH_SECURE_PACKET_OVERHEAD;

        // when oversize_storage becomes available, it is always used to better utilize cpu caches
        // (`packet` may go out of cache and will not be used anymore in this function)
        auto curr_packet_ptr = oversize_storage ? oversize_storage : packet;

        if (send_size > mtu) {
            packet_log.write("FORWARD (broadcast retransmission with reshaping (size={}, mtu={})", send_size, mtu);
            router.write_data_stream_bytes(BROADCAST_FAR_ADDR, curr_packet_ptr->far.data.part_8.offset,
                                           curr_packet_ptr->far.data.first.payload,
                                           payload_size, true,
                                           curr_packet_ptr->far.data.first.stream_id, 0,
                                           curr_packet_ptr->far.ttl, src_addr); // ttl already decreased
        }

        else {
            auto phy_addr = interfaces[interface->id].sessions->get_phy_addr(peer_addr);

            if (interfaces[interface->id].is_secured) {
                // creating oversize_storage if required and not created earlier
                if (send_size + MESH_SECURE_PACKET_OVERHEAD > allocated_packet_size && !oversize_storage) {
                    oversize_storage = (MeshPacket*) malloc(send_size + MESH_SECURE_PACKET_OVERHEAD);
                    memcpy(curr_packet_ptr, packet, send_size);
                    curr_packet_ptr = oversize_storage;
                }

                // signing packet
                auto session = interfaces[interface->id].sessions->get_or_none_session(phy_addr);
                generate_packet_signature(session, curr_packet_ptr, send_size);
                send_size += MESH_SECURE_PACKET_OVERHEAD;
            }

            // sending directly into interface
            packet_log.write("FORWARD (broadcast retransmission as is (size={}, mtu={})", send_size, mtu);
            write_log(self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: retransmitting broadcast to far(%u)",
                      (uint) peer_addr);
            interface->send_packet(phy_addr, curr_packet_ptr, send_size);
        }
    }

    if (oversize_storage)
        free(oversize_storage); // yes, free(nullptr) is valid and compilers may emit this if, but i'd better
                                // do it manually to make sure unnecessary function call optimized out
}


// mesh controller
MeshController::MeshController(const char* netname, far_addr_t self_addr_, bool run_thread_poll_task) : self_addr(self_addr_) {
    memcpy(network_name.data(), netname, std::min(strlen(netname), sizeof(network_name)));

    if (run_thread_poll_task)
        this->run_thread_poll_task();
}

void MeshController::run_thread_poll_task() {
    Os::create_task(task_check_packets, CHECK_PACKETS_TASK_NAME, CHECK_PACKETS_TASK_STACK_SIZE, this,
                    CHECK_PACKETS_TASK_PRIORITY, &check_packets_task_handle, CHECK_PACKETS_TASK_AFFINITY);
}

void MeshController::on_packet(uint interface_id, MeshPhyAddrPtr phy_addr, MeshPacket* packet, uint size) {
    auto& interface_descr = interfaces[interface_id];
    auto interface = interface_descr.interface;
    PacketLog packet_log;

    // pre-declare local vars to allow gotos... todo split this function to a few and change gotos to returns
    far_addr_t tx_addr;
    PeerSessionInfo* session;
    uint allocated_packet_size;
    MeshPacketType packet_type;
    far_addr_t src;
    far_addr_t dst;

    // log basic packet info
    packet_log.write_raw("[{}]: new packet from ", self_addr);
    if (interface_descr.address_size) {
        auto addr_bytes = (ubyte*) alloca(interface_descr.address_size);
        interface_descr.interface->write_addr_bytes(phy_addr, addr_bytes);
        packet_log.write_raw_bytes(addr_bytes, interface_descr.address_size);
    }
    else {
        packet_log.write_raw("unknown");
    }
    packet_log.write("{} bytes raw", (uint) size);
    if (interface_descr.is_secured) packet_log.write("SECURE");
    else packet_log.write("INSECURE");

    // ensure packet has enough size to read packet type
    if (!MESH_FIELD_ACCESSIBLE(type, size)) {
        packet_log.write("DISCARD (small size: packet type is not accessible)");
        goto end;
    }

    // todo add encryption for data streams

    allocated_packet_size = size;
    packet_type = packet->type;

    // gathering secure/insecure session info and checking packet signature
    if (packet_type >= MeshPacketType::FIRST_NEAR_PACKET_NUM) {
        packet_log.write("NEAR");
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet is NEAR");

        if (interface_descr.is_secured)
            handle_near_secure(interface_id, phy_addr, packet, size, packet_log);
        else
            handle_near_insecure(interface_id, phy_addr, packet, size, packet_log);

        goto end;
    }

    packet_log.write("FAR");
    if (interface_descr.is_secured) {
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet is from secure interface");

        session = interface_descr.sessions->get_or_none_session(phy_addr);
        if (!session) {
            packet_log.write("DISCARD (no session associated with sender)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because no session found");
            goto end;
        }

        auto sign_offset = (int) size - (int) MESH_SECURE_PACKET_OVERHEAD;
        if (sign_offset <= 0) {
            packet_log.write("DISCARD (small size: no security payload can be found)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because no security payload found");
            goto end;
        }
        auto sign = (MessageSign*) ((ubyte*) packet + sign_offset);

        timestamp_t timestamp = sign->timestamp;
        hashdigest_t packet_signature;
        memcpy(&packet_signature, &sign->hash, sizeof(hashdigest_t));
        tx_addr = session->secure.peer_far_addr;

        if (timestamp < session->secure.prev_peer_timestamp) {
            packet_log.write("DISCARD (security timestamp is not valid: got {}, expected{}+)",
                             timestamp, session->secure.prev_peer_timestamp);
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because security timestamp invalid");
            goto end;
        }

        auto correct_signature = calc_packet_signature(session, packet, sign_offset, timestamp);

        if (!!memcmp(&correct_signature, &packet_signature, sizeof(correct_signature))) {
            packet_log.write("DISCARD (security hash is not valid)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because security hash invalid");
            goto end;
        }

        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet security check passed");

        // finish
        session->secure.prev_peer_timestamp = timestamp;
        size = sign_offset;
    }
    else {
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet is from insecure interface");

        session = interface_descr.sessions->get_or_none_session(phy_addr);
        if (!session) {
            packet_log.write("DISCARD (no session associated with sender)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because no session found");
            goto end;
        }
        tx_addr = session->insecure.peer_far_addr;

        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet security check not required");
    }

    // check optimized far data packets
    if (packet_type == MeshPacketType::FAR_OPTIMIZED_DATA_FIRST) {
        packet_log.write("FAR_OPTIMIZED_DATA_FIRST (from {})", tx_addr);
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet type is FAR_OPTIMIZED_DATA_FIRST");

        if (!MESH_FIELD_ACCESSIBLE(opt_data.first, size)) {
            packet_log.write("DISCARD (small size: opt_data.first is not accessible)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because header size invalid");
            goto end;
        }

        auto payload_size = size - MESH_CALC_SIZE(opt_data.first.payload);
        handle_data_first_packet(&packet->opt_data.first, payload_size, tx_addr, self_addr, packet_log);
        goto end;
    }

    if (packet_type == MeshPacketType::FAR_OPTIMIZED_DATA_PART) {
        packet_log.write("FAR_OPTIMIZED_DATA_PART (from {})", tx_addr);
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet type is FAR_OPTIMIZED_DATA_PART");

        if (!MESH_FIELD_ACCESSIBLE(opt_data.part_8, size)) {
            packet_log.write("DISCARD (small size: opt_data.part_8 is not accessible)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because header size invalid");
            goto end;
        }

        auto payload_size = size - MESH_CALC_SIZE(opt_data.part_8.payload);
        handle_data_part_packet(&packet->opt_data.part_8, payload_size, tx_addr, self_addr, packet_log);
        goto end;
    }

    // parse common far packets
    if (!MESH_FIELD_ACCESSIBLE(far.dst_addr, size)) {
        packet_log.write("DISCARD (small size: far addresses are not accessible)");
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because far header size invalid");
        goto end;
    }
    src = packet->far.src_addr;
    dst = packet->far.dst_addr;

    packet_log.write("{} -> {}", src, dst);
    if (dst == BROADCAST_FAR_ADDR)
        packet_log.write("BROADCAST");

    if (src == self_addr) {
        packet_log.write("DISCARD (packet sent from current device)");
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because it's sent from the current device");
        goto end;
    }

    if (packet_type == MeshPacketType::FAR_PING) {
        packet_log.write("FAR_PING");
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet type is FAR_PING");

        if (!MESH_FIELD_ACCESSIBLE(far.ping, size)) {
            packet_log.write("DISCARD (small size: far ping structure is not accessible)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because header size invalid");
            goto end;
        }
        if (!--packet->far.ttl) {
            packet_log.write("DISCARD (TTL dropped to zero)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because ttl expired");
            goto end;
        }

        if (interface_descr.mtu < packet->far.ping.min_mtu) {
            packet_log.write("change min MTU ({} -> {})", (uint) packet->far.ping.min_mtu, (uint) interface_descr.mtu);
            packet->far.ping.min_mtu = interface_descr.mtu;
            packet->far.ping.router_num_with_min_mtu = packet->far.ping.routers_passed;
        }
        ++packet->far.ping.routers_passed;

        if (dst == self_addr) {
            packet_log.write("sending FAR_PING_RESPONSE");

            packet->type = MeshPacketType::FAR_PING_RESPONSE;
            packet->far.ttl = (decltype(packet->far.ttl)) (packet->far.ping.routers_passed + 1); // the "perfect" ttl, based on route length
            packet->far.dst_addr = packet->far.src_addr;
            packet->far.src_addr = self_addr;

            if (interface_descr.is_secured) {
                generate_packet_signature(session, packet, size);
                size += MESH_SECURE_PACKET_OVERHEAD;
            }

            // size is always enough because sending packet through the same interface by which the packet was received
            write_log(self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: sending FAR_PING_RESPONSE to far(%u)", (uint) src);
            interface->send_packet(phy_addr, packet, size);
        }
        else {
            packet_log.write("FORWARD (as is)");
            router.send_packet(packet, size, allocated_packet_size);
        }

        router.add_route(src, tx_addr, packet->far.ping.routers_passed);
        goto end;
    }

    // retransmitting packet (some required-to-retransmit packets go further and will be retransmitted
    // inside it's handlers (handle_data_first_packet(), handle_data_part_packet())
    if (dst != self_addr && dst != BROADCAST_FAR_ADDR) {
        packet_log.write("should be forwarded");
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet is not for us and not broadcast");

        if (!--packet->far.ttl) {
            packet_log.write("DISCARD (TTL dropped to zero)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because ttl expired");
            goto end;
        }

        // retransmit if packet fits the peers MTU (any non-data packet do)
        if (router.send_packet(packet, size, allocated_packet_size)) {
            packet_log.write("FORWARD (as is)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet retransmitted because it fits");
            goto end;
        }
    }

    if (packet_type == MeshPacketType::FAR_PING_RESPONSE) {
        packet_log.write("FAR_PING_RESPONSE");
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet type is FAR_PING_RESPONSE");

        if (!MESH_FIELD_ACCESSIBLE(far.ping_response, size)) {
            packet_log.write("DISCARD (small size: far.ping_response is not accessible)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because header size invalid");
            goto end;
        }

        if (!--packet->far.ttl) {
            packet_log.write("DISCARD (TTL dropped to zero)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because ttl expired");
            goto end;
        }

        router.add_route(src, tx_addr, packet->far.ping_response.routers_passed);
        goto end;
    }

    if (packet_type == MeshPacketType::FAR_DATA_FIRST) {
        packet_log.write("FAR_DATA_FIRST");
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet type is FAR_DATA_FIRST");

        if (!MESH_FIELD_ACCESSIBLE(far.data.first, size)) {
            packet_log.write("DISCARD (small size: far.data.first is not accessible)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because header size invalid");
            goto end;
        }

        if (!--packet->far.ttl) {
            packet_log.write("DISCARD (TTL dropped to zero)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because ttl expired");
            goto end;
        }

        auto payload_size = size - MESH_CALC_SIZE(far.data.first.payload);
        packet_log.write_raw(" (stream_id={}, stream_size={}, part_size={})", (uint) packet->far.data.first.stream_id,
                             (uint) packet->far.data.first.stream_size, payload_size);

        if (handle_data_first_packet(&packet->far.data.first, payload_size, src, dst, packet_log) && dst == BROADCAST_FAR_ADDR) {
            retransmit_packet_first_broadcast(packet, size, allocated_packet_size, src, payload_size, packet_log);
        }
        goto end;
    }

    if (packet_type == MeshPacketType::FAR_DATA_PART) {
        packet_log.write("FAR_DATA_PART");
        write_log(self_addr, LogFeatures::TRACE_PACKET, "packet type is FAR_DATA_PART");

        if (!MESH_FIELD_ACCESSIBLE(far.data.part_8, size)) {
            packet_log.write("DISCARD (small size: far.data.part_8 is not accessible)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because header size invalid");
            goto end;
        }

        if (!--packet->far.ttl) {
            packet_log.write("DISCARD (TTL dropped to zero)");
            write_log(self_addr, LogFeatures::TRACE_PACKET, "packet discarded because ttl expired");
            goto end;
        }

        auto payload_size = size - MESH_CALC_SIZE(far.data.part_8.payload);
        packet_log.write_raw(" (stream_id={}, offset={}, part_size={})", (uint) packet->far.data.first.stream_id,
                             (uint) packet->far.data.part_8.offset, payload_size);

        if (handle_data_part_packet(&packet->far.data.part_8, payload_size, src, dst, packet_log) && dst == BROADCAST_FAR_ADDR) {
            retransmit_packet_part_broadcast(packet, size, allocated_packet_size, src, payload_size, packet_log);
        }
        goto end;
    }

    write_log(self_addr, LogFeatures::TRACE_PACKET, "packet control reached end of on_packet() function");

    end:
    if constexpr (ENABLE_PACKET_LOGGER) {
        if (callbacks.packet_tracing_log)
            callbacks.packet_tracing_log(packet_log.finish());
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
    interfaces.push_back({interface, props.sessions, props.far_mtu, props.address_size, props.need_secure});
    write_log(self_addr, LogFeatures::TRACE_PACKET_IO, "sending broadcast hello world");
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
    memcpy(&hash_src[strlen(password) + 1], &salt, sizeof(salt) - 1);

    pre_shared_key = Os::Sha256Hasher::hash<decltype(pre_shared_key)>(hash_src, sizeof(salt) + strlen(password));
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

        if (check_stream_completeness(identity, stream))
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

    auto dst_addr = (far_addr_t) packet->far.dst_addr;

    // routing table lookup
    auto route_iter = routes.find(dst_addr);
    // no route: save packet and discover the route
    if (route_iter == routes.end()) {
        // save the packet
        auto saved_packet = (MeshPacket*) malloc(size + MESH_SECURE_PACKET_OVERHEAD);
        memcpy(saved_packet, packet, size);
        packet_cache.add_tx_packet(dst_addr, {saved_packet, size});

        // discover the route
        auto& route = routes[dst_addr];
        route.state = RouteState::INSPECTING;
        route.time_started = Os::get_microseconds();

        discover_route(dst_addr);
        return true;
    }
    // todo check for INEXISTING state
    // route is being inspected: save the packet
    if (route_iter->second.state == RouteState::INSPECTING) {
        // save the packet
        auto saved_packet = (MeshPacket*) malloc(size + MESH_SECURE_PACKET_OVERHEAD);
        memcpy(saved_packet, packet, size);
        packet_cache.add_tx_packet(dst_addr, {saved_packet, size});
        return true;
    }

    // routing table lookup
    auto gateway_far_addr = route_iter->second.routes[0].gateway_addr;
    packet->far.ttl = route_iter->second.routes[0].distance + 1;

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
            memcpy(new_packet, packet, size);
            packet = new_packet;
            needs_free = true;
        }

        // generate signature
        auto session = interface_descr.sessions->get_or_none_session(phy_addr);
        controller.generate_packet_signature(session, packet, size);

        size += MESH_SECURE_PACKET_OVERHEAD;
    }

    // send
    write_log(controller.self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: sending some packet to far(%u)", (uint) dst_addr);
    interface->send_packet(phy_addr, packet, size);

    // free auxiliary memory if allocated
    if (needs_free)
        free(packet);

    return true;
}

void Router::discover_route(far_addr_t dst) {
    auto far_ping = (MeshPacket*) malloc(MESH_CALC_SIZE(far.ping) + MESH_SECURE_PACKET_OVERHEAD);
    far_ping->type = MeshPacketType::FAR_PING;
    far_ping->far.ttl = CONTROLLER_DEFAULT_PACKET_TTL;
    far_ping->far.ping.routers_passed = 0;
    far_ping->far.ping.router_num_with_min_mtu = 0;
    far_ping->far.src_addr = controller.self_addr;
    far_ping->far.dst_addr = dst;

    for (auto& [far, peer] : peers) {
        auto peer_list = &peer;

        while (peer_list) {
            auto interface = peer_list->interface;
            auto interface_descr = controller.interfaces[interface->id];
            far_ping->far.ping.min_mtu = interface_descr.mtu;
            auto phy_addr = interface_descr.sessions->get_phy_addr(far);

            if (interface_descr.is_secured) {
                // session is always a valid ptr
                auto session = interface_descr.sessions->get_or_none_session(phy_addr);
                controller.generate_packet_signature(session, far_ping, MESH_CALC_SIZE(far.ping));
            }

            write_log(controller.self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: sending FAR_PING packet to far(%u)", (uint) dst);
            interface->send_packet(phy_addr, far_ping, MESH_CALC_SIZE(far.ping) + MESH_SECURE_PACKET_OVERHEAD);

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
    auto& route = routes[dst];
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
            controller.check_stream_completeness(identity, *stream);
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

    auto& route = routes[dst];

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
                std::max(offsetof(MeshPacket, far.data.part_8.payload),
                         (offset == 0 ? offsetof(MeshPacket, far.data.first.payload) : 0)) +
                (interface_descr.is_secured ? MESH_SECURE_PACKET_OVERHEAD : 0);

        // not a full packet
        if (packet_overhead_size + size < mtu && !force_send)
            return 0;

        packet = (MeshPacket*) malloc(std::min((size_t) mtu, size + packet_overhead_size));

        first_packet_type = MeshPacketType::FAR_DATA_FIRST;
        part_packet_type = MeshPacketType::FAR_DATA_PART;
        data_ptr = &packet->far.data;

        packet->far.src_addr = dst == BROADCAST_FAR_ADDR ? broadcast_src_addr : controller.self_addr;
        packet->far.dst_addr = dst;
        packet->far.ttl = dst == BROADCAST_FAR_ADDR ? broadcast_ttl : route.distance + 1;
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
            packet->type = first_packet_type;
            data_ptr->first.stream_id = stream_id;
            data_ptr->first.stream_size = stream_size;
            memcpy(&data_ptr->first.payload, data, chunk_size);
        }
        else { // part packet
            packet->type = part_packet_type;
            data_ptr->part_8.stream_id = stream_id;
            data_ptr->part_8.offset = offset;
            memcpy(&data_ptr->part_8.payload, data, chunk_size);
        }

        // for secure/insecure
        if (interface_descr.is_secured) {
            // session is always non-null
            controller.generate_packet_signature(interface_descr.sessions->get_or_none_session(phy_addr), packet,
                                                 send_size - MESH_SECURE_PACKET_OVERHEAD);
        }
        else {
            //
        }

        write_log(controller.self_addr, LogFeatures::TRACE_PACKET_IO, "packet io: sending data packet to far(%u)", (uint) dst);
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
    memcpy(&stream_data[offset], data, size);
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
