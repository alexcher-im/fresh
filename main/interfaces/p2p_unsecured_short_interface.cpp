#include <cstdio>
#include <cassert>
#include "mesh_controller.h"
#include "p2p_unsecured_short_interface.h"
#include "net_utils.h"


using namespace MeshProto;


P2PUnsecuredShortInterface::P2PUnsecuredShortInterface(bool is_self_rx_buf_infinite_, bool is_opponent_rx_buf_infinite_,
                                                       BaseSerial& read_stream_, BaseSerial& write_stream_)
: is_self_rx_buf_infinite(is_self_rx_buf_infinite_),
  is_opponent_rx_buf_infinite(is_opponent_rx_buf_infinite_),
  read_stream(read_stream_),
  write_stream(write_stream_) { }

void P2PUnsecuredShortInterface::check_packets() {
    // if waiting for new packet
    if (!remain_read) {
        ubyte tmp_char;
        if (!read_stream.read_nonblock(&tmp_char, 1))
            return;

        ubyte read_char = tmp_char;
        if (~read_char & 0b10000000) {
            return; // todo write this bytes somewhere as a common stdin char/bytes
        }

        remain_read = (uint) (read_char & 0b01111111);
        if (!remain_read) {
            assert(!ack_received); // got unexpected ACK signal
            ack_received = true;
            process_next_queue_element();
            return;
        }
    }

    // read as much, as we can
    auto read_amount = read_stream.read_nonblock((ubyte*) curr_buf + curr_read_amount, remain_read);
    remain_read -= read_amount;
    curr_read_amount += read_amount;

    // if something is remaining - yield and wait until everything received
    if (remain_read)
        return;

    send_ack();

    controller->on_packet(id, nullptr, (MeshPacket*) curr_buf, curr_read_amount);
    curr_read_amount = 0;
    remain_read = 0;
}

bool P2PUnsecuredShortInterface::accept_near_packet(MeshPhyAddrPtr phy_addr, const MeshPacket* packet, uint size) {
    return true;
}

MeshPacket* P2PUnsecuredShortInterface::alloc_near_packet(MeshPacketType type, uint size) {
    auto packet = (MeshPacket*) malloc(size);
    net_store(packet->type, type);
    return packet;
}

MeshPacket* P2PUnsecuredShortInterface::realloc_near_packet(MeshPacket* packet, MeshPacketType old_type,
                                                            MeshPacketType new_type, uint new_size) {
    auto new_packet = (MeshPacket*) realloc(packet, new_size);
    new_packet->type = new_type;
    return new_packet;
}

void P2PUnsecuredShortInterface::free_near_packet(MeshPacket* packet) {
    free(packet);
}

void P2PUnsecuredShortInterface::send_packet(MeshPhyAddrPtr phy_addr, const MeshPacket* packet, uint size) {
    if (!size)
        return;
    if (is_opponent_rx_buf_infinite || ack_received) {
        send_packet_data(packet, size);
        ack_received = false;
    }
    else
        cache.add_entry(packet, size);
}

MeshInterfaceProps P2PUnsecuredShortInterface::get_props() {
    return {&sessions, FAR_MTU, 0, false};
}

void P2PUnsecuredShortInterface::send_hello(MeshPhyAddrPtr phy_addr) {
    auto packet = (MeshPacket*) alloca(MESH_CALC_SIZE(near_hello_insecure));
    net_store(packet->type, MeshPacketType::NEAR_HELLO);
    net_store(packet->near_hello_insecure.self_far_addr, controller->self_addr);
    net_memcpy(packet->near_hello_secure.network_name, controller->network_name, sizeof(controller->network_name));

    send_packet(phy_addr, packet, MESH_CALC_SIZE(near_hello_insecure));
}

void P2PUnsecuredShortInterface::write_addr_bytes(MeshPhyAddrPtr phy_addr, void* out_buf) {
    // nothing
}

void P2PUnsecuredShortInterface::send_packet_data(const void* data, ubyte size) {
    write_stream.start_writing();
    write_stream.write_byte(0b10000000 | size); // header with size
    write_stream.write(data, size);             // data itself
    write_stream.end_writing();
}

void P2PUnsecuredShortInterface::process_next_queue_element() {
    if (cache.first_entry) {
        auto entry = cache.first_entry;
        cache.first_entry = entry->next;
        if (cache.last_entry == entry)
            cache.last_entry = nullptr;

        send_packet_data(entry->data, entry->size);
        ack_received = false;
        free(entry->data);
        free(entry);
    }
}

void P2PUnsecuredShortInterface::send_ack() {
    write_stream.start_writing();
    write_stream.write_byte(0b10000000);
    write_stream.end_writing();
}

void NsP2PUnsecuredShortInterface::PacketCache::add_entry(const void* data, ubyte size) {
    auto new_entry = (CacheEntry*) malloc(sizeof(CacheEntry));
    new_entry->data = malloc(size);
    new_entry->size = size;
    new_entry->next = nullptr;
    net_memcpy(new_entry->data, data, size);

    if (last_entry) {
        last_entry->next = new_entry;
        last_entry = new_entry;
    }
    else {
        first_entry = new_entry;
        last_entry = new_entry;
    }
}
