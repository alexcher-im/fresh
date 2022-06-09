#include <cstdio>
#include <cassert>
#include "mesh_controller.h"
#include "pc_std_uart_interface.h"

// ESP32 opens a stdout in text mode and by default, replaces \n with \r\n
// the only way to print raw bytes i found is to use uart_tx_one_char(), which is said to "output char to printf channel"
#ifdef ESP_PLATFORM
#include <rom/uart.h>
#define STDOUT_PRINT(data, size, count, fp) do { for (int i = 0; i < size * count; ++i) \
                                                    uart_tx_one_char(((const char*) data)[i]); \
                                               } while (0)
#define STDOUT_PUTC(chr, fp) uart_tx_one_char(chr)
#else
#define STDOUT_PRINT fwrite
#define STDOUT_PUTC putc
#endif


using namespace MeshProto;


PcStdUartInterface::PcStdUartInterface(bool is_self_rx_buf_infinite_, bool is_opponent_rx_buf_infinite_,
                                       FILE* read_stream_, FILE* write_stream_)
: is_self_rx_buf_infinite(is_self_rx_buf_infinite_),
  is_opponent_rx_buf_infinite(is_opponent_rx_buf_infinite_),
  read_stream(read_stream_),
  write_stream(write_stream_) { }

void PcStdUartInterface::check_packets() {
    // if waiting for new packet
    if (!remain_read) {
        int int_char;
        if ((int_char = getc(read_stream)) == EOF)
            return;

        ubyte read_char = int_char;
        if (~read_char & 0b10000000)
            return; // todo write this bytes somewhere as a common stdin char/bytes

        remain_read = (uint) (read_char & 0b01111111);
        if (!remain_read) {
            assert(!ack_received); // got unexpected ACK signal
            ack_received = true;
            return;
        }
    }

    // read as much, as we can
    auto read_amount = fread((ubyte*) curr_buf + curr_read_amount, 1, remain_read, read_stream);
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

bool PcStdUartInterface::accept_near_packet(MeshPhyAddrPtr phy_addr, const MeshPacket* packet, uint size) {
    return true;
}

MeshPacket* PcStdUartInterface::alloc_near_packet(MeshPacketType type, uint size) {
    auto packet = (MeshPacket*) malloc(size);
    packet->type = type;
    return packet;
}

MeshPacket* PcStdUartInterface::realloc_near_packet(MeshPacket* packet, MeshPacketType old_type,
                                                    MeshPacketType new_type, uint new_size) {
    auto new_packet = (MeshPacket*) realloc(packet, new_size);
    new_packet->type = new_type;
    return new_packet;
}

void PcStdUartInterface::free_near_packet(MeshPacket* packet) {
    free(packet);
}

void PcStdUartInterface::send_packet(MeshPhyAddrPtr phy_addr, const MeshPacket* packet, uint size) {
    if (!size)
        return;
    if (is_opponent_rx_buf_infinite)
        send_packet_data(packet, size);
    else if (ack_received)
        send_packet_data(packet, size);
    else
        cache.add_entry(packet, size);
}

MeshInterfaceProps PcStdUartInterface::get_props() {
    return {&sessions, FAR_MTU, 0, false};
}

void PcStdUartInterface::send_hello(MeshPhyAddrPtr phy_addr) {
    auto packet = (MeshPacket*) alloca(MESH_CALC_SIZE(near_hello_secure));
    packet->type = MeshPacketType::NEAR_HELLO;
    memcpy(packet->near_hello_secure.network_name, controller->network_name, sizeof(controller->network_name));

    send_packet(phy_addr, packet, MESH_CALC_SIZE(near_hello_secure));
}

void PcStdUartInterface::write_addr_bytes(MeshPhyAddrPtr phy_addr, void* out_buf) {
    // nothing
}

void PcStdUartInterface::send_packet_data(const void* data, ubyte size) {
    STDOUT_PUTC(0b10000000 | size, write_stream); // header with size
    STDOUT_PRINT(data, size, 1, write_stream);    // data itself
}

void PcStdUartInterface::process_next_queue_element() {
    if (cache.first_entry) {
        auto entry = cache.first_entry;
        cache.first_entry = entry->next;
        if (cache.last_entry == entry)
            cache.last_entry = nullptr;

        send_packet_data(entry->data, entry->size);
        free(entry->data);
        free(entry);
        ack_received = false;
    }
}

void PcStdUartInterface::send_ack() {
    STDOUT_PUTC(0b10000000, write_stream);
}

PcStdUartInterface PcStdUartInterface::open_on_esp32_for_pc() {
    return {false, true, stdin, stdout};
}

PcStdUartInterface PcStdUartInterface::open_on_windows_for_esp32() {
    return {true, false, stdin, stdout}; // todo this should be a winapi serial object
}

void NsPcStdUartInterface::PacketCache::add_entry(const void* data, ubyte size) {
    auto new_entry = (CacheEntry*) malloc(sizeof(CacheEntry));
    new_entry->data = malloc(size);
    new_entry->size = size;
    memcpy(new_entry->data, data, size);

    if (last_entry) {
        last_entry->next = new_entry;
        last_entry = new_entry;
    }
    else {
        first_entry = new_entry;
        last_entry = new_entry;
    }
}
