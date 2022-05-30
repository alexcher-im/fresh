#include <cstdlib>
#include "pc_std_uart_interface.h"


using namespace MeshProto;


PcStdUartInterface::PcStdUartInterface() {
    //
}

void PcStdUartInterface::check_packets() {
    //
}

bool PcStdUartInterface::accept_near_packet(MeshPhyAddrPtr phy_addr, const MeshPacket* packet, uint size) {
    return true;
}

MeshPacket* PcStdUartInterface::alloc_near_packet(MeshPacketType type, uint size) {
    auto packet = (MeshPacket*) malloc(size);
    packet->type = type;
    return packet;
}

MeshProto::MeshPacket*
PcStdUartInterface::realloc_near_packet(MeshProto::MeshPacket* packet, MeshProto::MeshPacketType old_type,
                                        MeshProto::MeshPacketType new_type, uint new_size) {
    auto new_packet = (MeshPacket*) realloc(packet, new_size);
    new_packet->type = new_type;
    return new_packet;
}

void PcStdUartInterface::free_near_packet(MeshProto::MeshPacket* packet) {
    free(packet);
}

void PcStdUartInterface::send_packet(MeshPhyAddrPtr phy_addr, const MeshProto::MeshPacket* packet, uint size) {
    //
}

MeshInterfaceProps PcStdUartInterface::get_props() {
    return {&sessions, 127, 0, false};
}

void PcStdUartInterface::send_hello(MeshPhyAddrPtr phy_addr) {
    //
}

void PcStdUartInterface::write_addr_bytes(MeshPhyAddrPtr phy_addr, void* out_buf) {
    //
}
