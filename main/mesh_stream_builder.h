#pragma once

#include "types.h"
#include "mesh_protocol.h"
#include "mesh_controller.h"


class MeshStreamBuilder
{
public:
    uint stream_size;
    MeshProto::far_addr_t dst_addr;
    MeshController& controller;
    decltype(MeshProto::PacketFarDataFirst::stream_id) stream_id;
    uint mtu;
    uint sent_size{0};
    ubyte* cache{};
    uint cache_fill{};

    static decltype(MeshProto::PacketFarDataFirst::stream_id) g_stream_id;

    MeshStreamBuilder(MeshController& controller_, MeshProto::far_addr_t dst_addr_, uint size);

    void write(const void* data, uint size);

    ~MeshStreamBuilder();
};
