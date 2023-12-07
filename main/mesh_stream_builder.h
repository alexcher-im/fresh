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
    MeshProto::stream_id_t stream_id;
    uint mtu;
    uint sent_size{0};
    ubyte* cache{};
    uint cache_fill{};

    static MeshProto::stream_id_t g_stream_id;

    MeshStreamBuilder(MeshController& controller_, MeshProto::far_addr_t dst_addr_, uint size);

    void write(const void* data, uint size);

    ~MeshStreamBuilder();
};
