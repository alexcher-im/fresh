#include "mesh_stream_builder.h"


decltype(MeshProto::PacketFarDataFirst::stream_id) MeshStreamBuilder::g_stream_id = 0;

MeshStreamBuilder::MeshStreamBuilder(MeshController& controller_, uint size, MeshProto::far_addr_t dst_addr_) : stream_size(size),
dst_addr(dst_addr_), controller(controller_), stream_id(g_stream_id++), cache((ubyte*) malloc(0)) {
    //
}

void MeshStreamBuilder::write(const void* data_, uint size) {
    auto data = (const ubyte*) data_;
    uint sent;

    if (!cache_fill) {
        sent = controller.router.write_data_stream_bytes(dst_addr, sent_size, data, size,
                                                         sent_size + size >= stream_size,
                                                         stream_id, stream_size, MeshController::DEFAULT_TTL,
                                                         controller.self_addr);

        if (sent != size) {
            auto remain_size = size - sent;
            cache = (ubyte*) realloc(cache, remain_size);
            memcpy(cache, data + sent, remain_size);
            cache_fill = remain_size;
        }
    }

    else {
        cache = (ubyte*) realloc(cache, cache_fill + size);
        memcpy(&cache[cache_fill], data, size);
        cache_fill += size;
        sent = controller.router.write_data_stream_bytes(dst_addr, sent_size, cache, cache_fill,
                                                         sent_size + size >= stream_size,
                                                         stream_id, stream_size, MeshController::DEFAULT_TTL,
                                                         controller.self_addr);

        if (sent != cache_fill) {
            auto remain_size = cache_fill - sent;
            for (int i = 0; i < remain_size; ++i) {
                cache[i] = cache[i + sent];
            }
            cache = (ubyte*) realloc(cache, remain_size);
            cache_fill = remain_size;
        } else {
            cache = (ubyte*) realloc(cache, 0);
            cache_fill = 0;
        }
    }

    sent_size += sent;
}

MeshStreamBuilder::~MeshStreamBuilder() {
    if (cache_fill) {
        controller.router.write_data_stream_bytes(dst_addr, sent_size, cache, cache_fill, true, stream_id,
                                                  stream_size, MeshController::DEFAULT_TTL, controller.self_addr);
    }
    free(cache);
}
