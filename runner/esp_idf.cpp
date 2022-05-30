#include <cstdio>
#include "platform/api.h"
#include "mesh_controller.h"
#include "wifi_esp_now_interface.h"
#include "mesh_stream_builder.h"

using namespace MeshProto;


extern "C" void app_main() {
    auto wifi_interface = new WifiEspNowMeshInterface();
    auto controller = new MeshController("dev net", wifi_interface->derive_far_addr_uint32());
    controller->set_psk_password("dev network");
    controller->user_stream_handler = [](...) {};
    controller->add_interface(wifi_interface);

    printf("mesh started; sizeof(MeshController)=%d\n", (int) sizeof(MeshController));

    if (Os::random_u32() % 3 == 0) {
        printf("will send a data packet!\n");
        Os::sleep_milliseconds(5000);
        printf("sending a data packet\n");
        fflush(stdout);

        far_addr_t dst_addr = 0;
        for (auto& [far, peer] : controller->router.peers)
            dst_addr = far;
        dst_addr = BROADCAST_FAR_ADDR;

        auto lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus sodales euismod dolor. Maecenas "
                     "condimentum erat urna, vel consequat arcu hendrerit sit amet. Curabitur justo nunc, euismod id "
                     "nisi a, tincidunt eleifend ante. Vestibulum nec justo vel nisi consequat condimentum. Curabitur "
                     "nec nulla ac orci tempus commodo. Donec molestie euismod ante, in efficitur lorem posuere et. "
                     "Curabitur euismod eleifend lectus et vestibulum. Nunc non mauris id leo tristique sollicitudin "
                     "a eget turpis.";

        MeshStreamBuilder builder(*controller, dst_addr, strlen(lorem) + 1);
        builder.write((ubyte*) lorem, strlen(lorem) + 1);
    }

    if (Os::random_u32() % 3 == 0) {
        printf("will send a 70-byte data garbage!\n");
        Os::sleep_milliseconds(5000);
        printf("sending a data packet\n");
        fflush(stdout);

        auto packet = (MeshPacket*) malloc(MESH_CALC_SIZE(far_data) + MESH_SECURE_PACKET_OVERHEAD + 70);
        packet->type = MeshPacketType::FAR_DATA_FIRST;
        packet->src_addr = controller->self_addr;
        for (auto& [far, peer] : controller->router.peers)
            packet->dst_addr = far;
        packet->far_data.first.stream_size = 70;
        controller->router.send_packet(packet, MESH_CALC_SIZE(far_data) + 70,
                                       MESH_CALC_SIZE(far_data) + MESH_SECURE_PACKET_OVERHEAD + 70);
        free(packet);
    }

    for (;;)
        Os::sleep_ticks(-1);
}
