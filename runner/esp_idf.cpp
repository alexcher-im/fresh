#include "platform/api.h"
#include "mesh_controller.h"
#include "wifi_esp_now_interface.h"
#include "p2p_unsecured_short_interface.h"
#include "mesh_stream_builder.h"
#include "platform/p2p/esp32_uart_stdout_p2p.h"
#include "platform/p2p/stdio_p2p.h"

#include <cstdio>


using namespace MeshProto;


extern "C" void app_main() {
    auto wifi_interface = new WifiEspNowMeshInterface();
    auto controller = new MeshController("dev net", wifi_interface->derive_far_addr_uint32());
    controller->set_psk_password("dev network");
    controller->user_stream_handler = [](MeshProto::far_addr_t src_addr, const ubyte* data, ushort size) {
        printf("%s\n", data);
        fflush(stdout);
    };
    controller->add_interface(wifi_interface);

    StdioSerial serial_in(stdin);
    Esp32UartSerialOut serial_out;
    auto uart_interface = new P2PUnsecuredShortInterface(false, true, serial_in, serial_out);
    controller->add_interface(uart_interface);

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

        auto packet = (MeshPacket*) malloc(MESH_CALC_SIZE(far.data) + MESH_SECURE_PACKET_OVERHEAD + 70);
        packet->type = MeshPacketType::FAR_DATA_FIRST;
        packet->far.src_addr = controller->self_addr;
        for (auto& [far, peer] : controller->router.peers)
            packet->far.dst_addr = far;
        packet->far.data.first.stream_size = 70;
        controller->router.send_packet(packet, MESH_CALC_SIZE(far.data) + 70,
                                       MESH_CALC_SIZE(far.data) + MESH_SECURE_PACKET_OVERHEAD + 70);
        free(packet);
    }

    for (;;)
        Os::sleep_ticks(-1);
}
