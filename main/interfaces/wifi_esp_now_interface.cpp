#undef NDEBUG

#include "wifi_esp_now_interface.h"
#include <esp_wifi.h>
#include <esp_now.h>
#include <cstring>
#include <nvs_flash.h>
#include "../hashes.h"
#include "net_utils.h"


using namespace NsWifiEspNowInterface;
using namespace MeshProto;


DRAM_ATTR static const ubyte BROADCAST_MAC[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static xQueueHandle global_rx_queue_handle = 0;


struct RequestQueueData
{
    ubyte mac[6];
    ubyte size;
    MeshPacket* payload;
};


static void recv_callback(const ubyte* mac, const ubyte* data, int data_size) {
    if (mac == NULL || data == NULL || data_size < 0) {
        printf("esp-now: data error in recv callback\n");
        return;
    }
    // todo handle too-long unavailability of queue/memory

    RequestQueueData push_data;
    while (!(push_data.payload = (MeshPacket*) malloc(data_size)))
        vTaskDelay(1);
    push_data.size = data_size;
    memcpy(push_data.payload, data, data_size);
    memcpy(push_data.mac, mac, 6);

    while (xQueueSend(global_rx_queue_handle, &push_data, 1) != pdTRUE)// == errQUEUE_FULL)
        vTaskDelay(1);
}

static void send_callback(const ubyte* mac_addr, esp_now_send_status_t status) {
    //
}


bool EspNowPeerManager::add_peer(const ubyte* mac, ubyte channel) {
    esp_now_peer_info_t peer{};
    peer.channel = channel;
    memcpy(peer.peer_addr, mac, 6);

    auto ret = esp_now_add_peer(&peer);
    return ret == ESP_OK || ret == ESP_ERR_ESPNOW_EXIST;
}

bool EspNowPeerManager::remove_peer(const ubyte* mac) {
    auto ret = esp_now_del_peer(mac);
    return ret == ESP_OK;
}


WifiEspNowMeshInterface::WifiEspNowMeshInterface() {
    // todo move all initialization to another global state (is flash initialized, is netif initialized, and so on)
    // init wifi
    ESP_ERROR_CHECK(nvs_flash_init());

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR));
    //ESP_ERROR_CHECK(esp_wifi_config_espnow_rate(WIFI_IF_STA, WIFI_PHY_RATE_MCS4_LGI));
    ESP_ERROR_CHECK(esp_wifi_start());

    // init esp-now
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_send_cb(send_callback));
    ESP_ERROR_CHECK(esp_now_register_recv_cb(recv_callback));

    // setting self mac
    esp_wifi_get_mac(WIFI_IF_STA, self_addr.raw);

    peer_manager.add_peer(BROADCAST_MAC, 0);
    rx_queue = xQueueCreate(MAX_QUEUED_RX_PACKETS, sizeof(RequestQueueData));
    global_rx_queue_handle = rx_queue;
}

void WifiEspNowMeshInterface::check_packets() {
    RequestQueueData data;

    while (xQueueReceive(rx_queue, &data, 0) == pdTRUE) {
        printf("queue received a packet\n");
        auto packet = data.payload;

        if (self_addr == data.mac)
            goto packet_end;

        if (net_load(packet->type) == MeshPacketType::NEAR_HELLO_INIT) {
            // packet size check
            printf("packet size check: got %d\n", data.size);
            if ((ubyte*) ((MacAddr*) packet->near_hello_init.interface_payload + 1) - (ubyte*) packet > data.size)
                goto packet_end;

            printf("packet addr check\n");
            if (net_load(*(MacAddr*)packet->near_hello_init.interface_payload) != self_addr)
                goto packet_end;
            data.size -= sizeof(MacAddr);
        }

        controller->on_packet(id, (MeshPhyAddrPtr) data.mac, packet, data.size);

        packet_end:
        free(packet);
    }
}

bool WifiEspNowMeshInterface::accept_near_packet(MeshPhyAddrPtr phy_addr, const MeshPacket* packet, uint size) {
    if (net_load(packet->type) == MeshPacketType::NEAR_HELLO) {
        return peer_manager.add_peer((ubyte*) phy_addr, 1);
    }
    if (net_load(packet->type) == MeshPacketType::NEAR_HELLO_INIT) {
        return peer_manager.add_peer((ubyte*) phy_addr, 1);
    }
    return true;
}

MeshPacket* WifiEspNowMeshInterface::alloc_near_packet(MeshPacketType type, uint size) {
    if (type == MeshPacketType::NEAR_HELLO_INIT)
        size += sizeof(MacAddr);
    auto mem = (MeshPacket*) malloc(size);
    net_store(mem->type, type);
    return mem;
}

MeshPacket* WifiEspNowMeshInterface::realloc_near_packet(MeshPacket* packet, MeshPacketType old_type,
                                                         MeshPacketType new_type, uint new_size) {
    if (new_type == MeshPacketType::NEAR_HELLO_INIT) {
        new_size += sizeof(MacAddr);
    }
    return (MeshPacket*) realloc(packet, new_size);
}

void WifiEspNowMeshInterface::free_near_packet(MeshPacket* packet) {
    free(packet);
}

void WifiEspNowMeshInterface::send_packet(MeshPhyAddrPtr phy_addr, const MeshProto::MeshPacket* packet, uint size) {
    if (net_load(packet->type) == MeshPacketType::NEAR_HELLO_INIT) {
        size += sizeof(MacAddr);
        net_memcpy((MacAddr*) packet->near_hello_init.interface_payload, phy_addr, sizeof(MacAddr));
        phy_addr = (MeshPhyAddrPtr) BROADCAST_MAC;
        printf("hello init broadcast sent (size=%d)\n", size);
    }
    else {
        printf("unicast sent (type=%d, size=%d)\n", (int) packet->type, size);
    }

    // todo make a while-loop for sending and waiting
    ESP_ERROR_CHECK(esp_now_send((ubyte*) phy_addr, (ubyte*) packet, size));
}

MeshInterfaceProps WifiEspNowMeshInterface::get_props() {
    return {(MeshInterfaceSessionManager*) &session_manager, FAR_MTU, sizeof(MacAddr), true};
}

WifiEspNowMeshInterface::~WifiEspNowMeshInterface() {
    global_rx_queue_handle = 0;
    vQueueDelete(rx_queue);
    esp_now_deinit();
    esp_wifi_deinit();
    esp_netif_deinit();
}

far_addr_t WifiEspNowMeshInterface::derive_far_addr_uint32() {
    far_addr_t addr_output{};
    uint hash_output;
    crc32(self_addr.raw, 6, (ubyte*) &hash_output);
    memcpy(&addr_output, &hash_output, std::min(sizeof(uint), sizeof(far_addr_t)));
    return addr_output;
}

void WifiEspNowMeshInterface::send_hello(MeshPhyAddrPtr phy_addr) {
    if (phy_addr == nullptr)
        phy_addr = (MeshPhyAddrPtr) BROADCAST_MAC;

    auto packet = (MeshPacket*) alloca(MESH_CALC_SIZE(near_hello_secure));
    net_store(packet->type, MeshPacketType::NEAR_HELLO);
    memcpy(packet->near_hello_secure.network_name, controller->network_name, sizeof(controller->network_name));

    send_packet(phy_addr, packet, MESH_CALC_SIZE(near_hello_secure));
}

void WifiEspNowMeshInterface::write_addr_bytes(MeshPhyAddrPtr phy_addr, void* out_buf) {
    memcpy(out_buf, phy_addr, sizeof(MacAddr));
}
