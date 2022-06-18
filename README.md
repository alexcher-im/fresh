# Fresh

A cross-interface & cross-platform mesh network with support of microcontrollers.
Primarily, intended to work in small networks (not larger than about 100-200 devices).

Currently, supports:
* Broadcasts
* Unicasts
* Route discovery
* Stream fragmentation/defragmentation
* Packet retransmission
* Multi-MTU support (reshaping transit streams to lower-mtu interfaces, but not in reverse)
* Insecure interfaces
* Combination of both secure and insecure interfaces on the same device
* Cross-platforming

Needs to be done:
* Removing devices and fixing routes
* Encryption (only authentication is implemented now)
* Proper synchronization to prevent data races

Task tracking is done via `todo`/`fixme` comments in the code.

For more details about the protocol, check [mesh_protocol.h](main/mesh_protocol.h).


## Usage (C++)

### Including (as library)
Clone a repo to your project's component directory and add `fresh` to 
`REQUIRES` or `PRIV_REQUIRES` in `idf_component_register()`.

For more information about ESP-IDF components, check 
[ESP-IDF Build System](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html).

### Code
```c++
#include "mesh_controller.h"
#include "interfaces/wifi_esp_now_interface.h"


void app_main() {
    // it's better to not create interfaces and controller on stack because they can take up much memory
    auto wifi_interface = new WifiEspNowMeshInterface();
    auto controller = new MeshController("network name", wifi_interface->derive_far_addr_uint32());
    
    // packet callback
    controller->user_stream_handler = [controller](MeshProto::far_addr_t src_addr, const ubyte* data, ushort size) {
        printf("Hello packet!\n");

        // sending response. builders are used to send large amount of data using many small chunks
        const char response_data[] = "hello!";
        MeshStreamBuilder builder(*controller, src_addr, sizeof(response_data));
        builder.write(response_data, sizeof(response_data));
    };
    
    // setting up mesh controller
    controller->set_psk_password("network pass"); // make sure to call this before any .add_interface()
    controller->add_interface(wifi_interface);
    
    vTaskDelay(-1);
}

```
