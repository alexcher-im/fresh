#pragma once

#include <cstring>
#include "types.h"


#pragma pack(push, 1)

namespace MeshProto
{
    // must be able to authorize devices into the current network
    // must be able to place multiple disjoint networks near each other
    // must be able to encrypt all transferring data streams with pre-shared key
    // must be able to provide a uniformed and cross-interface address, unique and sole to a physical device
    // must be able to protect against spoofing, replay attacks

    typedef uint hashdigest_t;
    typedef ubyte nonce_t[8];
    typedef ubyte session_key_t[8];
    typedef u64 timestamp_t;
    typedef uint far_addr_t;

    const far_addr_t BROADCAST_FAR_ADDR = -1;

    enum class MeshPacketType : ubyte
    {
        UNKNOWN = 0,

        // todo make different packet types for encrypted and unencrypted streams
        // they are needed when packet initially encrypted sent in untrusted environment and later arrived to destination
        // through trusted environment (that does not require encryption)

        // todo add a special 2-bit payload for data packets in their types

        // a unicast far packet
        FAR_DATA_FIRST,
        FAR_DATA_PART,
        // a broadcast far packet
        BROADCAST_DATA_FIRST,
        BROADCAST_DATA_PART,
        // an optimized far data packet, so it does not contain any far headers and is directed to the RX device
        FAR_OPTIMIZED_DATA_FIRST,
        FAR_OPTIMIZED_DATA_PART,

        // must always be a far unicast packet (src+dst addr, ttl)
        FAR_PING,
        FAR_PING_RESPONSE,

        // similar to above, but does not create a route (except for cases when this packet cannot be
        // delivered because of unknown route)
        FAR_PING_NOROUTE,
        FAR_PING_NOROUTE_RESPONSE,

        FIRST_NEAR_PACKET_NUM = 100,

        NEAR_PACKET_0,
        NEAR_PACKET_1,
        NEAR_PACKET_2,
        NEAR_PACKET_3,
        NEAR_PACKET_4,
        NEAR_PACKET_5,
        NEAR_PACKET_6,
        NEAR_PACKET_7,

        NEAR_HELLO,
        NEAR_HELLO_INIT,
        HEAR_HELLO_AUTHORIZE,
        NEAR_HELLO_JOINED
    };

    // secure features overview:
    //
    // secure features are used in untrusted environments such as WI-FI or Bluetooth radio where it's
    // possible for attacker to listen, send, spoof and MITM all transferring data.
    // the protection is based on pre-shared key (PSK): a common secret key all network members must know.
    //
    // a 4-way secure session establishment procedure is used to authorize new client into existing network.
    // after the session establishment, client (the device desiring to join) and network member (client's opponent)
    // both have the same randomly-generated non-secret session key and opponent's timestamp
    // both of which will be used to sign all packet headers and required to protect against replay attacks.
    // encryption is only used in data streams, and they are only decrypted at the destination device
    // however, each retransmitted packet must be independently signed for the next device in routing chain
    //
    // packet signature is represented as a hash digest of concatenated values
    // (packet (without signature bytes) + packet length + timestamp + PSK + session key) placed at the end of the packet
    // including a PSK helps to protect against spoofed packets from attacker (he does not know PSK to create a valid sign)
    // including a session key helps to protect against replay attacks with packets captured within another session
    // including a timestamp helps to protect against replay attacks with packets captured within this session
    // timestamps are exchanged during session establishment and new timestamps included in each signed packet:
    //  the new timestamp must always be greater than the timestamp from previous packet the current device sent in this session
    // timestamps of current device are only used for sending packets, and not for receiving

    // secure mesh join
    // broadcasting this packet to make nearby network members suggest you to join
    struct PacketNearHelloSecure
    {
        ubyte network_name[16];
        ubyte interface_payload[0];
    };// __attribute__((packed));

    // response to HELLO packet, from network member to client
    // initiates a secure session establishment
    struct PacketNearHelloInit
    {
        nonce_t member_nonce; // this does not require any signing/protection
        ubyte interface_payload[0];
    } __attribute__((packed));

    // response to HELLO_INIT packet, from client to network member
    // informs a network member that client knows the PSK
    // also sends its timestamp (packet id) and declares current session key
    // all fields must be signed to ensure this packet is not MITM-ed and selectively changed
    struct PacketNearHelloAuthorize
    {
        session_key_t session_key;
        timestamp_t initial_timestamp;
        far_addr_t self_far_addr;
        hashdigest_t hash; // packet sign with PSK (hash of all fields, concatenated with PSK)
        ubyte interface_payload[0];
    } __attribute__((packed));

    // response to HELLO_AUTHORIZE packet, from network member to client
    // informs a client that authorization succeeded, also proves that network member knows the PSK as well
    // also send its timestamp to finish session establishment
    // all fields must be signed to ensure this packet is not MITM-ed and selectively changed
    struct PacketNearHelloJoinedSecure
    {
        timestamp_t initial_timestamp;
        far_addr_t self_far_addr;
        hashdigest_t hash; // packet sign with PSK+session_key
        ubyte interface_payload[0];
    } __attribute__((packed));

    // insecure mesh join
    struct PacketNearHelloInsecure
    {
        ubyte network_name[16];
        far_addr_t self_far_addr;
        ubyte interface_payload[0];
    } __attribute__((packed));

    struct PacketNearHelloJoinedInsecure
    {
        far_addr_t self_far_addr;
        ubyte interface_payload[0];
    } __attribute__((packed));

    // other packets
    struct PacketFarPing
    {
        ubyte routers_passed;
        // mtu discovery data:
        ubyte router_num_with_min_mtu;
        ushort min_mtu;
    } __attribute__((packed));

    struct PacketFarPingResponse : public PacketFarPing
    {
        //
    } __attribute__((packed));

    struct PacketFarDataFirst
    {
        ubyte stream_id;
        ushort stream_size;
        ubyte payload[0];
    } __attribute__((packed));

    struct PacketFarDataPart8
    {
        ubyte stream_id;
        ushort offset;
        ubyte payload[0];
    } __attribute__((packed));

    struct PacketFarDataPart16
    {
        ubyte stream_id;
        ushort offset;
        ubyte payload[0];
    } __attribute__((packed));

    union DataStream
    {
        PacketFarDataFirst first;
        PacketFarDataPart8 part_8;
        //PacketFarDataPart16 part_16;
    } __attribute__((packed));

    struct MessageSign
    {
        timestamp_t timestamp;
        session_key_t session_key;
        hashdigest_t hash;
    } __attribute__((packed));

    struct MeshPacket
    {
        MeshPacketType type;

        union {
            // near:
            PacketNearHelloSecure near_hello_secure;
            PacketNearHelloInit near_hello_init;
            PacketNearHelloAuthorize near_hello_authorize;
            PacketNearHelloJoinedSecure near_hello_joined_secure;

            PacketNearHelloInsecure near_hello_insecure;
            PacketNearHelloJoinedInsecure near_hello_joined_insecure;

            ubyte near_packets[0];

            // optimized far:
            DataStream opt_data;

            // far:
            struct {
                ubyte ttl;
                far_addr_t src_addr;
                far_addr_t dst_addr;

                union {
                    PacketFarPing far_ping;
                    PacketFarPingResponse far_ping_response;

                    DataStream far_data;

                    // broadcast
                    struct {
                        uint broadcast_id;

                        DataStream bc_data;
                    } __attribute__((packed));
                } __attribute__((packed));
            } __attribute__((packed));
        } __attribute__((packed));
    } __attribute__((packed));

#define MESH_CALC_SIZE(field_name) (uint) (uintptr_t) (&((::MeshProto::MeshPacket*) nullptr)->field_name + 1)
#define MESH_FIELD_ACCESSIBLE(field_name, size) ((uintptr_t) (&((::MeshProto::MeshPacket*) nullptr)->field_name + 1) <= (size))
#define MESH_SECURE_PACKET_OVERHEAD (sizeof(MessageSign))

    /*union FarPacket
    {
        PacketFarDataFirst data_first;
        PacketFarDataPart8 data_part_8;
        PacketFarDataPart16 data_part_16;
    };

    struct UnprotectedPacket
    {
        MeshPacketType type;

        union {
            ubyte near_packet[0];
            FarPacket far_unicast;
            struct {
                uint broadcast_id;
                FarPacket far_broadcast;
            };
        };
    };

    struct MeshPacket
    {
        MeshPacketType type;

        union {
            ubyte near_packet[0];
            FarPacket far_unicast;
            struct {
                uint broadcast_id;
                FarPacket far_broadcast;
            };
        };

        struct {
            u64 timestamp;
            mesh_hashdigest_t sign; // crc32 of (headers_len(ubyte), headers, pre-shared key hash, peer nonce, timestamp)
        };
    };*/
}

#pragma pack(pop)


//namespace std {
//    template<>
//    struct hash<std::enable_if<decltype(MeshProto::func(nullptr))::value, MeshProto::far_addr_t>::type> {
//        //
//    }
//}
