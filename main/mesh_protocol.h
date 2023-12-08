#pragma once

#include "strong_type.h"
#include "blob_types.h"

#include <cstring>
#include <functional>


#pragma pack(push, 1)

namespace MeshProto
{
    // must be able to authorize devices into the current network
    // must be able to place multiple disjoint networks near each other
    // must be able to encrypt all transferring data streams with pre-shared key
    // must be able to provide a uniformed and cross-interface address, unique and sole to a physical device
    // must be able to protect against spoofing, replay attacks

    // regular versions

    // todo name types in CamelCase
    DEFINE_LOOSE_STRONG_TYPE(far_addr_t, uint, CDS_EQ() CDS_ICONV_INT() CDS_DEF_CTOR(far_addr_t));

    using hashdigest_t = uint;
    using nonce_t = u64; // ubyte[8]
    using session_key_t = u64; // ubyte[8]
    using timestamp_t = u64;
    using stream_id_t = ubyte;

    // serialized versions
    using ser_hashdigest_t   = BlobType<hashdigest_t,  std::endian::little>;
    using ser_nonce_t        = BlobType<nonce_t,       std::endian::little>;
    using ser_session_key_t  = BlobType<session_key_t, std::endian::little>;
    using ser_timestamp_t    = BlobType<timestamp_t,   std::endian::little>;
    using ser_far_addr_t     = BlobType<far_addr_t,    std::endian::little>;
    using ser_stream_id_t    = BlobType<stream_id_t,   std::endian::little>;

    static_assert(sizeof(far_addr_t) == sizeof(ser_far_addr_t));


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
        // a far data packet without far packet headers, directed to the RX device
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
        u8le network_name[16];
        ubyte interface_payload[0];
    };

    // response to HELLO packet, from network member to client
    // initiates a secure session establishment
    struct PacketNearHelloInit
    {
        ser_nonce_t member_nonce; // this does not require any signing/protection
        ubyte interface_payload[0];
    };

    // response to HELLO_INIT packet, from client to network member
    // informs a network member that client knows the PSK
    // also sends its timestamp (packet id) and declares current session key
    // all fields must be signed to ensure this packet is not MITM-ed and selectively changed
    struct PacketNearHelloAuthorize
    {
        ser_session_key_t session_key;
        ser_timestamp_t initial_timestamp;
        ser_far_addr_t self_far_addr;
        ser_hashdigest_t hash; // packet sign with PSK (hash of all fields, concatenated with PSK)
        ubyte interface_payload[0];
    };

    // response to HELLO_AUTHORIZE packet, from network member to client
    // informs a client that authorization succeeded, also proves that network member knows the PSK as well
    // also send its timestamp to finish session establishment
    // all fields must be signed to ensure this packet is not MITM-ed and selectively changed
    struct PacketNearHelloJoinedSecure
    {
        ser_timestamp_t initial_timestamp;
        ser_far_addr_t self_far_addr;
        ser_hashdigest_t hash; // packet sign with PSK+session_key
        ubyte interface_payload[0];
    };

    // insecure mesh join
    struct PacketNearHelloInsecure
    {
        u8le network_name[16];
        ser_far_addr_t self_far_addr;
        ubyte interface_payload[0];
    };

    struct PacketNearHelloJoinedInsecure
    {
        ser_far_addr_t self_far_addr;
        ubyte interface_payload[0];
    };

    // other packets
    struct PacketFarPing
    {
        u8le routers_passed;
        // mtu discovery data:
        u8le router_num_with_min_mtu;
        u32le min_mtu;
    };

    struct PacketFarPingResponse : public PacketFarPing
    {
        //
    };

    struct PacketFarDataFirst
    {
        ser_stream_id_t stream_id;
        u16le stream_size;
        ubyte payload[0];
    };

    struct PacketFarDataPart8
    {
        ser_stream_id_t stream_id;
        u16le offset;
        ubyte payload[0];
    };

    union DataStream
    {
        PacketFarDataFirst first;
        PacketFarDataPart8 part_8;
        //PacketFarDataPart16 part_16;
    };

    struct MessageSign
    {
        ser_timestamp_t timestamp;
        ser_session_key_t session_key;
        ser_hashdigest_t hash;
    };

    struct MeshPacket
    {
        MeshPacketType type;

        union {
            u8le near_packets[0];

            // near:
            PacketNearHelloSecure near_hello_secure;
            PacketNearHelloInit near_hello_init;
            PacketNearHelloAuthorize near_hello_authorize;
            PacketNearHelloJoinedSecure near_hello_joined_secure;

            PacketNearHelloInsecure near_hello_insecure;
            PacketNearHelloJoinedInsecure near_hello_joined_insecure;

            // optimized far:
            DataStream opt_data;

            // far:
            struct {
                u8le ttl;
                ser_far_addr_t src_addr;
                ser_far_addr_t dst_addr;

                union {
                    PacketFarPing ping;
                    PacketFarPingResponse ping_response;

                    DataStream data; // including broadcasts
                };
            } far;
        };

        MeshPacket() = delete;
    };

#define MESH_CALC_SIZE(field_name) (uint) (uintptr_t) (&((::MeshProto::MeshPacket*) nullptr)->field_name + 1)
#define MESH_FIELD_ACCESSIBLE(field_name, size) ((uintptr_t) (&((::MeshProto::MeshPacket*) nullptr)->field_name + 1) <= (size))
#define MESH_SECURE_PACKET_OVERHEAD (sizeof(MessageSign))
}

#pragma pack(pop)


ODS_STD_HASH(MeshProto::far_addr_t)
