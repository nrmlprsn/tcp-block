#pragma once

#include <cstring>
#include <stdint.h>
#include <arpa/inet.h>
#include <string>

struct Mac{
        static constexpr int Size = 6;
        uint8_t mac[Size];

        // constructor
        Mac(){}
        Mac(const uint8_t* r) {memcpy(this->mac, r, Size);}
        Mac(const std::string& r);

        // assign operator
        Mac& operator = (const Mac& r){memcpy(this->mac, r.mac, Size);return *this;}

        // bool operator
        bool operator == (const Mac& r) const{return memcmp(mac, r.mac, Size) == 0;}
        bool operator != (const Mac& r) const{return memcmp(mac, r.mac, Size) != 0;}

        static Mac get_mac(const std::string& iface);
};

struct Ip{
        static const int Size = 4;
        uint32_t ip;

        // constructor
        Ip(){}
        Ip(const uint32_t r) : ip(r){}
        Ip(const std::string r);

        // bool operator
        bool operator == (const Ip& r) const{return ip == r.ip;}

        static Ip get_ip(const std::string& iface);
};

#pragma pack(push, 1)
typedef struct{
        Mac dmac;
        Mac smac;
        uint16_t type;

        // type
        enum: uint16_t {
                IP4 = 0x0800,
                ARP = 0x0806,
                IP6 = 0x86DD
        };
}eth_hdr;

typedef struct{
        uint16_t htype;
        uint16_t ptype;
        uint8_t hlen;
        uint8_t plen;
        uint16_t op;
        Mac smac;
        Ip sip;
        Mac tmac;
        Ip tip;

        // htype
        enum: uint16_t {
                NETROM = 0,
                ETHER = 1,
                EETHER = 2,
                AX25 = 3,
                PRONET = 4,
                CHAOS = 5,
                IEEE802 = 6,
                ARCNET = 7,
                APPLETLK = 8,
                LANSTAR = 9,
                DLCI = 15,
                ATM = 19,
                METRICOM = 23,
                IPSEC = 31
        };

        // op
        enum: uint16_t {
                Request = 1,
                Reply = 2,
                RevRequest = 3,
                RevReply = 4,
                InvRequest = 8,
                InvReply = 9
        };
}arp_hdr;

typedef struct{
        uint8_t v_hl;
        uint8_t tos;
        uint16_t len;
        uint16_t id;
        uint16_t off;
        uint8_t ttl;
        uint8_t p;
        uint16_t sum;
        uint32_t sip;
        uint32_t dip;

        enum: uint8_t {
                TCP = 6,
                UDP = 17
        };

        uint8_t version() const { return v_hl >> 4; }
        uint8_t hl() const { return (v_hl & 0x0F) * 4; }
}ip_hdr;

typedef struct{
        uint16_t sport;
        uint16_t dport;
        uint32_t seq;
        uint32_t ack;
        uint8_t off_rsv;
        uint8_t flags;
        uint16_t win;
        uint16_t sum;
        uint16_t urp;

        enum: uint8_t {
                FIN = 0x01,
                SYN = 0x02,
                RST = 0x04,
                PSH = 0x08,
                ACK = 0x10,
                URG = 0x20
        };

        uint8_t off() const { return (off_rsv >> 4) * 4; }
}tcp_hdr;
#pragma pack(pop)

