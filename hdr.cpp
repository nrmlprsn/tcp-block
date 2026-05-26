#include "hdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <arpa/inet.h>

Mac::Mac(const std::string& r){
        std::string s;
        for(char ch:r){
                if((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
                        s += ch;
        }
        int res = sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if(res != Size){
                fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
                return;
        }
}

Mac Mac::get_mac(const std::string& iface){
        Mac result;

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(fd<0) return result;

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);

        if(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0){
                memcpy(result.mac, ifr.ifr_hwaddr.sa_data, 6);
        }

        close(fd);
        return result;
}

Ip::Ip(const std::string r) {
        unsigned int a, b, c, d;
        int res = sscanf(r.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
        if (res != Size) {
                fprintf(stderr, "Ip::Ip sscanf return %d r=%s\n", res, r.c_str());
                return;
        }
        ip = (a << 24) | (b << 16) | (c << 8) | d;
}

Ip Ip::get_ip(const std::string& iface){
        Ip result;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(fd<0) return result;

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);

        if(ioctl(fd, SIOCGIFADDR, &ifr) == 0){
                struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
                result.ip = ntohl(sin->sin_addr.s_addr);
        }

        close(fd);
        return result;
}

