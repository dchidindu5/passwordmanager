// written by dennis
// for linux and mac
#include <iostream>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
using namespace std;

void getIPandMAC(const char* iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("Socket failed");
        return;
    }

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ);

    // Get IP Address
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
        std::cout << "Interface:    " << iface << std::endl;
        std::cout << "IP Address:   " << inet_ntoa(ipaddr->sin_addr) << std::endl;
    } else {
        perror("Failed to get IP address");
    }

    // Get MAC Address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        std::cout << "MAC Address:  ";
        for (int i = 0; i < 6; i++) {
            printf("%02X", mac[i]);
            if (i < 5) std::cout << ":";
        }
        std::cout << std::endl;
    } else {
        perror("Failed to get MAC address");
    }

    close(fd);
}

int main() {
    // Replace "eth0" with your actual interface, like "wlan0" or use `ip a` to find out
    getIPandMAC("eth0");
    getIPandMAC("wlan0");
    return 0;
}