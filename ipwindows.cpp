#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

void logIPandMAC(const std::string& filename) {
    IP_ADAPTER_INFO adapterInfo[16]; // supports up to 16 adapters
    DWORD bufferSize = sizeof(adapterInfo);
    DWORD status = GetAdaptersInfo(adapterInfo, &bufferSize);

    if (status != ERROR_SUCCESS) {
        std::cerr << "GetAdaptersInfo failed with error: " << status << std::endl;
        return;
    }

    std::ofstream logFile(filename);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file." << std::endl;
        return;
    }

    PIP_ADAPTER_INFO adapter = adapterInfo;
    while (adapter) {
        logFile << "Adapter Name: " << adapter->AdapterName << "\n";
        logFile << "IP Address:   " << adapter->IpAddressList.IpAddress.String << "\n";

        logFile << "MAC Address:  ";
        for (UINT i = 0; i < adapter->AddressLength; ++i) {
            char buffer[4];
            sprintf(buffer, "%02X", adapter->Address[i]);
            logFile << buffer;
            if (i < adapter->AddressLength - 1)
                logFile << "-";
        }
        logFile << "\n";

        // Only log the first adapter. Remove this break to log all.
        break;

        adapter = adapter->Next;
    }

    logFile.close();
    std::cout << "IP and MAC address logged to: " << filename << std::endl;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    logIPandMAC("log.txt");

    WSACleanup();
    return 0;
}
/*
g++ -o ip_mac_logger.exe your_file.cpp -liphlpapi -lws2_32
create a random log file that is being pushed to a custom made github repo after every 1 hr so far as their is internet connectivity only on windows
*/