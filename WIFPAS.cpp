#include <iostream>
#include <vector>
#include <string>
#include <windows.h>

std::string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        _pclose(pipe);
        throw;
    }
    _pclose(pipe);
    return result;
}

std::vector<std::string> getWifiProfiles() {
    std::vector<std::string> profiles;
    std::string cmd = "netsh wlan show profiles";
    std::string result = exec(cmd.c_str());

    std::string::size_type pos = 0;
    std::string key = "All User Profile     : ";
    while ((pos = result.find(key, pos)) != std::string::npos) {
        pos += key.length();
        std::string::size_type end = result.find("\n", pos);
        profiles.push_back(result.substr(pos, end - pos));
    }
    return profiles;
}
std::string getWifiPassword(const std::string& profile) {
    std::string cmd = "netsh wlan show profile name=\"" + profile + "\" key=clear";
    std::string result = exec(cmd.c_str());

    std::string::size_type pos = result.find("Key Content            : ");
    if (pos != std::string::npos) {
        pos += std::string("Key Content            : ").length();
        std::string::size_type end = result.find("\n", pos);
        return result.substr(pos, end - pos);
    }
    return "N/A";
}
int main() {
    std::vector<std::string> profiles = getWifiProfiles();

    std::cout << "WiFi Profiles and Passwords:" << std::endl;
    for (const auto& profile : profiles) {
        std::string password = getWifiPassword(profile);
        std::cout << "Profile: " << profile << std::endl;
        std::cout << "Password: " << password << std::endl;
        std::cout << "--------------------------" << std::endl;
    }

    return 0;
}
