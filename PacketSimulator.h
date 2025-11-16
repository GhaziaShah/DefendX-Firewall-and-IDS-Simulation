#pragma once
#include "Firewall.h"
#include "IDS.h"
#include <vector>
#include <random>

class PacketSimulator {
private:
    Firewall* firewall;
    IDS* ids;
    std::vector<std::string> maliciousPayloads;
    std::vector<std::string> safePayloads;
    std::mt19937 rng;
public:
    PacketSimulator(Firewall* fw, IDS* idsptr);
    std::string generateRandomIP();
    int generateRandomPort();
    std::string generateRandomProtocol();
    std::string generateRandomPayload();
    std::vector<Packet> generatePackets(int n);
    void runSimulation(int n);
    void printPacketstatus(const Packet& p, const std::string& status);
    void displayProgress(int current, int total);
};
