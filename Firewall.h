#pragma once
#include "Utility.h"
#include <unordered_map>
#include <vector>
#include <string>

struct Packet {
    std::string srcIP;
    std::string destIP;
    int port;
    std::string protocol;
    std::string payload;
};

struct FirewallRule {
    std::string action;
    int port;
    std::string protocol;
};

struct FirewallLog {
    std::string timestamp;
    std::string result;
    std::string ip;
    int port;
    std::string protocol;
};

class Firewall {
private:
    std::unordered_map<std::string, std::vector<FirewallRule>> ruleTable;
    std::vector<FirewallLog> logs;
    void logResult(const FirewallLog& log);
public:
    Firewall();
    bool addRule(const std::string& ip, const std::string& action, int port, const std::string& protocol);
    void addBlockRule(const std::string& ip);
    void removeRulesForIP(const std::string& ip);
    void loadRulesFromFile(const std::string& filename);
    void saveRulesToFile(const std::string& filename) const;
    std::string checkPacket(const Packet& p);
    std::vector<std::string> getBlockedIPs() const;
    std::vector<std::pair<std::string, FirewallRule>> listRules() const;
    void displayLogs() const;
    void saveLogsToFile(const std::string& filename) const;
};
