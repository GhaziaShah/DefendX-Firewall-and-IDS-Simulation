#include "Firewall.h"
#include <fstream>
#include <iostream>
#include <algorithm>

Firewall::Firewall() {
    std::cout << "Firewall Initialized Successfully." << std::endl;
}

std::string Firewall::getCurrentTime() const { return ::getCurrentTime(); }

void Firewall::logResult(const FirewallLog& log) {
    std::cout << log.result << " -----> " << log.ip
              << " on port " << log.port
              << " using " << log.protocol << std::endl;
    std::ofstream out("firewall_logs.txt", std::ios::app);
    if (out.is_open()) {
        out << "[" << log.timestamp << "] " << log.result
            << " -----> " << log.ip << " on port " << log.port
            << " using " << log.protocol << "\n";
    }
}

bool Firewall::addRule(const std::string& ip, const std::string& action, int port, const std::string& protocol) {
    if (!isValidIP(ip) || !isValidPort(port) || !isValidProtocol(protocol)) return false;
    std::string act = action;
    std::transform(act.begin(), act.end(), act.begin(), ::toupper);
    if (act != "ALLOW" && act != "BLOCK") return false;
    ruleTable[ip].push_back({act, port, protocol});
    std::cout << "[RULE ADDED] " << act << " " << ip << " " << port << " " << protocol << std::endl;
    return true;
}

void Firewall::loadRulesFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;
    std::string action, ip, protocol; int port;
    while (file >> action >> ip >> port >> protocol) {
        addRule(ip, action, port, protocol);
    }
    file.close();
}

void Firewall::addBlockRule(const std::string& ip) {
    if (!isValidIP(ip)) return;
    auto it = ruleTable.find(ip);
    bool alreadyBlocked = false;
    if (it != ruleTable.end()) {
        for (auto &r : it->second) if (r.action == "BLOCK") alreadyBlocked = true;
    }
    if (alreadyBlocked) return;
    ruleTable[ip].push_back({"BLOCK",0,"ANY"});
    FirewallLog flog = { getCurrentTime(), "Blocked (auto-blacklist)", ip, 0, "ANY" };
    logs.push_back(flog);
    logResult(flog);
}

void Firewall::removeRulesForIP(const std::string& ip) {
    ruleTable.erase(ip);
    saveRulesToFile("firewall_rules.txt");
}

void Firewall::saveRulesToFile(const std::string& filename) const {
    std::ofstream out(filename);
    for (const auto &kv : ruleTable)
        for (const auto &r : kv.second)
            out << r.action << " " << kv.first << " " << r.port << " " << r.protocol << "\n";
}

std::vector<std::pair<std::string, FirewallRule>> Firewall::listRules() const {
    std::vector<std::pair<std::string, FirewallRule>> out;
    for (const auto &kv : ruleTable)
        for (const auto &r : kv.second) out.emplace_back(kv.first,r);
    return out;
}

std::string Firewall::checkPacket(const Packet& p) {
    if (!isValidIP(p.srcIP) || !isValidIP(p.destIP) || !isValidPort(p.port) || !isValidProtocol(p.protocol)) return "Blocked";
    std::string result = "Allowed";
    auto it = ruleTable.find(p.destIP);
    if (it != ruleTable.end()) {
        for (auto &rule : it->second) {
            if ((rule.port == p.port || rule.port == 0) &&
                (rule.protocol == p.protocol || rule.protocol == "ANY")) {
                result = (rule.action == "ALLOW") ? "Allowed" : "Blocked";
            }
        }
    }
    FirewallLog log = {getCurrentTime(), result, p.destIP, p.port, p.protocol};
    logs.push_back(log);
    logResult(log);
    return result;
}

void Firewall::displayLogs() const {
    for (auto& log : logs) std::cout << "[" << log.timestamp << "] " << log.result
                                      << " -----> " << log.ip << " on port " << log.port
                                      << " using " << log.protocol << "\n";
}

void Firewall::saveLogsToFile(const std::string& filename) const {
    std::ofstream out(filename, std::ios::app);
    for (auto& log : logs)
        out << "[" << log.timestamp << "] " << log.result
            << " -----> " << log.ip << " on port " << log.port
            << " using " << log.protocol << "\n";
}

std::vector<std::string> Firewall::getBlockedIPs() const {
    std::vector<std::string> blocked;
    for (auto& kv : ruleTable)
        for (auto& r : kv.second)
            if (r.action == "BLOCK") { blocked.push_back(kv.first); break; }
    return blocked;
}

