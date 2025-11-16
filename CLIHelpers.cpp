#include "CLIHelpers.h"
#include <iostream>
#include <string>
using namespace std;

bool hasCommand(int argc, char* argv[], const std::string& command) {
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == command) return true;
    }
    return false;
}
std::string getCommandValue(int argc, char* argv[], const std::string& command) {
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == command && i + 1 < argc) {
            return argv[i + 1];
        }
    }
    return "";
}

// ----------------- Interactive menu (keeps previous features intact) -----------------
void interactiveMenu(Firewall &fw, IDS &ids, PacketSimulator &sim) {
    while (true) {
        cout << "\n=== MENU ===\n"
             << "1) Run demo traffic (the built-in sample set)\n"
             << "2) Run packet simulator (random) - specify number\n"
             << "3) Show firewall logs\n"
             << "4) Show IDS logs\n"
             << "5) Show IDS summary\n"
             << "6) Show auto-blacklisted IPs (IDS)\n"
             << "7) Show firewall rules\n"
             << "8) Add firewall rule\n"
             << "9) Remove all rules for an IP\n"
             << "10) Export IDS logs to file\n"
             << "11) Save firewall rules to file\n"
             << "0) Exit\n"
             << "Choice: ";
        int choice;
        if (!(cin >> choice)) {
            cin.clear();
            string junk;
            getline(cin, junk);
            cout << "Invalid input.\n";
            continue;
        }

        if (choice == 0) break;

        if (choice == 1) {
            // Demo traffic: same as main's sample
            vector<Packet> packets = {
                {"192.168.1.0","10.0.0.1",80,"TCP","Normal traffic data"},
                {"192.168.1.19","10.0.0.2",22,"TCP","Normal traffic data"},
                {"192.168.1.12","10.0.0.3",80,"TCP","Repeated login attempt from same source"},
                {"192.168.1.13","10.0.0.8",80,"TCP","Repeated login attempt from same source"},
                {"192.168.1.13","10.0.0.9",80,"TCP","Repeated login attempt from same source"},
                {"192.168.1.13","10.0.0.10",8080,"TCP","wget http malicious link"},
                {"192.168.1.16","10.0.0.11",443,"TCP","GET /home"},
                {"10.0.0.9","10.0.0.10",53,"UDP","DNS query for example.com"},
                {"192.168.1.13","10.0.0.13",80,"TCP","Normal traffic data"},
                {"192.168.1.15","10.0.0.5",8080,"TCP","wget http malicious link"}
            };
            for (size_t i = 0; i < packets.size(); ++i) {
                cout << "\n[Demo Packet " << i+1 << "] " << packets[i].srcIP << " -> " << packets[i].destIP << endl;
                string decision = fw.checkPacket(packets[i]);
                if (decision == "Blocked") {
                    cout << "[Firewall] Packet blocked. Skipping IDS inspection.\n";
                    continue;
                }
                ids.inspectPacket(packets[i].srcIP, packets[i].destIP, packets[i].payload);
                // check again after IDS auto-block may have added rule
                decision = fw.checkPacket(packets[i]);
                if (decision == "Blocked") cout << "[Firewall] Packet blocked due to IDS auto-blacklist.\n";
            }
        } else if (choice == 2) {
            cout << "How many random packets? ";
            int n;
            cin >> n;
            if (n <= 0) { cout << "Invalid number\n"; continue; }
            sim.runSimulation(n);
        } else if (choice == 3) {
            fw.displayLogs();
        } else if (choice == 4) {
            ids.displayLogs();
        } else if (choice == 5) {
            ids.showSummary();
        } else if (choice == 6) {
            ids.showBlacklistedIPs();
            auto blocked = fw.getBlockedIPs();
            if (!blocked.empty()) {
                cout << "\n--- Firewall blocked IPs (from rules) ---\n";
                for (auto &ip : blocked) cout << ip << "\n";
            }
        } else if (choice == 7) {
            auto rules = fw.listRules();
            cout << "\n--- Firewall Rules ---\n";
            if (rules.empty()) cout << "No rules loaded.\n";
            for (auto &p : rules) {
                cout << p.second.action << " " << p.first << " " << p.second.port << " " << p.second.protocol << "\n";
            }
        } else if (choice == 8) {
        	string ip, action, proto;
    int port;

    cout << "IP: ";
    if (!(cin >> ip) || !isValidIP(ip)) {
        cout << "[ERROR] Invalid IP address!\n";
        cin.clear(); cin.ignore(10000, '\n');
        continue;   // Go back to menu - don't proceed
    }

    cout << "Action (ALLOW/BLOCK): ";
    if (!(cin >> action)) {
        cout << "[ERROR] Invalid action!\n";
        cin.clear(); cin.ignore(10000, '\n');
        continue;
    }
    transform(action.begin(), action.end(), action.begin(), ::toupper);
    if (action != "ALLOW" && action != "BLOCK") {
        cout << "[ERROR] Action must be ALLOW or BLOCK!\n";
        continue;
    }

    cout << "Port (0 for any): ";
    if (!(cin >> port) || !isValidPort(port)) {
        cout << "[ERROR] Invalid port number! (0-65535)\n";
        cin.clear(); cin.ignore(10000, '\n');
        continue;
    }

    cout << "Protocol (TCP/UDP/ANY/HTTP/ICMP): ";
    if (!(cin >> proto) || !isValidProtocol(proto)) {
        cout << "[ERROR] Invalid protocol!\n";
        cin.clear(); cin.ignore(10000, '\n');
        continue;
    }

    // Only if ALL inputs are valid - add the rule
    if (fw.addRule(ip, action, port, proto)) {
        cout << "[SUCCESS] Rule added successfully!\n";
        cout << "   " << action << " " << ip << " " << port << " " << proto << endl;
        cout << "   Use option 11 to save rules permanently.\n";
    }
   } else if (choice == 9) {
            string ip;
            cout << "IP to remove rules for: "; cin >> ip;
            fw.removeRulesForIP(ip);
        } else if (choice == 10) {
            cout << "Exporting IDS logs to ids_export.txt ...\n";
            ids.exportToFile("ids_export.txt");
        } else if (choice == 11) {
            fw.saveRulesToFile("firewall_rules.txt");
        } else {
            cout << "Unknown choice.\n";
        }
    }
}
