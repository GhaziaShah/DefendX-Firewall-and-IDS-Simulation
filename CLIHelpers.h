#pragma once
#include <iostream>
#include <string>
#include "Firewall.h"
#include "IDS.h"
#include "PacketSimulator.h"

bool hasCommand(int argc, char* argv[], const std::string& command);
std::string getCommandValue(int argc, char* argv[], const std::string& command);
void interactiveMenu(Firewall &fw, IDS &ids, PacketSimulator &sim);
