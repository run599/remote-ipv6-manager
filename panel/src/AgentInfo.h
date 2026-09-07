#pragma once
#include <QString>

struct AgentInfo {
    QString hwid, user, os, ip, lastSeen;
    bool online = false;
};