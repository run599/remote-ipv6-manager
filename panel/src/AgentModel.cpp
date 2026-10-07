#include "AgentModel.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QDebug>

AgentModel::AgentModel(ApiClient* api, QObject* parent)
    : QAbstractListModel(parent), _api(api) {}

int AgentModel::rowCount(const QModelIndex&) const { return _agents.size(); }

QVariant AgentModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() >= _agents.size()) return {};
    const auto& a = _agents[idx.row()];
    switch (role) {
        case HwidRole:     return a.hwid;
        case UserRole:     return a.user;
        case OsRole:       return a.os;
        case IpRole:       return a.ip;
        case OnlineRole:   return a.online;
        case LastSeenRole: return a.lastSeen;
        case IndexRole:    return idx.row();
        case SelectedRole: return a.hwid == _selectedHwid;
    }
    return {};
}

QHash<int, QByteArray> AgentModel::roleNames() const {
    return { {HwidRole,"hwid"}, {UserRole,"user"}, {OsRole,"os"}, {IpRole,"ip"},
             {OnlineRole,"online"}, {LastSeenRole,"lastSeen"}, {IndexRole,"index"},
             {SelectedRole,"selected"} };
}

void AgentModel::refresh() {
    const QString json = _api->get("/api/agents");
    if (json.isEmpty()) {
        // 关键：失败不要把模型清空。原实现把空串交给 updateFromJson，
        // 解析出零个元素后清空列表 → 界面显示"所有机器都掉线"，
        // 真正原因（超时/401/证书）却看不到。
        qWarning() << "刷新 agent 列表失败:" << _api->lastError();
        return;
    }
    updateFromJson(json);
}

void AgentModel::selectAgent(const QString& hwid) {
    if (_selectedHwid == hwid) return;
    _selectedHwid = hwid;
    if (!_agents.isEmpty()) {
        emit dataChanged(index(0), index(_agents.size() - 1), {SelectedRole});
    }
}

void AgentModel::updateFromJson(const QString& json) {
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isArray()) {      // 非数组（错误对象/HTML）不能当成"零个 agent"
        qWarning() << "agents 响应不是数组，保留旧数据";
        return;
    }
    QVector<AgentInfo> newAgents;
    int online = 0;
    for (const auto& v : doc.array()) {
        QJsonObject o = v.toObject();
        AgentInfo a;
        a.hwid = o["hwid"].toString();
        a.user = o["user"].toString();
        a.os = o["os"].toString();
        a.ip = o["ip"].toString();
        a.online = o["online"].toBool();
        a.lastSeen = (qint64)o["last_seen"].toDouble();
        if (a.online) online++;
        newAgents.append(a);
    }
    beginResetModel();
    _agents = newAgents;
    _onlineCount = online;
    endResetModel();
    emit countChanged();
}
