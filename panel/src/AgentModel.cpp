#include "AgentModel.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

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
    }
    return {};
}

QHash<int, QByteArray> AgentModel::roleNames() const {
    return { {HwidRole,"hwid"}, {UserRole,"user"}, {OsRole,"os"}, {IpRole,"ip"},
             {OnlineRole,"online"}, {LastSeenRole,"lastSeen"}, {IndexRole,"index"} };
}

void AgentModel::refresh() {
    QString json = _api->get("/api/agents");
    updateFromJson(json);
}

void AgentModel::updateFromJson(const QString& json) {
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
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
