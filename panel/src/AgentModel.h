#pragma once
#include <QAbstractListModel>
#include <QVector>
#include <QTimer>
#include "ApiClient.h"

struct AgentInfo {
    QString hwid, user, os, ip;
    bool online = false;
    qint64 lastSeen = 0;
};

// ═══════════════════════════════════════════════
// Agent 数据模型 — QML ListView 直接绑定
// ═══════════════════════════════════════════════

class AgentModel : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int onlineCount READ onlineCount NOTIFY countChanged)
    Q_PROPERTY(int totalCount READ totalCount NOTIFY countChanged)

public:
    enum Roles { HwidRole, UserRole, OsRole, IpRole, OnlineRole, LastSeenRole, IndexRole };
    explicit AgentModel(ApiClient* api, QObject* parent = nullptr);

    int rowCount(const QModelIndex& = QModelIndex()) const override;
    QVariant data(const QModelIndex&, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    int onlineCount() const { return _onlineCount; }
    int totalCount() const { return _agents.size(); }

    Q_INVOKABLE void refresh();
    Q_INVOKABLE QString selectedHwid() const { return _selectedHwid; }

signals:
    void countChanged();
    void agentSelected(QString hwid);

private:
    void updateFromJson(const QString& json);

    ApiClient* _api;
    QVector<AgentInfo> _agents;
    QString _selectedHwid;
    int _onlineCount = 0;
};
