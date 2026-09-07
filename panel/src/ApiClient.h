#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QString>

// ═══════════════════════════════════════════════
// HTTP 客户端 — QML 通过 Q_INVOKABLE 调用
// ═══════════════════════════════════════════════

class ApiClient : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString serverUrl READ serverUrl WRITE setServerUrl NOTIFY serverUrlChanged)
    Q_PROPERTY(bool connected READ connected NOTIFY connectedChanged)

public:
    explicit ApiClient(QObject* parent = nullptr);

    QString serverUrl() const { return _serverUrl; }
    void setServerUrl(const QString& url);
    bool connected() const { return _connected; }

    // QML 可调用
    Q_INVOKABLE QString login(const QString& user, const QString& pass);
    Q_INVOKABLE QString get(const QString& path);
    Q_INVOKABLE QString post(const QString& path, const QString& body);

signals:
    void serverUrlChanged();
    void connectedChanged();

private:
    QString _serverUrl;
    QString _cookie;
    bool _connected = false;
    QNetworkAccessManager _nam;
};
