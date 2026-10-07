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
    // QML 需要 cookie 值（LoginPage 会把它传给各页签）：
    // 原来没有这个属性，api.cookie 恒为 undefined → 登录后所有页签都在无凭据请求
    Q_PROPERTY(QString cookie READ cookie NOTIFY cookieChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY lastErrorChanged)

public:
    explicit ApiClient(QObject* parent = nullptr);

    QString serverUrl() const { return _serverUrl; }
    void setServerUrl(const QString& url);
    bool connected() const { return _connected; }
    QString cookie() const { return _cookie; }
    QString lastError() const { return _lastError; }

    // QML 可调用
    Q_INVOKABLE QString login(const QString& user, const QString& pass);
    Q_INVOKABLE QString get(const QString& path);
    Q_INVOKABLE QString post(const QString& path, const QString& body);

signals:
    void serverUrlChanged();
    void connectedChanged();
    void cookieChanged();
    void lastErrorChanged();

private:
    QString _serverUrl;
    QString _cookie;
    bool _connected = false;
    QString _lastError;
    QNetworkAccessManager _nam;

    void saveCookie(QNetworkReply* reply);
    void setLastError(const QString& err);
};
