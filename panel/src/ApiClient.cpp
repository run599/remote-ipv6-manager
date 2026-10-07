#include "ApiClient.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkCookie>
#include <QEventLoop>
#include <QSslConfiguration>

ApiClient::ApiClient(QObject* parent) : QObject(parent) {}

void ApiClient::setServerUrl(const QString& url) {
    if (_serverUrl != url) { _serverUrl = url; emit serverUrlChanged(); }
}

// 自签证书 TLS 配置：面板与服务端同属自有环境，
// 信任由部署边界保证（面板仅运维本机运行），跳过系统信任链校验
static QSslConfiguration selfSignedConfig() {
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    return cfg;
}

QString ApiClient::login(const QString& user, const QString& pass) {
    QJsonObject body;
    body["user"] = user;
    body["pass"] =  pass;
    QString resp = post("/api/login", QJsonDocument(body).toJson());
    if (!_lastError.isEmpty()) {
        // 网络层失败（地址写错/证书/超时）：与"密码错"分开报，用户才知道该改什么
        if (_connected) { _connected = false; emit connectedChanged(); }
        return resp;
    }
    QJsonDocument doc = QJsonDocument::fromJson(resp.toUtf8());
    const bool ok = doc.isObject() && doc.object().value("ok").toBool();
    if (ok != _connected) {
        _connected = ok;
        emit connectedChanged();
    }
    if (!ok) setLastError(QStringLiteral("认证失败：用户名或密码不正确"));
    return resp;
}

QString ApiClient::get(const QString& path) {
    QNetworkRequest req(QUrl(_serverUrl + path));
    if (_serverUrl.startsWith("https", Qt::CaseInsensitive)) {
        req.setSslConfiguration(selfSignedConfig());
    }
    // 修复点：原来不设传输超时，IPv6 半开连接会让 loop.exec() 卡满 TCP 超时（数分钟），
    // 且 5 秒一轮的刷新定时器会在嵌套事件循环里重入叠加。
    req.setTransferTimeout(8000);
    if (!_cookie.isEmpty()) req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam.get(req);
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    saveCookie(reply);
    if (reply->error() != QNetworkReply::NoError) {
        setLastError(QString("%1: %2").arg(path, reply->errorString()));
        reply->deleteLater();
        return QString();   // 调用方必须区分"空"与"失败"（AgentModel 已改为失败时保留旧数据）
    }
    setLastError(QString());
    QString result = reply->readAll();
    reply->deleteLater();
    return result;
}

QString ApiClient::post(const QString& path, const QString& body) {
    QNetworkRequest req(QUrl(_serverUrl + path));
    if (_serverUrl.startsWith("https", Qt::CaseInsensitive)) {
        req.setSslConfiguration(selfSignedConfig());
    }
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (!_cookie.isEmpty()) req.setRawHeader("Cookie", _cookie.toUtf8());
    req.setTransferTimeout(15000);
    QNetworkReply* reply = _nam.post(req, body.toUtf8());
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    saveCookie(reply);
    if (reply->error() != QNetworkReply::NoError) {
        setLastError(QString("%1: %2").arg(path, reply->errorString()));
        reply->deleteLater();
        return QString();
    }
    setLastError(QString());
    QString result = reply->readAll();
    reply->deleteLater();
    return result;
}

// 修复点：原来把整条 Set-Cookie 原文当 Cookie 头回发
// （"c2session=xxx; Path=/; HttpOnly; Secure; SameSite=Strict"），
// 按 RFC 6265 请求头只应含 name=value 对，严格的服务端会 400/401。
void ApiClient::saveCookie(QNetworkReply* reply) {
    for (const auto& c : reply->rawHeaderPairs()) {
        if (c.first.toLower() == "set-cookie") {
            const QString trimmed = QString::fromUtf8(c.second).section(';', 0, 0).trimmed();
            if (trimmed != _cookie) {
                _cookie = trimmed;
                emit cookieChanged();
            }
        }
    }
}

void ApiClient::setLastError(const QString& err) {
    if (_lastError != err) {
        _lastError = err;
        emit lastErrorChanged();
    }
}
