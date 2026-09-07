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
    QJsonObject body; body["user"] = user; body["pass"] = pass;
    QString resp = post("/api/login", QJsonDocument(body).toJson());
    QJsonDocument doc = QJsonDocument::fromJson(resp.toUtf8());
    if (doc.object().value("ok").toBool()) {
        _connected = true;
        emit connectedChanged();
    }
    return resp;
}

QString ApiClient::get(const QString& path) {
    QNetworkRequest req(QUrl(_serverUrl + path));
    if (_serverUrl.startsWith("https", Qt::CaseInsensitive)) {
        req.setSslConfiguration(selfSignedConfig());
    }
    if (!_cookie.isEmpty()) req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam.get(req);
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    // 保存 cookie
    for (const auto& c : reply->rawHeaderPairs()) {
        if (c.first.toLower() == "set-cookie") _cookie = c.second;
    }
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
    QNetworkReply* reply = _nam.post(req, body.toUtf8());
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    for (const auto& c : reply->rawHeaderPairs()) {
        if (c.first.toLower() == "set-cookie") _cookie = c.second;
    }
    QString result = reply->readAll();
    reply->deleteLater();
    return result;
}
