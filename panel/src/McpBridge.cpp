#include "McpBridge.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>
#include <QThread>

McpBridge::McpBridge(QObject* parent) : QObject(parent) {}

static QString httpGet(const QString& url, const QString& cookie, QNetworkAccessManager& nam) {
    QUrl qurl(url);
    QNetworkRequest req(qurl);
    if (!cookie.isEmpty()) req.setRawHeader("Cookie", cookie.toUtf8());
    QNetworkReply* reply = nam.get(req);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    QString r = reply->readAll();
    reply->deleteLater();
    return r;
}

static QString httpPost(const QString& url, const QByteArray& body, const QString& cookie, QNetworkAccessManager& nam) {
    QUrl qurl(url);
    QNetworkRequest req(qurl);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (!cookie.isEmpty()) req.setRawHeader("Cookie", cookie.toUtf8());
    QNetworkReply* reply = nam.post(req, body);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    QString r = reply->readAll();
    reply->deleteLater();
    return r;
}

void McpBridge::getToolList(const QString& hwid, const QString& serverUrl, const QString& cookie) {
    Q_UNUSED(hwid); Q_UNUSED(serverUrl); Q_UNUSED(cookie);
    _tools = {"execute", "powershell", "cmd", "list_processes", "kill_process", "process_info",
              "screenshot", "screen_info", "list_directory", "read_file", "write_file", "delete_file"};
    emit toolListChanged();
}

void McpBridge::callTool(const QString& hwid, const QString& serverUrl, const QString& cookie,
                         const QString& tool, const QString& argsJson) {
    _busy = true; emit busyChanged();

    QJsonObject body;
    body["agent_hwid"] = hwid;
    body["name"] = tool;
    body["arguments"] = QJsonDocument::fromJson(argsJson.toUtf8()).object();

    QString resp = httpPost(serverUrl + "/api/mcp", QJsonDocument(body).toJson(), cookie, _nam);
    QJsonDocument doc = QJsonDocument::fromJson(resp.toUtf8());
    QString requestId = doc.object().value("request_id").toString();

    if (requestId.isEmpty()) {
        _busy = false; emit busyChanged();
        emit toolResult("{\"error\":\"no request_id\"}");
        return;
    }

    // 轮询结果
    QString resultUrl = serverUrl + "/api/mcp/result?request_id=" + requestId;
    for (int i = 0; i < 60; i++) {
        QThread::msleep(500);
        QString r = httpGet(resultUrl, cookie, _nam);
        QJsonDocument rd = QJsonDocument::fromJson(r.toUtf8());
        if (rd.object().value("ok").toBool()) {
            QString result = QJsonDocument(rd.object().value("result").toObject()).toJson();
            if (result.contains("[BMP base64]")) {
                emit screenshotReady(result.mid(result.indexOf("[BMP base64]") + 13));
            }
            _busy = false; emit busyChanged();
            emit toolResult(result);
            return;
        }
    }
    _busy = false; emit busyChanged();
    emit toolResult("{\"error\":\"timeout\"}");
}
