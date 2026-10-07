#include "McpBridge.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QUrl>

// 截图文本标记：与 plugins/screen_capture/screen_capture.py 的契约。
// 注意长度是 12，原实现写 +13 会吃掉 base64 的第一个字符，
// 导致长度不再是 4 的倍数、解码必然失败，而且界面上只会显示一片黑底。
static const char* kShotMarker = "[BMP base64]";

McpBridge::McpBridge(QObject* parent) : QObject(parent) {}

void McpBridge::callTool(const QString& hwid, const QString& serverUrl, const QString& cookie,
                         const QString& tool, const QString& argsJson, const QString& source) {
    if (_busy) {
        emit toolResult(tool, QStringLiteral("{\"error\":\"上一个调用尚未完成\"}"), source);
        return;
    }
    if (hwid.isEmpty()) {
        emit toolResult(tool, QStringLiteral("{\"error\":\"未选择客户端\"}"), source);
        return;
    }

    _busy = true;
    emit busyChanged();

    QJsonObject body;
    body["agent_hwid"] = hwid;
    body["name"] = tool;
    body["arguments"] = QJsonDocument::fromJson(argsJson.toUtf8()).object();

    QNetworkRequest req(QUrl(serverUrl + "/api/mcp"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setTransferTimeout(15000);
    if (!cookie.isEmpty()) req.setRawHeader("Cookie", cookie.toUtf8());

    QNetworkReply* reply = _nam.post(req, QJsonDocument(body).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply, tool, serverUrl, cookie, source]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            finish(tool, QString("{\"error\":\"%1\"}").arg(reply->errorString()), source);
            return;
        }
        const QJsonObject o = QJsonDocument::fromJson(reply->readAll()).object();
        const QString requestId = o.value("request_id").toString();
        if (requestId.isEmpty()) {
            finish(tool, QString("{\"error\":\"%1\"}").arg(o.value("error").toString("no request_id")), source);
            return;
        }
        pollOnce(tool, serverUrl, cookie, requestId, source, 0);
    });
}

void McpBridge::pollOnce(const QString& tool, const QString& serverUrl, const QString& cookie,
                         const QString& requestId, const QString& source, int attempt) {
    // 120 × 500ms = 60 秒上限。原来 ShellTerminal/TaskOrchestrator 是无限重试，
    // pending 永远不返回时定时器链会无限增长。
    if (attempt >= 120) {
        finish(tool, QStringLiteral("{\"error\":\"等待结果超时（60 秒）\"}"), source);
        return;
    }

    QNetworkRequest req(QUrl(serverUrl + "/api/mcp/result?request_id=" + requestId));
    req.setTransferTimeout(5000);
    if (!cookie.isEmpty()) req.setRawHeader("Cookie", cookie.toUtf8());

    QNetworkReply* r = _nam.get(req);
    connect(r, &QNetworkReply::finished, this, [this, r, tool, serverUrl, cookie, requestId, source, attempt]() {
        r->deleteLater();
        if (r->error() != QNetworkReply::NoError) {
            finish(tool, QString("{\"error\":\"%1\"}").arg(r->errorString()), source);
            return;
        }
        const QJsonObject o = QJsonDocument::fromJson(r->readAll()).object();
        if (o.value("ok").toBool()) {
            const QJsonValue rv = o.value("result");
            const QJsonObject ro = rv.toObject();
            // 结构化字段优先：不要对序列化后的文本做子串搜索
            if (ro.contains("image_base64")) {
                emit screenshotReady(tool, ro.value("image_base64").toString(), source);
            }
            QString text;
            if (rv.isString()) {
                text = rv.toString();
            } else if (rv.isObject()) {
                text = QString::fromUtf8(QJsonDocument(rv.toObject()).toJson(QJsonDocument::Compact));
            } else if (rv.isArray()) {
                text = QString::fromUtf8(QJsonDocument(rv.toArray()).toJson(QJsonDocument::Compact));
            } else {
                text = QString::fromUtf8(QJsonDocument(ro).toJson(QJsonDocument::Compact));
            }
            // 兼容旧格式：文本里的标记（用标记实际长度，不再硬编码 +13）
            if (!ro.contains("image_base64")) {
                const QString marker = QString::fromLatin1(kShotMarker);
                const int pos = text.indexOf(marker);
                if (pos >= 0) emit screenshotReady(tool, text.mid(pos + marker.size()), source);
            }
            if (tool == "tools/list") {
                const QJsonArray arr = ro.value("tools").toArray();
                if (!arr.isEmpty()) {
                    _tools.clear();
                    for (const auto& t : arr) {
                        const QString name = t.toObject().value("name").toString();
                        if (!name.isEmpty()) _tools << name;
                    }
                    emit toolListChanged();
                }
            }
            finish(tool, text, source);
            return;
        }
        if (o.value("status").toString() == "pending") {
            QTimer::singleShot(500, this, [this, tool, serverUrl, cookie, requestId, source, attempt]() {
                pollOnce(tool, serverUrl, cookie, requestId, source, attempt + 1);
            });
            return;
        }
        finish(tool, QString("{\"error\":\"%1\"}").arg(o.value("error").toString("unknown")), source);
    });
}

void McpBridge::finish(const QString& tool, const QString& result, const QString& source) {
    _busy = false;
    emit busyChanged();
    emit toolResult(tool, result, source);
}

void McpBridge::getToolList(const QString& hwid, const QString& serverUrl, const QString& cookie) {
    // 原来这个函数三个参数全是 Q_UNUSED、返回硬编码的 12 个工具名：
    // 点"刷新工具列表"永远不变，下拉里的名字还与服务端能力无关。
    // 现在走同一条中继，让客户端的 PluginLoader 聚合各插件的 tools/list。
    callTool(hwid, serverUrl, cookie, "tools/list", "{}", "mcp");
}
