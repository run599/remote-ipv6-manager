#include "McpBridge.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QUrl>
#include "TlsConfig.h"

// 截图文本标记：与 plugins/screen_capture/screen_capture.py 的契约。
// 注意长度是 12，原实现写 +13 会吃掉 base64 的第一个字符，
// 导致长度不再是 4 的倍数、解码必然失败，而且界面上只会显示一片黑底。
static const char* kShotMarker = "[BMP base64]";

McpBridge::McpBridge(QObject* parent) : QObject(parent) {
    // 看门狗：单次触发，到期强制 finish。
    // finish（网络层不回、定时器链断、QML 侧异常），_busy 就永久为 true ——
    // 现象正是"点什么都提示'上一个调用尚未完成'"。看门狗把"清 busy"变成
    // 不依赖任何路径的兜底。
    _watchdog.setSingleShot(true);
    connect(&_watchdog, &QTimer::timeout, this, [this]() {
        if (!_busy) return;
        finish(QStringLiteral("_watchdog"),
               QStringLiteral("{\"error\":\"等待结果超时（%1 秒），已自动解除忙碌状态\"}")
                   .arg(_deadlineMs / 1000),
               QString());
    });

    _tick.setInterval(1000);
    connect(&_tick, &QTimer::timeout, this, [this]() {
        if (!_busy) return;
        _busySeconds++;
        emit busySecondsChanged();
    });
}

int McpBridge::deadlineMsFor(const QString& tool) {
    // 任何一环都比普通命令慢一个量级，给 180 秒。
    if (tool == QLatin1String("screenshot")) return 180000;
    return 60000;
}

void McpBridge::armWatchdog(const QString& tool, const QString& source) {
    _deadlineMs = deadlineMsFor(tool);
    _busySeconds = 0;
    emit busySecondsChanged();
    _tick.start();
    _watchdog.start(_deadlineMs);
}

void McpBridge::cancel() {
    if (!_busy) return;
    finish(QStringLiteral("_cancel"), QStringLiteral("{\"error\":\"已取消\"}"), QString());
}

void McpBridge::callTool(const QString& hwid, const QString& serverUrl, const QString& cookie,
                         const QString& tool, const QString& argsJson, const QString& source) {
    if (_busy) {
        // 自愈：卡住超过期限（看门狗因故没触发）时强制临时授权，而不是永久拒绝。
        // 原来这里无条件拒绝，配合"某条路径不清 busy"就是死锁。
        if (_busySeconds * 1000 <= _deadlineMs) {
            emit toolResult(tool,
                            QStringLiteral("{\"error\":\"上一个调用尚未完成（已等待 %1 秒，可点「取消」或继续等待）\"}")
                                .arg(_busySeconds),
                            source);
            return;
        }
        finish(QStringLiteral("_stuck"),
               QStringLiteral("{\"error\":\"上一个调用疑似卡死，已强制解除\"}"), QString());
    }
    if (hwid.isEmpty()) {
        emit toolResult(tool, QStringLiteral("{\"error\":\"未选择客户端\"}"), source);
        return;
    }

    _busy = true;
    emit busyChanged();
    armWatchdog(tool, source);

    QJsonObject body;
    body["agent_hwid"] = hwid;
    body["name"] = tool;
    body["arguments"] = QJsonDocument::fromJson(argsJson.toUtf8()).object();

    QNetworkRequest req(QUrl(serverUrl + "/api/mcp"));
    // https 必须套用自签证书配置，否则握手失败（见 TlsConfig.h 说明）
    r6mApplyTls(req, serverUrl);
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
    // 轮询上限跟随本工具的期限（截图 180 秒，其余 60 秒）。
    // 原来硬编码 120 × 500ms = 60 秒，对截图偏短；同时保留次数上限，
    // 避免 pending 永不返回时定时器链无限增长。
    const int maxAttempts = _deadlineMs / 500;
    if (attempt >= maxAttempts) {
        finish(tool, QStringLiteral("{\"error\":\"等待结果超时（%1 秒）\"}").arg(_deadlineMs / 1000), source);
        return;
    }

    QNetworkRequest req(QUrl(serverUrl + "/api/mcp/result?request_id=" + requestId));
    r6mApplyTls(req, serverUrl);   // 同上：漏了这一步就会 SSL 握手失败
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
    _watchdog.stop();
    _tick.stop();
    _busy = false;
    _busySeconds = 0;
    emit busyChanged();
    emit busySecondsChanged();
    // source 为空表示这是看门狗/取消产生的本地终态，不是某次真实调用的结果：
    // 不能按 source 派发（否则四个页签全收到一条莫名其妙的错误）。
    // 统一发给 toolResult 的通用使用方需要按 tool 名过滤，故这里保留 tool 名。
    emit toolResult(tool, result, source.isEmpty() ? QStringLiteral("bridge") : source);
}

void McpBridge::getToolList(const QString& hwid, const QString& serverUrl, const QString& cookie) {
    // 原来这个函数三个参数全是 Q_UNUSED、返回硬编码的 12 个工具名：
    // 点"刷新工具列表"永远不变，下拉里的名字还与服务端能力无关。
    // 现在走同一条中继，让客户端的 PluginLoader 聚合各插件的 tools/list。
    callTool(hwid, serverUrl, cookie, "tools/list", "{}", "mcp");
}
