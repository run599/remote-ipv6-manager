#include "ScreenStream.h"
#include "TlsConfig.h"
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QUrl>
#include <QDebug>

ScreenStream::ScreenStream(QObject* parent) : QObject(parent) {
    // 取帧节奏：跟服务端下发的 interval 一致。下限 100ms（服务端也夹到 100ms），
    // 再快没有意义 —— 面板侧真正要显示的画面刷新率受解码与重绘限制。
    _timer.setInterval(_intervalMs);
    connect(&_timer, &QTimer::timeout, this, &ScreenStream::fetchLatest);

    // fps 每秒结算：不要每帧都更新 UI 属性，否则高频属性变更会把 QML 绑定刷爆
    _statTimer.setInterval(1000);
    connect(&_statTimer, &QTimer::timeout, this, [this]() {
        if (!_active) return;
        _fps = double(_receivedThisSecond);
        _receivedThisSecond = 0;
        emit statsChanged();
    });
}

void ScreenStream::setStatus(const QString& s) {
    if (_status == s) return;
    _status = s;
    emit statusChanged();
}

void ScreenStream::setPaused(bool p) {
    if (_paused == p) return;
    _paused = p;
    emit pausedChanged();
    setStatus(p ? QStringLiteral("已暂停（画面冻结）") : QStringLiteral("监控中"));
}

void ScreenStream::postJson(const QString& path, const QJsonObject& body,
                            std::function<void(bool)> done) {
    QNetworkRequest req(QUrl(_serverUrl + path));
    r6mApplyTls(req, _serverUrl);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (!_cookie.isEmpty()) req.setRawHeader("Cookie", _cookie.toUtf8());
    req.setTransferTimeout(8000);
    QNetworkReply* reply = _nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply, done]() {
        reply->deleteLater();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // 有 HTTP 状态码就说明连上了；Qt 对 4xx 也会把 error() 置位，不能据此判失败
        const bool ok = (status >= 200 && status < 300);
        if (done) done(ok);
    });
}

void ScreenStream::start(const QString& serverUrl, const QString& cookie,
                         const QString& hwid, int scale, int intervalMs) {
    if (hwid.isEmpty()) {
        setStatus(QStringLiteral("请先选择一个客户端"));
        return;
    }
    _serverUrl = serverUrl;
    _cookie = cookie;
    _hwid = hwid;
    _scale = scale;
    _intervalMs = intervalMs < 100 ? 100 : intervalMs;
    _received = 0;
    _receivedThisSecond = 0;
    _lastSeq = -1;
    _frameKb = 0;
    _ageMs = 0;
    _fps = 0.0;

    if (_active) {
        // 已在监控：只改参数
        updateParams(scale, intervalMs);
        return;
    }

    _active = true;
    emit activeChanged();
    setStatus(QStringLiteral("正在建立会话…"));

    QJsonObject body;
    body["hwid"] = _hwid;
    body["scale"] = _scale;
    body["interval_ms"] = _intervalMs;
    postJson(QStringLiteral("/api/screen/start"), body, [this](bool ok) {
        if (!_active) return;
        if (!ok) {
            setStatus(QStringLiteral("无法开始监控（服务端拒绝或不可达）"));
            stop();
            return;
        }
        setStatus(QStringLiteral("监控中"));
        _timer.setInterval(_intervalMs);
        _timer.start();
        _statTimer.start();
    });
}

void ScreenStream::updateParams(int scale, int intervalMs) {
    if (!_active) return;
    _scale = scale;
    _intervalMs = intervalMs < 100 ? 100 : intervalMs;
    _timer.setInterval(_intervalMs);
    QJsonObject body;
    body["hwid"] = _hwid;
    body["scale"] = _scale;
    body["interval_ms"] = _intervalMs;
    postJson(QStringLiteral("/api/screen/start"), body, nullptr);  // 幂等更新
}

void ScreenStream::stop() {
    const bool wasActive = _active;
    _timer.stop();
    _statTimer.stop();
    _active = false;
    _paused = false;
    _inflight = false;
    if (wasActive) {
        emit activeChanged();
        emit pausedChanged();
        setStatus(QStringLiteral("已停止"));
        QJsonObject body;
        body["hwid"] = _hwid;
        // 通知服务端结束会话；即使这一步失败，服务端的静默超时（15s）也会兜住，
        // 受管端不会一直被要求采集上传。
        postJson(QStringLiteral("/api/screen/stop"), body, nullptr);
    }
}

void ScreenStream::fetchLatest() {
    if (!_active || _paused || _inflight || _hwid.isEmpty()) return;
    _inflight = true;

    QNetworkRequest req(QUrl(_serverUrl + QStringLiteral("/api/screen/latest?hwid=") + _hwid));
    r6mApplyTls(req, _serverUrl);
    if (!_cookie.isEmpty()) req.setRawHeader("Cookie", _cookie.toUtf8());
    req.setTransferTimeout(6000);

    QNetworkReply* reply = _nam.get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        _inflight = false;
        reply->deleteLater();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray raw = reply->readAll();
        if (status == 404) {
            // 服务端会话不在了（被静默超时清理 / 被别处停止）：明确告知而不是默默空转
            setStatus(QStringLiteral("会话已结束（受管端可能已离线）"));
            stop();
            return;
        }
        if (status != 200) return;

        const QJsonObject o = QJsonDocument::fromJson(raw).object();
        _ageMs = o.value("age_ms").toInt();
        if (o.value("waiting").toBool()) {
            setStatus(QStringLiteral("等待首帧…"));
            emit statsChanged();
            return;
        }
        const QString b64 = o.value("image_base64").toString();
        if (b64.isEmpty()) return;
        const int seq = o.value("seq").toInt();
        if (seq == _lastSeq) {
            // 服务端还没收到新帧（采集慢于显示）：不要重复上屏，也别把 fps 算高
            _ageMs = o.value("age_ms").toInt();
            emit statsChanged();
            return;
        }
        // 收到真实帧就把状态从"等待首帧…"复位。
        // 否则第一次读发生在采集线程出第一帧之前，那句"等待首帧…"会一直挂着，
        // 让人以为还没通 —— 实测就是这个表现。
        setStatus(QStringLiteral("监控中"));
        _lastSeq = seq;
        _received++;
        _receivedThisSecond++;
        _frameKb = b64.size() / 1024;
        emit frameReady(b64,
                        o.value("format").toString(QStringLiteral("png")),
                        o.value("width").toInt(),
                        o.value("height").toInt(),
                        seq);
    });
}
