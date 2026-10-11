#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QTimer>
#include <QString>
#include <QJsonObject>
#include <functional>

// ═══════════════════════════════════════════════════════════════════════════
// ScreenStream —— 屏幕监控（实时看屏）的面板侧
//
// 为什么单独一个类，不复用 McpBridge：
//   天然把并发串行掉了。实时看屏要求**按显示节奏高频取帧**，塞进那条链路会：
//     ① 和普通命令互相阻塞（看上屏时执行不了命令）
//     ② busy 长期为真（之前"上一个命令尚未完成"那个坑就是这么来的）
//   所以这里用纯异步 QNetworkAccessManager：不阻塞 GUI 线程，也不碰 busy。
//
// 与 McpBridge 的职责边界：
//   McpBridge  —— 一次性工具调用（终端 / 文件 / 单张截图）
//   ScreenStream —— 持续画面：管会话开关 + 按节奏取最新帧 + 统计
// ═══════════════════════════════════════════════════════════════════════════

class ScreenStream : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool active READ active NOTIFY activeChanged)
    Q_PROPERTY(bool paused READ paused WRITE setPaused NOTIFY pausedChanged)
    Q_PROPERTY(double fps READ fps NOTIFY statsChanged)
    Q_PROPERTY(int frameKb READ frameKb NOTIFY statsChanged)
    Q_PROPERTY(int ageMs READ ageMs NOTIFY statsChanged)
    Q_PROPERTY(QString status READ status NOTIFY statusChanged)
    Q_PROPERTY(int received READ received NOTIFY statsChanged)

public:
    explicit ScreenStream(QObject* parent = nullptr);

    bool active() const { return _active; }
    bool paused() const { return _paused; }
    void setPaused(bool p);
    double fps() const { return _fps; }
    int frameKb() const { return _frameKb; }
    int ageMs() const { return _ageMs; }
    int received() const { return _received; }
    QString status() const { return _status; }

    // 开始监控：serverUrl/cookie 由 QML 从 ApiClient 传进来（保持本类不依赖 ApiClient）
    Q_INVOKABLE void start(const QString& serverUrl, const QString& cookie,
                           const QString& hwid, int scale, int intervalMs);
    Q_INVOKABLE void stop();
    // 监控中改画质/帧间隔：只更新服务端会话参数，不重建会话（避免白屏一下）
    Q_INVOKABLE void updateParams(int scale, int intervalMs);

signals:
    void activeChanged();
    void pausedChanged();
    void statsChanged();
    void statusChanged();
    // 一帧就绪。format 目前恒为 png；width/height 来自服务端转发（免去面板解码取值）
    void frameReady(QString base64, QString format, int width, int height, int seq);

private:
    void setStatus(const QString& s);
    void postJson(const QString& path, const QJsonObject& body, std::function<void(bool)> done);
    void fetchLatest();

    QNetworkAccessManager _nam;
    QTimer _timer;          // 取帧节奏
    QTimer _statTimer;      // 每秒结算一次 fps
    QString _serverUrl;
    QString _cookie;
    QString _hwid;
    int _intervalMs = 100;   // 2026-10-10: 400100（2.510 fps  下限由服务端夹到 100）
    int _scale = 2;            // 2026-10-10: 42（1/41/2 分辨率  体积≈1/4  编码/上行更快且更清晰 ）
    bool _active = false;
    bool _paused = false;
    bool _inflight = false;   // 上一帧还没回来就不再发（防止慢网络下堆积）
    int _received = 0;
    int _receivedThisSecond = 0;
    int _lastSeq = -1;
    QString _status;
    double _fps = 0.0;
    int _frameKb = 0;
    int _ageMs = 0;
};
