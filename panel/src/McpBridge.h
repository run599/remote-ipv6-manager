#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>
#include <QStringList>

// ═══════════════════════════════════════════════
// MCP 工具调用桥接 — QML 调用 → C++ → HTTP → 结果
//
// 设计要点（都是踩过的坑）：
//  1) 全程异步：原来在 Q_INVOKABLE 里 QThread::msleep(500) 轮询最多 60 次，
//     跑在 GUI 线程上 → 界面冻结 30 秒，连"执行中"都来不及重绘。
//  2) 结果带 source 标签：McpBridge 是全局单例，四个页签全部常驻存活，
//     不带标签时任何一次调用都会同时触发四个处理器（终端里刷出目录 JSON）。
//  3) 截图走结构化字段优先，文本标记兜底，且偏移量用标记实际长度。
// ═══════════════════════════════════════════════

class McpBridge : public QObject {
    Q_OBJECT
    Q_PROPERTY(QStringList toolList READ toolList NOTIFY toolListChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)

public:
    explicit McpBridge(QObject* parent = nullptr);

    QStringList toolList() const { return _tools; }
    bool busy() const { return _busy; }

    // 真正去问被控端要工具清单（走中继 tools/list，由客户端本地聚合各插件）
    Q_INVOKABLE void getToolList(const QString& hwid, const QString& serverUrl, const QString& cookie);

    // source: "shell" / "mcp" / "file" / "screen" —— 用于把结果只派发给发起方
    Q_INVOKABLE void callTool(const QString& hwid, const QString& serverUrl, const QString& cookie,
                              const QString& tool, const QString& argsJson, const QString& source);

signals:
    void toolListChanged();
    void busyChanged();
    void toolResult(QString tool, QString result, QString source);
    void screenshotReady(QString tool, QString base64, QString source);

private:
    void pollOnce(const QString& tool, const QString& serverUrl, const QString& cookie,
                  const QString& requestId, const QString& source, int attempt);
    void finish(const QString& tool, const QString& result, const QString& source);

    QNetworkAccessManager _nam;
    QStringList _tools;
    bool _busy = false;
    QTimer _pollTimer;
};
