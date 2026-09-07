#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>
#include <QMap>

// ═══════════════════════════════════════════════
// MCP 工具调用桥接 — QML 调用 → C++ → HTTP → 结果
// ═══════════════════════════════════════════════

class McpBridge : public QObject {
    Q_OBJECT
    Q_PROPERTY(QStringList toolList READ toolList NOTIFY toolListChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)

public:
    explicit McpBridge(QObject* parent = nullptr);

    QStringList toolList() const { return _tools; }
    bool busy() const { return _busy; }

    Q_INVOKABLE void getToolList(const QString& hwid, const QString& serverUrl, const QString& cookie);
    Q_INVOKABLE void callTool(const QString& hwid, const QString& serverUrl, const QString& cookie,
                              const QString& tool, const QString& argsJson);

signals:
    void toolListChanged();
    void busyChanged();
    void toolResult(QString result);
    void screenshotReady(QString base64);

private:
    void pollResult(const QString& serverUrl, const QString& cookie, const QString& requestId);

    QNetworkAccessManager _nam;
    QStringList _tools;
    bool _busy = false;
    QTimer _pollTimer;
};
