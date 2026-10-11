#pragma once
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>
#include <QStringList>

// ═══════════════════════════════════════════════
//
// 设计要点（都是踩过的坑）：
//  1) 全程异步：原来在 Q_INVOKABLE 里 QThread::msleep(500) 轮询最多 60 次，
//  2) 结果带 source 标签：McpBridge 是全局单例，四个页签全部常驻存活，
//     不带标签时任何一次调用都会同时触发四个处理器（终端里刷出目录 JSON）。
//  3) 截图走结构化字段优先，文本标记兜底，且偏移量用标记实际长度。
// ═══════════════════════════════════════════════

class McpBridge : public QObject {
    Q_OBJECT
    Q_PROPERTY(QStringList toolList READ toolList NOTIFY toolListChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    // 已等待秒数：让"截屏中..."能显示成"截屏中... 12s"。
    // 慢操作最怕看起来像卡死 —— 有一个跳动的数字，用户就知道它还活着。
    Q_PROPERTY(int busySeconds READ busySeconds NOTIFY busySecondsChanged)

public:
    explicit McpBridge(QObject* parent = nullptr);

    QStringList toolList() const { return _tools; }
    bool busy() const { return _busy; }
    int busySeconds() const { return _busySeconds; }

    // 放弃当前调用（清 busy 并给出"已取消"）。给操作者一条退路：
    // 只要没有取消口，任何一次卡住都得等满期限。
    Q_INVOKABLE void cancel();

    // 真正去问受管端要工具清单（走中继 tools/list，由客户端本地聚合各插件）
    Q_INVOKABLE void getToolList(const QString& hwid, const QString& serverUrl, const QString& cookie);

    // source: "shell" / "mcp" / "file" / "screen" —— 用于把结果只派发给发起方。
    //
    //    只会在**运行时抛 TypeError 并中断整个 onClicked**：表现为"按钮点了没反应、
    //    busy 从不变真、服务端收不到任何请求"，且没有任何显式报错提示原因。
    //    实测踩过：ScreenTab 的「📸 单张」漏传 source，单张截图功能整个是死的
    //    （详情行永远是上一个实时帧的数据，看起来像"显示没刷新"）。
    Q_INVOKABLE void callTool(const QString& hwid, const QString& serverUrl, const QString& cookie,
                              const QString& tool, const QString& argsJson,
                              const QString& source = QString());

signals:
    void toolListChanged();
    void busyChanged();
    void busySecondsChanged();
    void toolResult(QString tool, QString result, QString source);
    void screenshotReady(QString tool, QString base64, QString source);

private:
    void pollOnce(const QString& tool, const QString& serverUrl, const QString& cookie,
                  const QString& requestId, const QString& source, int attempt);
    void finish(const QString& tool, const QString& result, const QString& source);
    // 按工具给期限：截图天生比命令慢（抓屏 + 缩放 + 编码 + 数 MB 上传）
    static int deadlineMsFor(const QString& tool);
    // 看门狗：到期无条件 finish，保证 _busy 不可能永久卡住
    void armWatchdog(const QString& tool, const QString& source);

    QNetworkAccessManager _nam;
    QStringList _tools;
    bool _busy = false;
    int _busySeconds = 0;
    int _deadlineMs = 60000;
    QTimer _pollTimer;
    QTimer _watchdog;   // 单次：硬期限
    QTimer _tick;       // 1 秒：驱动 busySeconds
};
