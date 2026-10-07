#include "ApiClient.h"
#include "AgentModel.h"
#include "McpBridge.h"
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QIcon>
#include <QDebug>
#include <QQuickStyle>

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName("C2 Panel");
    app.setOrganizationName("C2");

    // 实测（2026-10-07）：默认使用 Windows 原生样式，它不支持自定义 Button.background，
    // 启动时刷 "The current style does not support customization of this control"，
    // 登录页的渐变按钮会被渲染成原生外观（自定义样式全被忽略）。
    // Basic 样式是官方文档给出的可定制样式，跨机器外观也一致。
    QQuickStyle::setStyle(QStringLiteral("Basic"));

    ApiClient api;
    AgentModel agentModel(&api);
    McpBridge mcp;

    QQmlApplicationEngine engine;
    // 实测（2026-10-07，Qt 6.9.3）：资源里的 QML 模块必须显式把 qrc 根加入导入路径，
    // 否则 `import C2Panel`（对应 qmldir 里的 module C2Panel）解析不到，
    // 报 "module C2Panel is not installed"，QML 加载失败 → 程序启动即 return -1。
    engine.addImportPath(QStringLiteral("qrc:/"));
    engine.rootContext()->setContextProperty("api", &api);
    engine.rootContext()->setContextProperty("agentModel", &agentModel);
    engine.rootContext()->setContextProperty("mcp", &mcp);

    // 修复点：qml.qrc 的 prefix 是 /C2Panel，条目是 main.qml，
    // 真实资源路径为 qrc:/C2Panel/main.qml。原来写 qrc:/qml/main.qml，
    // load() 必然失败 → rootObjects 为空 → 直接 return -1，
    // 现象是"双击没有任何窗口"，GUI 下连错误提示都看不到。
    engine.load(QUrl(QStringLiteral("qrc:/C2Panel/main.qml")));
    if (engine.rootObjects().isEmpty()) {
        qCritical() << "QML 加载失败: qrc:/C2Panel/main.qml （检查 qml.qrc 是否已随 target 编译进资源）";
        return -1;
    }
    return app.exec();
}
