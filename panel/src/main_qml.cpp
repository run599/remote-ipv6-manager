#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include "ApiClient.h"
#include "AgentModel.h"
#include "McpBridge.h"

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName("RMM Panel");
    app.setOrganizationName("RMM");

    ApiClient api;
    AgentModel agents(&api);
    McpBridge mcp;

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("api", &api);
    engine.rootContext()->setContextProperty("agentModel", &agents);
    engine.rootContext()->setContextProperty("mcp", &mcp);

    engine.load(QUrl(QStringLiteral("qrc:/RMMPanel/qml/main.qml")));
    if (engine.rootObjects().isEmpty()) return -1;

    return app.exec();
}
