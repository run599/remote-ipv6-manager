#include "ApiClient.h"
#include "AgentModel.h"
#include "McpBridge.h"
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QIcon>

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName("C2 Panel");
    app.setOrganizationName("C2");

    ApiClient api;
    AgentModel agentModel(&api);
    McpBridge mcp;

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("api", &api);
    engine.rootContext()->setContextProperty("agentModel", &agentModel);
    engine.rootContext()->setContextProperty("mcp", &mcp);

    engine.load(QUrl(QStringLiteral("qrc:/qml/main.qml")));
    if (engine.rootObjects().isEmpty()) return -1;
    return app.exec();
}
