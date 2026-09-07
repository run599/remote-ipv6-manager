#include "MainWindow.h"
#include <QApplication>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QEventLoop>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setStyle("Fusion");

    // 默认服务器地址（250 的 IPv6，TLS）
    QString server = "https://[2001:db8:YOUR-SERVER-IPv6-HERE]:8443";

    // 登录
    QNetworkAccessManager nam;
    QNetworkRequest loginReq(QUrl(server + "/api/login"));
    loginReq.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QNetworkReply* reply = nam.post(loginReq, R"({"user":"admin","pass":"YOUR-PASSWORD"})");
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    QString cookie;
    for (const auto& h : reply->rawHeaderPairs()) {
        if (QString(h.first).toLower().contains("set-cookie")) {
            cookie = QString(h.second).split(';').first();
            break;
        }
    }
    reply->deleteLater();

    if (cookie.isEmpty()) {
        QMessageBox::critical(nullptr, "错误", "登录失败");
        return 1;
    }

    MainWindow w(server, cookie);
    w.show();
    return app.exec();
}