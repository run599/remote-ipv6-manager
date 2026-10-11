#pragma once
// TlsConfig.h —— 面板的统一 TLS 配置（自签证书）
//
// 为什么单独抽一个头：面板里有多个类各自发 HTTPS 请求（ApiClient / McpBridge，
// 以及后续可能新增的），而"接受自签证书"这件事必须**每个请求都设置**。
// 实测踩坑（2026-10-07 端到端）：ApiClient 设了、McpBridge 漏了，
// 结果是"能登录、但所有工具调用都失败"，报
//     SSL 握手失败: 为此目的，根 CA 证书不可信
// 界面表现只是终端里一行 [error]，很容易被当成服务端问题。
// 抽成共享头后，新增请求类只要 include 它就不会再漏。

#include <QSslConfiguration>
#include <QNetworkRequest>
#include <QSslSocket>

// 自签证书 TLS 配置：面板与服务端同属自有环境，
// 信任由部署边界保证（面板仅运维本机运行），跳过系统信任链校验。
//
// 安全性说明：这里用 VerifyNone 而不是标识固定（客户端 StubCore 用的是标识固定）。
// 面板运行在操作者本机、连的是自己的服务端，与客户端的威胁模型不同；
// 若要把面板也收紧到标识固定，应在此处读入服务端证书 DER 并做 SHA-256 比对，
// 而不是改回系统信任链（自签证书永远过不了系统信任链）。
inline QSslConfiguration r6mSelfSignedConfig() {
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    return cfg;
}

// 统一给请求套用：url 是 https 时才设置（http 下设置无害，但保持显式更清晰）
inline void r6mApplyTls(QNetworkRequest& req, const QString& url) {
    if (url.startsWith(QStringLiteral("https"), Qt::CaseInsensitive)) {
        req.setSslConfiguration(r6mSelfSignedConfig());
    }
}
