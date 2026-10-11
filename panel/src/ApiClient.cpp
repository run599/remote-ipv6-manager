#include "ApiClient.h"
#include <functional>
#include <exception>

#include <QSettings>
#include <QByteArray>
#ifdef Q_OS_WIN
#include <windows.h>
#include <wincrypt.h>
#endif

// ── 凭据自启动配置辅助 ──
// DPAPI：只对这些字节加密，密钥由 Windows 按当前用户派生 —— 别的用户/别的机器
// 解不出来（这正是我们要的：即使配置文件被拷走也读不出面板口令）。
namespace {
const char* kOrg = "r6m";
const char* kApp = "RMMPanel";

#ifdef Q_OS_WIN
QString dpapiProtect(const QString& plain) {
    if (plain.isEmpty()) return QString();
    QByteArray in = plain.toUtf8();
    DATA_BLOB din{ static_cast<DWORD>(in.size()),
                   reinterpret_cast<BYTE*>(in.data()) }, dout{};
    if (!CryptProtectData(&din, L"r6m-panel-cred", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &dout)) {
        return QString();
    }
    QByteArray blob(reinterpret_cast<const char*>(dout.pbData), static_cast<int>(dout.cbData));
    LocalFree(dout.pbData);
    return QString::fromLatin1(blob.toBase64());
}
QString dpapiUnprotect(const QString& b64) {
    if (b64.isEmpty()) return QString();
    QByteArray blob = QByteArray::fromBase64(b64.toLatin1());
    if (blob.isEmpty()) return QString();
    DATA_BLOB din{ static_cast<DWORD>(blob.size()),
                   reinterpret_cast<BYTE*>(blob.data()) }, dout{};
    if (!CryptUnprotectData(&din, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &dout)) {
        return QString();   // 换用户/换机  解不出，优雅退回要求重输
    }
    QString out = QString::fromUtf8(reinterpret_cast<const char*>(dout.pbData),
                                    static_cast<int>(dout.cbData));
    LocalFree(dout.pbData);
    return out;
}
#endif
}  // namespace


// ── 跨 QML 边界的异常护栏（2026-10-10）──────────────────────────────────────
//   错误模块 Qt6Core.dll / 异常代码 **0xC0000602（STATUS_FAIL_FAST_EXCEPTION）**
static QString r6mGuard(const char* where, const std::function<QString()>& fn) {
    try {
        return fn();
    } catch (const std::exception& e) {
        return QString("{\"error\":\"%1 异常: %2\"}").arg(where).arg(QString::fromUtf8(e.what()));
    } catch (...) {
        return QString("{\"error\":\"%1 未知异常\"}").arg(where);
    }
}

QString ApiClient::savedServer() const {
    QSettings s(kOrg, kApp);
    return s.value(QStringLiteral("server")).toString();
}

QString ApiClient::savedUser() const {
    QSettings s(kOrg, kApp);
    return s.value(QStringLiteral("user")).toString();
}

QString ApiClient::savedPass() const {
#ifdef Q_OS_WIN
    QSettings s(kOrg, kApp);
    return dpapiUnprotect(s.value(QStringLiteral("pass_enc")).toString());
#else
    return QString();
#endif
}

void ApiClient::saveCreds(const QString& server, const QString& user,
                          const QString& pass, bool remember) {
    QSettings s(kOrg, kApp);
    s.setValue(QStringLiteral("server"), server);
    s.setValue(QStringLiteral("user"), user);
    s.setValue(QStringLiteral("remember"), remember);
#ifdef Q_OS_WIN
    // 不勾"记住密码"时把密文一起清掉 —— 否则"不记住"只是不起作用
    s.setValue(QStringLiteral("pass_enc"), remember ? dpapiProtect(pass) : QString());
#else
    Q_UNUSED(pass);
#endif
    s.sync();
}
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkCookie>
#include <windows.h>
#include <commdlg.h>
#include <QStringList>
#include <QHttpMultiPart>
#include <QHttpPart>
#include <QFile>
#include <QFileInfo>
#include <QEventLoop>
#include <QSslConfiguration>
#include "TlsConfig.h"

ApiClient::ApiClient(QObject* parent) : QObject(parent) {}

void ApiClient::setServerUrl(const QString& url) {
    if (_serverUrl != url) { _serverUrl = url; emit serverUrlChanged(); }
}

// TLS 配置已抽到 TlsConfig.h（原先只在本文件里，McpBridge 漏设导致工具调用全部 SSL 失败）

QString ApiClient::login(const QString& user, const QString& pass) {
    return r6mGuard("login", [&]() -> QString {
    QJsonObject body;
    body["user"] = user;
    body["pass"] =  pass;
    QString resp = post("/api/login", QJsonDocument(body).toJson());
    if (!_lastError.isEmpty()) {
        // 真正的传输层失败（地址写错/证书/超时/代理）：与"密码错"分开报，
        // 用户才知道该改地址还是改密码。
        if (_connected) { _connected = false; emit connectedChanged(); }
        return resp;
    }
    QJsonDocument doc = QJsonDocument::fromJson(resp.toUtf8());
    const bool ok = doc.isObject() && doc.object().value("ok").toBool();
    if (ok != _connected) {
        _connected = ok;
        emit connectedChanged();
    }
    if (!ok) {
        // 按 HTTP 状态码给具体原因。
        // 之前这里只有一句"用户名或密码不正确"，而且因为 post() 把 4xx 也当成网络错误、
        // login() 提前 return，这句**根本到不了用户眼前** —— 用户看到的是
        // "/api/login: 需要验证"（Qt 对 401 的本地化系统错误串），完全无法判断该改什么。
        QString msg;
        const int retryAfter = doc.object().value("retry_after").toInt();
        switch (_lastStatus) {
        case 401:
            msg = QStringLiteral("用户名或密码不正确");
            break;
        case 429:
            msg = retryAfter > 0
                  ? QStringLiteral("登录失败次数过多，服务端已临时锁定，请 %1 秒后重试").arg(retryAfter)
                  : QStringLiteral("登录失败次数过多，服务端已临时锁定，请稍后重试");
            break;
        case 407:
            msg = QStringLiteral("系统代理要求身份验证（HTTP 407）：请检查系统代理设置");
            break;
        case 400:
            msg = QStringLiteral("请求被服务端拒绝（HTTP 400）");
            break;
        default:
            if (_lastStatus >= 500) {
                msg = QStringLiteral("服务端内部错误（HTTP %1）").arg(_lastStatus);
            } else if (_lastStatus > 0) {
                msg = QStringLiteral("登录失败（HTTP %1%2）")
                          .arg(_lastStatus)
                          .arg(_lastServerError.isEmpty() ? QString()
                                                          : QStringLiteral("：") + _lastServerError);
            } else {
                msg = QStringLiteral("登录失败：服务端未返回有效响应");
            }
            break;
        }
        setLastError(msg);
    }
    return resp;
    });
}

// 401 去重：刷新定时器与用户操作可能同时触发多个请求，
// 每个都回 401 时不该连发 N 次信号（QML 侧会反复重置状态）。
void ApiClient::notifySessionExpired() {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (now - _lastExpiredMs < 5000) return;
    _lastExpiredMs = now;
    if (_connected) { _connected = false; emit connectedChanged(); }
    emit sessionExpired();
}

QString ApiClient::get(const QString& path) {
    return r6mGuard("get", [&]() -> QString {
    QNetworkRequest req(QUrl(_serverUrl + path));
    if (_serverUrl.startsWith("https", Qt::CaseInsensitive)) {
        req.setSslConfiguration(r6mSelfSignedConfig());
    }
    // 修复点：原来不设传输超时，IPv6 半开连接会让 loop.exec() 卡满 TCP 超时（数分钟），
    // 且 5 秒一轮的刷新定时器会在嵌套事件循环里重入叠加。
    req.setTransferTimeout(8000);
    if (!_cookie.isEmpty()) req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam.get(req);
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    saveCookie(reply);
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QString errStr = reply->errorString();
    const QNetworkReply::NetworkError nerr = reply->error();
    QString result = QString::fromUtf8(reply->readAll());
    reply->deleteLater();

    if (status != 0) {
        // 拿到了 HTTP 状态码：这不是"传输失败"，把 body 交给调用方判断。
        // （原来只要 error()!=NoError 就当成网络错误，4xx 也走这条路，
        //   结果所有失败都退化成一句看不懂的 path + 系统错误串）
        _lastStatus = status;
        setLastError(QString());
        if (status == 401) notifySessionExpired();
        return result;
    }
    _lastStatus = 0;
    if (nerr != QNetworkReply::NoError) {
        setLastError(QString("%1: %2").arg(path, errStr));
        return QString();   // 调用方必须区分"空"与"失败"（AgentModel 已改为失败时保留旧数据）
    }
    setLastError(QString());
    return result;
    });
}

QString ApiClient::post(const QString& path, const QString& body) {
    return r6mGuard("post", [&]() -> QString {
    QNetworkRequest req(QUrl(_serverUrl + path));
    if (_serverUrl.startsWith("https", Qt::CaseInsensitive)) {
        req.setSslConfiguration(r6mSelfSignedConfig());
    }
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (!_cookie.isEmpty()) req.setRawHeader("Cookie", _cookie.toUtf8());
    req.setTransferTimeout(15000);
    QNetworkReply* reply = _nam.post(req, body.toUtf8());
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    saveCookie(reply);
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QString errStr = reply->errorString();
    const QNetworkReply::NetworkError nerr = reply->error();
    QString result = QString::fromUtf8(reply->readAll());
    reply->deleteLater();

    if (status != 0) {
        _lastStatus = status;
        // 把服务端的 error 字段抠出来备用（服务端鉴权失败回 {"error":"unauthorized"} 等）
        _lastServerError.clear();
        const QJsonDocument d = QJsonDocument::fromJson(result.toUtf8());
        if (d.isObject()) _lastServerError = d.object().value("error").toString();
        setLastError(QString());   // 有状态码 = 已连上，不算传输错误
        // 登录接口本身回 401 是"密码错"，不该触发会话失效；其余接口回 401
        // 一律说明会话已失效，必须让界面回到登录页并说明原因。
        if (status == 401 && !path.contains("/api/login")) notifySessionExpired();
        return result;
    }
    _lastStatus = 0;
    if (nerr != QNetworkReply::NoError) {
        setLastError(QString("%1: %2").arg(path, errStr));
        return QString();
    }
    setLastError(QString());
    return result;
    });
}

// 修复点：原来把整条 Set-Cookie 原文当 Cookie 头回发
// （"c2session=xxx; Path=/; HttpOnly; Secure; SameSite=Strict"），
// 按 RFC 6265 请求头只应含 name=value 对，严格的服务端会 400/401。
void ApiClient::saveCookie(QNetworkReply* reply) {
    for (const auto& c : reply->rawHeaderPairs()) {
        if (c.first.toLower() == "set-cookie") {
            const QString trimmed = QString::fromUtf8(c.second).section(';', 0, 0).trimmed();
            if (trimmed != _cookie) {
                _cookie = trimmed;
                emit cookieChanged();
            }
        }
    }
}

void ApiClient::setLastError(const QString& err) {
    if (_lastError != err) {
        _lastError = err;
        emit lastErrorChanged();
    }
}

// ───────────────────────────────────────────────────────────────────────────
// 文件投放 / 取回
// ───────────────────────────────────────────────────────────────────────────

// 把本机文件上传到服务端 filestore（multipart/form-data，字段名 file）。
// 同步等待，返回形状与 get/post 一致：服务端 JSON 原文；传输失败返回空串。
QString ApiClient::uploadFile(const QString& localPath) {
    QFileInfo fi(localPath);
    if (!fi.exists() || !fi.isFile())
        return QStringLiteral("{\"error\":\"本机没有这个文件\"}");
    if (fi.size() <= 0)
        return QStringLiteral("{\"error\":\"文件是空的\"}");
    if (fi.size() > (64LL << 20))
        return QStringLiteral("{\"error\":\"文件超过服务端 64MB 上限\"}");

    QFile* f = new QFile(localPath);
    if (!f->open(QIODevice::ReadOnly)) {
        delete f;
        // 被别的进程独占是常见原因（exe 正在运行、Office 文档被打开）
        return QStringLiteral("{\"error\":\"打不开本机文件（可能被占用）\"}");
    }

    QNetworkRequest req(QUrl(_serverUrl + "/api/files/upload"));
    if (_serverUrl.startsWith("https", Qt::CaseInsensitive)) {
        req.setSslConfiguration(r6mSelfSignedConfig());
    }
    if (!_cookie.isEmpty()) req.setRawHeader("Cookie", _cookie.toUtf8());
    // 大文件要放宽；不能用 post() 里那个 15 秒（几十 MB 传不完就被判超时）
    req.setTransferTimeout(600000);

    QHttpMultiPart* mp = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    QHttpPart part;
    part.setHeader(QNetworkRequest::ContentDispositionHeader,
                   QString("form-data; name=\"file\"; filename=\"%1\"").arg(fi.fileName()));
    part.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/octet-stream"));
    part.setBodyDevice(f);
    f->setParent(mp);              // 生命周期交给 multipart，reply 结束后一起释放
    mp->append(part);

    QNetworkReply* reply = _nam.post(req, mp);
    mp->setParent(reply);
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    saveCookie(reply);
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QNetworkReply::NetworkError nerr = reply->error();
    const QString errStr = reply->errorString();
    QString result = QString::fromUtf8(reply->readAll());
    reply->deleteLater();

    if (status != 0) {
        _lastStatus = status;
        const QJsonDocument d = QJsonDocument::fromJson(result.toUtf8());
        if (d.isObject()) _lastServerError = d.object().value("error").toString();
        setLastError(QString());
        if (status == 401) notifySessionExpired();
        return result;
    }
    _lastStatus = 0;
    if (nerr != QNetworkReply::NoError) {
        setLastError(QString("uploadFile: %1").arg(errStr));
        return QString();
    }
    setLastError(QString());
    return result;
}

// 把 base64 片段写成本机文件的一部分。返回空串表示成功。
QString ApiClient::saveBase64Chunk(const QString& localPath, const QString& b64, bool append) {
    QByteArray clean = b64.toUtf8();
    clean = clean.trimmed();
    clean.replace("\r", "").replace("\n", "").replace(" ", "");
    if (clean.isEmpty()) return QStringLiteral("片段为空（远端可能没读出内容）");
    const QByteArray raw = QByteArray::fromBase64(clean);
    if (raw.isEmpty()) return QStringLiteral("base64 解码为空（片段可能被上游截断）");

    QFile f(localPath);
    const QIODevice::OpenMode mode = append
        ? QIODevice::OpenMode(QIODevice::WriteOnly | QIODevice::Append)
        : QIODevice::OpenMode(QIODevice::WriteOnly | QIODevice::Truncate);
    if (!f.open(mode)) return QStringLiteral("打不开本机目标文件（路径或权限问题）");
    const qint64 w = f.write(raw);
    f.close();
    if (w != raw.size()) return QStringLiteral("写入不完整（磁盘满？）");
    return QString();
}


QString ApiClient::readLocalFileBase64(const QString& localPath, int offset, int length) {
    setLastError(QString());
    QFile f(localPath);
    if (!f.open(QIODevice::ReadOnly)) {
        setLastError(QStringLiteral("打不开本机文件（被占用或无权限）"));
        return QString();
    }
    if (offset < 0) offset = 0;
    if (length <= 0) length = 1 << 20;
    if (!f.seek((qint64)offset)) {
        f.close();
        setLastError(QStringLiteral("定位失败（偏移超出文件）"));
        return QString();
    }
    const QByteArray raw = f.read((qint64)length);
    f.close();
    if (raw.isEmpty() && offset < (int)f.size()) {
        setLastError(QStringLiteral("读到 0 字节"));
        return QString();
    }
    return QString::fromLatin1(raw.toBase64());
}

// 本机文件信息（JSON），给界面做提示用。
QString ApiClient::localFileInfo(const QString& localPath) {
    QFileInfo fi(localPath);
    QJsonObject o;
    o.insert("exists", fi.exists());
    o.insert("is_file", fi.isFile());
    o.insert("size", (double)fi.size());
    o.insert("name", fi.fileName());
    o.insert("dir", fi.absolutePath());
    return QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact));
}

// ───────────────────────────────────────────────────────────────────────────
// 本机文件选择（Win32 通用对话框）
// ───────────────────────────────────────────────────────────────────────────
// 把 QML 传来的 '|' 分隔过滤器转成 Win32 要的格式：描述\0模式\0描述\0模式\0\0
static std::wstring buildWinFilter(const QString& filter) {
    std::wstring f;
    if (filter.isEmpty()) {
        f = L"All files (*.*)";
        f.push_back(L'\0');
        f += L"*.*";
        f.push_back(L'\0');
    } else {
        const QStringList parts = filter.split('|');
        for (const QString& p : parts) {
            f += p.toStdWString();
            f.push_back(L'\0');
        }
    }
    f.push_back(L'\0');   // 结尾必须是两个 NUL
    return f;
}

QString ApiClient::pickOpenFile(const QString& title, const QString& filter) {
    std::wstring f = buildWinFilter(filter);
    std::wstring t = title.toStdWString();
    wchar_t buf[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;          // 拿不到主窗口句柄也无妨：非模态所有权不影响可用性
    ofn.lpstrFilter = f.c_str();
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = t.empty() ? nullptr : t.c_str();
    // NOCHANGEDIR：不改进程当前目录（QML 那边有相对路径假设，别踩）
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return QString();   // 取消
    return QString::fromWCharArray(buf);
}

QString ApiClient::pickSaveFile(const QString& title, const QString& defaultName) {
    std::wstring t = title.toStdWString();
    wchar_t buf[MAX_PATH] = {};
    if (!defaultName.isEmpty()) {
        const std::wstring d = defaultName.toStdWString();
        wcsncpy(buf, d.c_str(), MAX_PATH - 1);
    }
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = L"All files (*.*)\0*.*\0\0";
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = t.empty() ? nullptr : t.c_str();
    ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn)) return QString();   // 取消
    return QString::fromWCharArray(buf);
}
