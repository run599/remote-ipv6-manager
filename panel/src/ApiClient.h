#pragma once
#include <QDateTime>
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QString>

// ═══════════════════════════════════════════════
// HTTP 客户端 — QML 通过 Q_INVOKABLE 调用
// ═══════════════════════════════════════════════

class ApiClient : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString serverUrl READ serverUrl WRITE setServerUrl NOTIFY serverUrlChanged)
    Q_PROPERTY(bool connected READ connected NOTIFY connectedChanged)
    // QML 需要 cookie 值（LoginPage 会把它传给各页签）：
    Q_PROPERTY(QString cookie READ cookie NOTIFY cookieChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY lastErrorChanged)

public:
    explicit ApiClient(QObject* parent = nullptr);

    QString serverUrl() const { return _serverUrl; }
    void setServerUrl(const QString& url);
    bool connected() const { return _connected; }
    QString cookie() const { return _cookie; }
    QString lastError() const { return _lastError; }

    // QML 可调用
    Q_INVOKABLE QString login(const QString& user, const QString& pass);
    Q_INVOKABLE QString get(const QString& path);
    Q_INVOKABLE QString post(const QString& path, const QString& body);

    // ── 文件投放/取回需要的三个新能力 ──
    // 原来只有 get/post 两个"收发字符串"的接口，所以文件这类**二进制**根本进不来也出不去：
    // 投放页只能投放服务端 filestore 里已有的文件（得先用别的手段把文件弄上去），
    // 文件页的"上传/下载"则一直是空壳。
    //
    // uploadFile：把**本机**文件以 multipart 上传到服务端 filestore，返回服务端 JSON。
    Q_INVOKABLE QString uploadFile(const QString& localPath);

    // saveBase64Chunk：把 base64 片段解码后写入(append=false)/追加(append=true)到本机文件。
    // 为什么按"片段"设计：读回远端文件走的是受管端 shell_exec 的 powershell 工具，
    // 返回空串 = 成功；非空 = 错误原因（不要把错误吞掉，否则又是一次"静默失效"）。
    Q_INVOKABLE QString saveBase64Chunk(const QString& localPath, const QString& b64, bool append);

    // localFileInfo：本机文件的存在性/大小/基名（JSON），投放前给个明确提示。
    Q_INVOKABLE QString localFileInfo(const QString& localPath);

    // readLocalFileBase64：读**本机**文件的指定片段并返回 base64（空串=失败）。
    // 用途：把本机文件直接写到受管端（走 file_browser 的 write_file，免走 filestore 中转）。
    // 为什么带 offset/length：大文件要分片写，受管端侧靠 append=true 追加。
    // 失败时返回空串，原因放 lastError（QML 侧读 api.lastError）。
    Q_INVOKABLE QString readLocalFileBase64(const QString& localPath, int offset, int length);

    // ── 本机文件选择（Win32 通用对话框）──
    // 为什么不用 QtQuick.Dialogs：它是**插件模块**，部署里少一个 DLL 就报
    // comdlg32 是系统自带的，零部署依赖、零 Qt 模块依赖。
    // filter 用 '|' 分隔：描述|模式|描述|模式（C++ 侧转成 Win32 的 \0 分隔 + 结尾双 \0）
    Q_INVOKABLE QString pickOpenFile(const QString& title, const QString& filter);
    // 保存对话框：defaultName 作为预填文件名，返回选定的完整路径；取消返回空串
    Q_INVOKABLE QString pickSaveFile(const QString& title, const QString& defaultName);

    // ── 凭据自启动配置 ──
    // 地址/用户名明文存；**密码用 Windows DPAPI 加密后存**（不明文落盘，
    // 且绑定当前用户；换用户/换机解不出来就返回空串，要求重输）。
    // 不这么做就不敢做"记住密码" —— 面板的凭据是服务端管理员口令。
    Q_INVOKABLE QString savedServer() const;
    Q_INVOKABLE QString savedUser() const;
    Q_INVOKABLE QString savedPass() const;
    Q_INVOKABLE void    saveCreds(const QString& server, const QString& user,
                                  const QString& pass, bool remember);

signals:
    // 就停在主界面空转 —— 每 5 秒刷一次 401，列表里显示的却是**缓存的旧数据**，
    // 用户看到"客户端在线"，点任何命令都失败（响应体是 {"error":"unauthorized"}，
    // 被当成命令输出显示成 "Host requires authentication"）。
    // 实测证据：面板 stderr 连续刷
    //   qt.network.http2: stream N finished with error: "Host requires authentication"
    //   agents 响应不是数组，保留旧数据
    // 而服务端侧一条 /api/screen 日志都没有（请求根本没通过鉴权）。
    void sessionExpired();
    void serverUrlChanged();
    void connectedChanged();
    void cookieChanged();
    void lastErrorChanged();

private:
    QString _serverUrl;
    QString _cookie;
    bool _connected = false;
    QString _lastError;
    // 最近一次请求的 HTTP 状态码与服务端错误码。
    // 为什么要单独存：Qt 把 4xx/5xx 也算作 reply->error()，光看 error() 分不清
    // "密码错(401)" 和 "被限流(429)" 和 "根本没连上(0)"，而这三者给用户的建议完全不同。
    int _lastStatus = 0;
    qint64 _lastExpiredMs = 0;   // 401 去重时间戳
    void notifySessionExpired();
    QString _lastServerError;
    QNetworkAccessManager _nam;

    void saveCookie(QNetworkReply* reply);
    void setLastError(const QString& err);
};
