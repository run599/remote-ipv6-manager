// ═══════════════════════════════════════════════════════════════════════════
// TrayIcon —— 管理端的右下角托盘（后台常驻）+ 开机自启动
//
// 为什么需要它：管理端要长期挂着看"谁在线、有没有待核验"，但把它一直摆在
// 桌面中间挡事。所以关窗口 = 收到右下角继续跑，真正退出只能从托盘菜单走。
//
// 实现选型：直接用 Win32 Shell_NotifyIcon，**不引入 QtWidgets** ——
//   ① 面板只链 Qt Quick/Controls/Network，为了一个托盘去拉整个 Widgets 不值得；
//   ② Qt.labs.platform 的 SystemTrayIcon 需要额外部署 Qt Labs 插件（有过
//
// 自启动：写 HKCU\...\CurrentVersion\Run（**当前用户**，不需要管理员）。
// 默认开启，但尊重用户的关闭选择 —— 关过之后就不再自动加回来（见 ensureAutoStart）。
// ═══════════════════════════════════════════════════════════════════════════
#pragma once

#include <QObject>
#include <QString>

class TrayIcon : public QObject {
    Q_OBJECT
public:
    explicit TrayIcon(QObject* parent = nullptr);
    ~TrayIcon() override;

    // 创建托盘图标（可重复调用，幂等）
    Q_INVOKABLE bool install(const QString& tooltip);
    Q_INVOKABLE void uninstall();

    // 右下角气泡提示（例如"已最小化到后台，仍在监控"）
    Q_INVOKABLE void balloon(const QString& title, const QString& body);

    // 开机自启动：查 / 设 / "按默认策略确保"
    Q_INVOKABLE bool autoStartEnabled() const;
    Q_INVOKABLE bool setAutoStart(bool on);
    Q_INVOKABLE QString exePath() const;
    // 默认开启；用户主动关过就不再自动加回来（用 QSettings 记住这个选择）
    Q_INVOKABLE void ensureAutoStart();

    // 托盘菜单里"开机自启动"那一项当前的勾选状态（供界面显示）
    Q_INVOKABLE bool autoStartMenuItemChecked() const { return autoStartEnabled(); }

signals:
    void showRequested();   // 左键单击 / 菜单"显示主界面"
    void quitRequested();   // 菜单"退出"

private:
    bool _installed = false;
};
