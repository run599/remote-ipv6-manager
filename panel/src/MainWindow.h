#pragma once
#include <QMainWindow>
#include <QLabel>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QVector>
#include <QStackedWidget>

class AgentListWidget;
class McpPanelWidget;
class ShellTerminalWidget;
class FileExplorerWidget;
class TaskOrchestratorWidget;

#include "AgentInfo.h"

// ═══════════════════════════════════════════════
// 主窗口 — macOS 风格
// 顶部状态栏 + 左侧客户端列表 + 右侧多标签面板
// ═══════════════════════════════════════════════

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(const QString& serverUrl, const QString& cookie, QWidget* parent = nullptr);

private slots:
    void refreshAll();
    void onAgentSelected(const QString& hwid);
    void onTabChanged(int index);

private:
    void setupUi();
    void setupConnections();
    void setupTabs();
    QString apiGet(const QString& path);
    QString apiPost(const QString& path, const QByteArray& body);

    QString _serverUrl;
    QString _cookie;
    QNetworkAccessManager* _nam;
    QTimer* _refreshTimer;
    QVector<AgentInfo> _agents;
    QString _selectedHwid;

    // UI 组件
    QLabel* _statusBadge;
    QLabel* _agentCountLabel;
    QLabel* _toolCountLabel;
    AgentListWidget* _agentList;
    McpPanelWidget* _mcpPanel;
    ShellTerminalWidget* _shellTerminal;
    FileExplorerWidget* _fileExplorer;
    TaskOrchestratorWidget* _taskOrchestrator;
    QStackedWidget* _rightStack;
};