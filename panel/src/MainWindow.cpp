#include "MainWindow.h"
#include "AgentListWidget.h"
#include "McpPanelWidget.h"
#include "ShellTerminalWidget.h"
#include "FileExplorerWidget.h"
#include "TaskOrchestratorWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QFrame>
#include <QSplitter>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QMessageBox>
#include <QNetworkReply>
#include <QEventLoop>
#include <QTabBar>

// ═══════════════════════════════════════════════
// macOS Big Sur / Sonoma 风格样式表
// 特点：磨砂玻璃感、卡片阴影、圆角、SF字体
// ═══════════════════════════════════════════════
static const QString STYLESHEET = R"(
    /* ── 全局 ── */
    QMainWindow { background: #ededed; }
    QWidget { font-family: 'SF Pro Display', 'SF Pro Text', 'Segoe UI', 'Microsoft YaHei UI', sans-serif; font-size: 13px; color: #1d1d1f; }

    /* ── 主按钮（蓝色渐变）── */
    QPushButton#primaryBtn {
        background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #6CB4EE, stop:1 #0A84FF);
        border: none; border-radius: 6px; color: white;
        font-size: 13px; font-weight: 600; padding: 8px 18px;
        min-height: 18px;
    }
    QPushButton#primaryBtn:hover {
        background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #5AA3DD, stop:1 #0070E0);
    }
    QPushButton#primaryBtn:pressed {
        background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #4890CC, stop:1 #0060C0);
    }
    QPushButton#primaryBtn:disabled { background: #D1D1D6; color: #AEAEB2; }

    /* ── 次级按钮（灰色胶囊）── */
    QPushButton#secondaryBtn {
        background: rgba(0,0,0,0.05); border: 1px solid rgba(0,0,0,0.1);
        border-radius: 6px; color: #1d1d1f; font-size: 13px; font-weight: 500;
        padding: 7px 14px; min-height: 16px;
    }
    QPushButton#secondaryBtn:hover { background: rgba(0,0,0,0.08); }
    QPushButton#secondaryBtn:pressed { background: rgba(0,0,0,0.12); }

    /* ── 输入框 ── */
    QLineEdit {
        background: #ffffff; border: 1px solid rgba(0,0,0,0.1);
        border-radius: 6px; padding: 8px 12px; color: #1d1d1f; font-size: 13px;
        selection-background-color: #0A84FF;
    }
    QLineEdit:focus { border-color: #0A84FF; border-width: 1.5px; }

    /* ── 卡片（带阴影效果）── */
    QFrame#card {
        background: #ffffff; border: 1px solid rgba(0,0,0,0.06);
        border-radius: 10px;
    }

    /* ── 左侧栏（半透明磨砂感）── */
    QFrame#sidebar {
        background: rgba(245,245,247,0.92);
        border: 1px solid rgba(0,0,0,0.06);
        border-radius: 10px;
    }

    /* ── 顶部栏 ── */
    QFrame#topBar {
        background: rgba(255,255,255,0.85);
        border-bottom: 1px solid rgba(0,0,0,0.08);
    }

    /* ── 标签栏（macOS 分段控制风格）── */
    QPushButton#tabBtn {
        background: transparent; border: none;
        color: #86868B; font-size: 13px; font-weight: 500;
        padding: 6px 16px; border-radius: 6px; min-height: 18px;
    }
    QPushButton#tabBtn:hover { background: rgba(0,0,0,0.05); }
    QPushButton#tabBtn:checked {
        background: #ffffff; color: #1d1d1f; font-weight: 600;
        border: 1px solid rgba(0,0,0,0.08);
    }

    /* ── 状态标签 ── */
    QLabel#badgeGreen {
        background: rgba(52,199,89,0.12); color: #30B550;
        font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 10px;
    }
    QLabel#badgeBlue {
        background: rgba(10,132,255,0.10); color: #0A84FF;
        font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 10px;
    }
    QLabel#badgeGray {
        background: rgba(0,0,0,0.04); color: #8E8E93;
        font-size: 11px; font-weight: 500; padding: 3px 10px; border-radius: 10px;
    }

    /* ── 表格 ── */
    QTableWidget {
        border: none; background: transparent; gridline-color: transparent;
        font-size: 13px; selection-background-color: rgba(10,132,255,0.12);
        selection-color: #1d1d1f;
    }
    QTableWidget::item { padding: 6px 8px; border-bottom: 1px solid rgba(0,0,0,0.04); }
    QTableWidget::item:selected { background: rgba(10,132,255,0.10); }
    QTableWidget::item:hover { background: rgba(0,0,0,0.03); }
    QHeaderView::section {
        background: rgba(0,0,0,0.02); border: none;
        padding: 8px 10px; font-size: 11px; font-weight: 600;
        color: #86868B; text-transform: uppercase;
    }

    /* ── 滚动条 ── */
    QScrollBar:vertical {
        background: transparent; width: 8px; margin: 0;
    }
    QScrollBar::handle:vertical {
        background: rgba(0,0,0,0.15); border-radius: 4px; min-height: 30px;
    }
    QScrollBar::handle:vertical:hover { background: rgba(0,0,0,0.25); }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }

    /* ── 文本编辑 ── */
    QTextEdit {
        background: #1E1E2E; color: #CDD6F4; border: 1px solid rgba(0,0,0,0.08);
        border-radius: 8px; padding: 10px; font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
        font-size: 13px; selection-background-color: rgba(10,132,255,0.3);
    }

    /* ── 下拉框 ── */
    QComboBox {
        background: #ffffff; border: 1px solid rgba(0,0,0,0.1);
        border-radius: 6px; padding: 7px 12px; font-size: 13px;
    }
    QComboBox:hover { border-color: #0A84FF; }
    QComboBox::drop-down { border: none; width: 24px; }
    QComboBox::down-arrow { image: none; border-left: 4px solid transparent;
        border-right: 4px solid transparent; border-top: 5px solid #8E8E93; margin-right: 8px; }
)";

MainWindow::MainWindow(const QString& serverUrl, const QString& cookie, QWidget* parent)
    : QMainWindow(parent), _serverUrl(serverUrl), _cookie(cookie) {
    _nam = new QNetworkAccessManager(this);
    setWindowTitle("C2 Command Center");
    setMinimumSize(1280, 800);
    setStyleSheet(STYLESHEET);
    setupUi();
    setupConnections();
    _refreshTimer = new QTimer(this);
    connect(_refreshTimer, &QTimer::timeout, this, &MainWindow::refreshAll);
    _refreshTimer->start(5000);
    refreshAll();
}

void MainWindow::setupUi() {
    QWidget* central = new QWidget();
    central->setStyleSheet("background: #ededed;");
    setCentralWidget(central);
    QVBoxLayout* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // ═══ 顶部标题栏（磨砂玻璃风格）═══
    QFrame* toolbar = new QFrame();
    toolbar->setObjectName("topBar");
    toolbar->setFixedHeight(52);
    QHBoxLayout* tl = new QHBoxLayout(toolbar);
    tl->setContentsMargins(24, 0, 24, 0);
    tl->setSpacing(10);

    // Logo 圆形
    QLabel* logoBg = new QLabel();
    logoBg->setFixedSize(32, 32);
    logoBg->setStyleSheet("background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #0A84FF, stop:1 #5856D6); border-radius: 16px;");
    QLabel* logoIcon = new QLabel("⌘");
    logoIcon->setStyleSheet("color: white; font-size: 18px; font-weight: 700;");
    logoIcon->setAlignment(Qt::AlignCenter);
    QVBoxLayout* logoStack = new QVBoxLayout(logoBg);
    logoStack->setContentsMargins(0, 0, 0, 0);
    logoStack->addWidget(logoIcon);
    tl->addWidget(logoBg);

    QLabel* title = new QLabel("C2 Command Center");
    title->setStyleSheet("font-size: 15px; font-weight: 700; color: #1d1d1f; letter-spacing: -0.3px;");
    tl->addWidget(title);
    tl->addSpacing(20);

    // 右侧徽标
    _agentCountLabel = new QLabel("● 0 Online");
    _agentCountLabel->setObjectName("badgeGreen");
    tl->addWidget(_agentCountLabel);

    _toolCountLabel = new QLabel("⚡ 0 Tools");
    _toolCountLabel->setObjectName("badgeBlue");
    tl->addWidget(_toolCountLabel);

    tl->addStretch();

    QLabel* serverBadge = new QLabel(_serverUrl);
    serverBadge->setObjectName("badgeGray");
    tl->addWidget(serverBadge);

    root->addWidget(toolbar);

    // ═══ 内容区 ═══
    QWidget* content = new QWidget();
    content->setStyleSheet("background: #ededed;");
    QHBoxLayout* cl = new QHBoxLayout(content);
    cl->setContentsMargins(16, 12, 16, 8);
    cl->setSpacing(12);

    // 左侧：客户端列表（磨砂侧边栏）
    _agentList = new AgentListWidget();
    _agentList->setObjectName("sidebar");
    cl->addWidget(_agentList);

    // 右侧：标签页面板
    QWidget* rightPanel = new QWidget();
    rightPanel->setObjectName("card");
    QVBoxLayout* rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(12, 12, 12, 12);
    rightLayout->setSpacing(0);

    // 分段控制标签栏（macOS Segmented Control 风格）
    QFrame* segControl = new QFrame();
    segControl->setFixedHeight(36);
    segControl->setStyleSheet("QFrame { background: rgba(0,0,0,0.04); border-radius: 8px; }");
    QHBoxLayout* segLayout = new QHBoxLayout(segControl);
    segLayout->setContentsMargins(3, 3, 3, 3);
    segLayout->setSpacing(2);

    _rightStack = new QStackedWidget();
    struct TabInfo { QString label; };
    QList<TabInfo> tabs = {{"🖥 终端"}, {"🔧 工具"}, {"📁 文件"}, {"⚡ 任务"}};
    QList<QPushButton*> tabBtns;

    for (int i = 0; i < tabs.size(); i++) {
        QPushButton* btn = new QPushButton(tabs[i].label);
        btn->setObjectName("tabBtn");
        btn->setCheckable(true);
        btn->setChecked(i == 0);
        btn->setFixedHeight(30);
        segLayout->addWidget(btn);
        tabBtns.append(btn);
        connect(btn, &QPushButton::clicked, this, [this, i, tabBtns]() {   // 按值捕获：原来按引用捕获局部 QList，函数返回后即悬垂
            _rightStack->setCurrentIndex(i);
            for (int j = 0; j < tabBtns.size(); j++) tabBtns[j]->setChecked(j == i);
        });
    }
    rightLayout->addWidget(segControl);
    rightLayout->addSpacing(8);

    // 初始化四个面板
    _shellTerminal = new ShellTerminalWidget();
    _rightStack->addWidget(_shellTerminal);

    _mcpPanel = new McpPanelWidget();
    _rightStack->addWidget(_mcpPanel);

    _fileExplorer = new FileExplorerWidget();
    _rightStack->addWidget(_fileExplorer);

    _taskOrchestrator = new TaskOrchestratorWidget();
    _rightStack->addWidget(_taskOrchestrator);

    rightLayout->addWidget(_rightStack, 1);
    cl->addWidget(rightPanel, 1);

    root->addWidget(content, 1);

    // ═══ 底部状态栏 ═══
    QFrame* footer = new QFrame();
    footer->setFixedHeight(32);
    footer->setStyleSheet("QFrame { background: rgba(255,255,255,0.8); border-top: 1px solid rgba(0,0,0,0.06); }");
    QHBoxLayout* fl = new QHBoxLayout(footer);
    fl->setContentsMargins(24, 0, 24, 0);
    QLabel* vLabel = new QLabel("C2 Panel v2.0");
    vLabel->setStyleSheet("color: #8E8E93; font-size: 11px;");
    fl->addWidget(vLabel);
    fl->addStretch();
    QLabel* techLabel = new QLabel("C++ Qt6 · IPv6 · MCP");
    techLabel->setStyleSheet("color: #AEAEB2; font-size: 11px;");
    fl->addWidget(techLabel);
    root->addWidget(footer);
}

void MainWindow::setupConnections() {
    connect(_agentList, &AgentListWidget::agentSelected, this, &MainWindow::onAgentSelected);
}

// ── API ──

QString MainWindow::apiGet(const QString& path) {
    QNetworkRequest req(QUrl(_serverUrl + path));
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->get(req);
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    QString result = reply->readAll();
    reply->deleteLater();
    return result;
}

QString MainWindow::apiPost(const QString& path, const QByteArray& body) {
    QNetworkRequest req(QUrl(_serverUrl + path));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->post(req, body);
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    QString result = reply->readAll();
    reply->deleteLater();
    return result;
}

// ── 业务逻辑 ──

void MainWindow::refreshAll() {
    QString agentsJson = apiGet("/api/agents");
    QJsonDocument doc = QJsonDocument::fromJson(agentsJson.toUtf8());
    _agents.clear();
    int onlineCount = 0;
    for (const auto& v : doc.array()) {
        QJsonObject a = v.toObject();
        AgentInfo info;
        info.hwid = a["hwid"].toString();
        info.user = a["user"].toString();
        info.os = a["os"].toString();
        info.ip = a["ip"].toString();
        info.online = a["online"].toBool();
        info.lastSeen = a["last_seen"].toString();
        _agents.append(info);
        if (info.online) onlineCount++;
    }
    _agentCountLabel->setText(QString("● %1 Online").arg(onlineCount));
    _agentList->setAgents(_agents);
    _taskOrchestrator->setAgents(_agents);
    _taskOrchestrator->setServerInfo(_serverUrl, _cookie);
}

void MainWindow::onAgentSelected(const QString& hwid) {
    _selectedHwid = hwid;
    _mcpPanel->setSelectedAgent(hwid, _serverUrl, _cookie);
    _shellTerminal->setAgent(hwid, _serverUrl, _cookie);
    _fileExplorer->setAgent(hwid, _serverUrl, _cookie);
    _taskOrchestrator->setSelectedAgent(hwid);   // 让"仅选中 Agent"分支真的可用
    refreshAll();
}

void MainWindow::onTabChanged(int index) {
    _rightStack->setCurrentIndex(index);
}