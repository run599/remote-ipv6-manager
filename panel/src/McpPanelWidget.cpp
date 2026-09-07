#include "McpPanelWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkReply>

McpPanelWidget::McpPanelWidget(QWidget* parent) : QFrame(parent) {
    setStyleSheet("QFrame { background: #ffffff; border: 1px solid #e5e5ea; border-radius: 12px; }");
    _nam = new QNetworkAccessManager(this);

    QVBoxLayout* sl = new QVBoxLayout(this);
    sl->setContentsMargins(16, 16, 16, 16);
    sl->setSpacing(10);

    // 标题行
    QHBoxLayout* titleRow = new QHBoxLayout();
    QLabel* title = new QLabel("🔧 MCP 远程工具");
    title->setStyleSheet("font-size: 15px; font-weight: 700; color: #1d1d1f;");
    titleRow->addWidget(title);
    titleRow->addStretch();
    _statusLabel = new QLabel("未选择客户端");
    _statusLabel->setStyleSheet("font-size: 11px; color: #86868b;");
    titleRow->addWidget(_statusLabel);
    sl->addLayout(titleRow);

    // 工具选择行
    QHBoxLayout* toolRow = new QHBoxLayout();
    toolRow->setSpacing(8);
    _toolCombo = new QComboBox();
    _toolCombo->setMinimumWidth(280);
    _toolCombo->setEditable(true);
    _toolCombo->addItem("(选择或输入工具名)");
    toolRow->addWidget(_toolCombo);

    _runBtn = new QPushButton("▶ 执行");
    _runBtn->setFixedHeight(36);
    _runBtn->setFixedWidth(90);
    connect(_runBtn, &QPushButton::clicked, this, &McpPanelWidget::callTool);
    toolRow->addWidget(_runBtn);

    QPushButton* refreshBtn = new QPushButton("⟳ 刷新工具");
    refreshBtn->setFlat(true);
    connect(refreshBtn, &QPushButton::clicked, this, &McpPanelWidget::refreshTools);
    toolRow->addWidget(refreshBtn);
    sl->addLayout(toolRow);

    // 参数输入
    _paramInput = new QLineEdit();
    _paramInput->setPlaceholderText("参数 (JSON 格式，如 {\"command\":\"whoami\"})");
    sl->addWidget(_paramInput);

    // 结果区
    _resultArea = new QTextEdit();
    _resultArea->setReadOnly(true);
    _resultArea->setPlaceholderText("执行结果将显示在这里…");
    sl->addWidget(_resultArea, 1);
}

void McpPanelWidget::setSelectedAgent(const QString& hwid, const QString& serverUrl, const QString& cookie) {
    _hwid = hwid;
    _serverUrl = serverUrl;
    _cookie = cookie;
    _statusLabel->setText("已选择: " + hwid.left(16) + "…");
    refreshTools();
}

void McpPanelWidget::refreshTools() {
    if (_hwid.isEmpty()) return;
    QNetworkRequest req(QUrl(_serverUrl + "/api/mcp?hwid=" + _hwid));
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        reply->deleteLater();
        _toolCombo->clear();
        _toolCombo->addItem("(选择或输入工具名)");
        QJsonArray tools = doc.object().value("tools").toArray();
        for (const auto& t : tools) {
            QString name = t.toObject().value("name").toString();
            QString desc = t.toObject().value("description").toString().left(40);
            _toolCombo->addItem(name + "  —  " + desc);
        }
    });
}

void McpPanelWidget::callTool() {
    if (_hwid.isEmpty()) { _resultArea->setText("请先选择客户端"); return; }
    QString raw = _toolCombo->currentText().trimmed();
    QString toolName = raw.split("  —  ").first().trimmed();
    if (toolName.isEmpty() || toolName.startsWith("(")) return;

    QJsonObject argsObj;
    QString paramText = _paramInput->text().trimmed();
    if (!paramText.isEmpty()) {
        QJsonDocument paramDoc = QJsonDocument::fromJson(paramText.toUtf8());
        argsObj = paramDoc.object();
    }

    QJsonObject body;
    body["agent_hwid"] = _hwid;
    body["name"] = toolName;
    body["arguments"] = argsObj;

    QNetworkRequest req(QUrl(_serverUrl + "/api/mcp"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->post(req, QJsonDocument(body).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        onToolResult(reply->readAll());
        reply->deleteLater();
    });
}

void McpPanelWidget::onToolResult(const QString& result) {
    QJsonDocument doc = QJsonDocument::fromJson(result.toUtf8());
    QString output;
    if (doc.isObject()) {
        QJsonObject obj = doc.object();
        if (obj.contains("raw")) {
            output = obj.value("raw").toString();
        } else if (obj.contains("error")) {
            output = "❌ " + obj.value("error").toString();
        } else {
            output = QJsonDocument(obj).toJson(QJsonDocument::Indented);
        }
    } else {
        output = result;
    }
    _resultArea->setPlainText(output);
}
