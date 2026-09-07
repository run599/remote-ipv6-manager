#include "TaskOrchestratorWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkReply>

TaskOrchestratorWidget::TaskOrchestratorWidget(QWidget* parent) : QFrame(parent) {
    setStyleSheet("QFrame { background: #ffffff; border: 1px solid #e5e5ea; border-radius: 12px; }");
    _nam = new QNetworkAccessManager(this);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(10);

    QHBoxLayout* titleRow = new QHBoxLayout();
    QLabel* title = new QLabel("⚡ 任务编排器");
    title->setStyleSheet("font-size: 15px; font-weight: 700; color: #1d1d1f;");
    titleRow->addWidget(title);
    titleRow->addStretch();
    mainLayout->addLayout(titleRow);

    _commandInput = new QTextEdit();
    _commandInput->setFixedHeight(60);
    _commandInput->setPlaceholderText("输入命令，如 whoami");
    _commandInput->setStyleSheet("QTextEdit { background: #f5f5f7; border: 1px solid #e5e5ea; border-radius: 8px; padding: 8px; font-family: Consolas; }");
    mainLayout->addWidget(_commandInput);

    QHBoxLayout* targetRow = new QHBoxLayout();
    _targetAll = new QCheckBox("所有在线 Agent");
    _targetAll->setChecked(true);
    _targetSelected = new QCheckBox("仅选中 Agent");
    targetRow->addWidget(_targetAll);
    targetRow->addWidget(_targetSelected);
    targetRow->addStretch();
    mainLayout->addLayout(targetRow);

    QHBoxLayout* btnRow = new QHBoxLayout();
    _executeBtn = new QPushButton("▶ 批量执行");
    _executeBtn->setFixedHeight(36);
    connect(_executeBtn, &QPushButton::clicked, this, &TaskOrchestratorWidget::onExecuteClicked);
    btnRow->addWidget(_executeBtn);
    _clearBtn = new QPushButton("🗑 清空");
    _clearBtn->setFlat(true);
    connect(_clearBtn, &QPushButton::clicked, this, &TaskOrchestratorWidget::onClearClicked);
    btnRow->addWidget(_clearBtn);
    btnRow->addStretch();
    mainLayout->addLayout(btnRow);

    _resultTable = new QTableWidget();
    _resultTable->setColumnCount(4);
    _resultTable->setHorizontalHeaderLabels({"Agent", "状态", "时间", "结果"});
    _resultTable->verticalHeader()->setVisible(false);
    _resultTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    _resultTable->setEditTriggers(QTableWidget::NoEditTriggers);
    _resultTable->setShowGrid(false);
    mainLayout->addWidget(_resultTable, 1);
}

void TaskOrchestratorWidget::setAgents(const QVector<AgentInfo>& agents) { _agents = agents; }

void TaskOrchestratorWidget::setServerInfo(const QString& serverUrl, const QString& cookie) {
    _serverUrl = serverUrl;
    _cookie = cookie;
}

void TaskOrchestratorWidget::onExecuteClicked() {
    QString cmd = _commandInput->toPlainText().trimmed();
    if (cmd.isEmpty()) return;
    _resultTable->setRowCount(0);
    _hwidToRow.clear();

    for (const auto& a : _agents) {
        if (!a.online) continue;
        int row = _resultTable->rowCount();
        _resultTable->insertRow(row);
        _resultTable->setItem(row, 0, new QTableWidgetItem(a.hwid.left(16)));
        _resultTable->setItem(row, 1, new QTableWidgetItem("⏳ 排队"));
        _resultTable->setItem(row, 2, new QTableWidgetItem(QDateTime::currentDateTime().toString("HH:mm:ss")));
        _resultTable->setItem(row, 3, new QTableWidgetItem("等待中..."));
        _hwidToRow[a.hwid] = row;
        dispatchToAgent(a.hwid);
    }
}

void TaskOrchestratorWidget::dispatchToAgent(const QString& hwid) {
    QString cmd = _commandInput->toPlainText().trimmed();
    QJsonObject body;
    body["agent_hwid"] = hwid;
    body["name"] = "execute";
    body["arguments"] = QJsonObject{{"command", cmd}};

    QNetworkRequest req(QUrl(_serverUrl + "/api/mcp"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->post(req, QJsonDocument(body).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply, hwid]() {
        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        reply->deleteLater();
        if (doc.isObject() && doc.object().contains("request_id")) {
            updateRow(hwid, "⏳ 执行中");
            QTimer::singleShot(1000, this, [this, hwid, requestId = doc.object().value("request_id").toString()]() {
                pollResult(hwid, requestId);
            });
        }
    });
}

void TaskOrchestratorWidget::pollResult(const QString& hwid, const QString& requestId) {
    QNetworkRequest req(QUrl(_serverUrl + "/api/mcp/result?request_id=" + requestId));
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, hwid, requestId]() {
        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        reply->deleteLater();
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            if (obj.value("ok").toBool()) {
                QString raw = obj.value("result").toString();
                if (raw.isEmpty()) raw = obj.value("raw").toString();
                updateRow(hwid, "✅ 完成", raw.left(100));
            } else if (obj.value("status").toString() == "pending") {
                QTimer::singleShot(1000, this, [this, hwid, requestId]() { pollResult(hwid, requestId); });
            } else {
                updateRow(hwid, "❌ 错误", obj.value("error").toString().left(100));
            }
        }
    });
}

void TaskOrchestratorWidget::updateRow(const QString& hwid, const QString& status, const QString& result) {
    if (!_hwidToRow.contains(hwid)) return;
    int row = _hwidToRow[hwid];
    _resultTable->setItem(row, 1, new QTableWidgetItem(status));
    if (!result.isEmpty()) _resultTable->setItem(row, 3, new QTableWidgetItem(result));
}

void TaskOrchestratorWidget::onClearClicked() {
    _resultTable->setRowCount(0);
    _hwidToRow.clear();
}

void TaskOrchestratorWidget::onAutoRefresh() {}