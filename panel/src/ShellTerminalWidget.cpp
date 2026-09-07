#include "ShellTerminalWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QKeyEvent>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QTimer>
#include <QTextCursor>

ShellTerminalWidget::ShellTerminalWidget(QWidget* parent) : QFrame(parent) {
    setStyleSheet("QFrame { background: #ffffff; border: 1px solid #e5e5ea; border-radius: 12px; }");
    _nam = new QNetworkAccessManager(this);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(10);

    // 标题行
    QHBoxLayout* titleRow = new QHBoxLayout();
    QLabel* title = new QLabel("🖥️ 远程终端");
    title->setStyleSheet("font-size: 15px; font-weight: 700; color: #1d1d1f;");
    titleRow->addWidget(title);
    titleRow->addStretch();
    _statusLabel = new QLabel("未连接");
    _statusLabel->setStyleSheet("font-size: 11px; color: #86868b;");
    titleRow->addWidget(_statusLabel);
    mainLayout->addLayout(titleRow);

    // 常用命令快捷按钮
    QHBoxLayout* shortcutsRow = new QHBoxLayout();
    shortcutsRow->setSpacing(6);
    QStringList shortcuts = {"whoami", "ipconfig", "tasklist", "systeminfo", "netstat -an", "dir"};
    for (const QString& cmd : shortcuts) {
        QPushButton* btn = new QPushButton(cmd);
        btn->setFlat(true);
        btn->setStyleSheet("QPushButton { background: #f0f0f5; color: #86868b; font-size: 11px; padding: 4px 10px; border-radius: 6px; } QPushButton:hover { background: #e0e0e5; }");
        btn->setFixedHeight(28);
        connect(btn, &QPushButton::clicked, this, [this, cmd]() { insertShortcut(cmd); });
        shortcutsRow->addWidget(btn);
    }
    shortcutsRow->addStretch();
    mainLayout->addLayout(shortcutsRow);

    // 输出区
    _output = new QTextEdit();
    _output->setReadOnly(true);
    _output->setFont(QFont("Consolas", 11));
    _output->setStyleSheet("QTextEdit { background: #1e1e1e; color: #d4d4d4; border: 1px solid #3c3c3c; border-radius: 8px; padding: 10px; }");
    _output->setPlaceholderText("输出将显示在这里…");
    _output->setLineWrapMode(QTextEdit::NoWrap);
    mainLayout->addWidget(_output, 1);

    // 输入行
    QHBoxLayout* inputRow = new QHBoxLayout();
    inputRow->setSpacing(8);
    _input = new QLineEdit();
    _input->setPlaceholderText("输入命令，回车执行…");
    _input->setStyleSheet("QLineEdit { background: #1e1e1e; color: #d4d4d4; border: 1px solid #3c3c3c; border-radius: 8px; padding: 8px 12px; font-size: 13px; font-family: Consolas; } QLineEdit:focus { border-color: #007aff; }");
    _input->setFont(QFont("Consolas", 12));
    connect(_input, &QLineEdit::returnPressed, this, &ShellTerminalWidget::executeCommand);
    _input->installEventFilter(this);
    inputRow->addWidget(_input, 1);

    _runBtn = new QPushButton("▶ 执行");
    _runBtn->setFixedHeight(36);
    _runBtn->setFixedWidth(90);
    connect(_runBtn, &QPushButton::clicked, this, &ShellTerminalWidget::executeCommand);
    inputRow->addWidget(_runBtn);
    mainLayout->addLayout(inputRow);
}

void ShellTerminalWidget::setAgent(const QString& hwid, const QString& serverUrl, const QString& cookie) {
    _hwid = hwid;
    _serverUrl = serverUrl;
    _cookie = cookie;
    _statusLabel->setText("已连接: " + hwid.left(16) + "…");
    _history.clear();
    _historyIdx = -1;
    _output->clear();
    appendOutput("[Shell] 连接到 " + hwid.left(16) + "...", QColor("#34c759"));
    appendOutput("输入命令或点击上方快捷按钮", QColor("#86868b"));
}

bool ShellTerminalWidget::eventFilter(QObject* obj, QEvent* event) {
    if (obj == _input && event->type() == QEvent::KeyPress) {
        QKeyEvent* ke = static_cast<QKeyEvent*>(event);
        if (ke->key() == Qt::Key_Up) { onHistoryUp(); return true; }
        if (ke->key() == Qt::Key_Down) { onHistoryDown(); return true; }
    }
    return QFrame::eventFilter(obj, event);
}

void ShellTerminalWidget::insertShortcut(const QString& cmd) {
    _input->setText(cmd);
    _input->setFocus();
}

void ShellTerminalWidget::executeCommand() {
    QString cmd = _input->text().trimmed();
    if (cmd.isEmpty()) return;
    _history.append(cmd);
    _historyIdx = _history.size();
    _input->clear();
    appendOutput("> " + cmd, QColor("#ffffff"));

    QJsonObject body;
    body["agent_hwid"] = _hwid;
    body["name"] = "execute";
    body["arguments"] = QJsonObject{{"command", cmd}};

    QNetworkRequest req(QUrl(_serverUrl + "/api/mcp"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->post(req, QJsonDocument(body).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        reply->deleteLater();
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            if (obj.contains("request_id")) {
                pollResult(obj.value("request_id").toString());
            } else if (obj.contains("error")) {
                appendOutput("❌ " + obj.value("error").toString(), QColor("#ff6b6b"));
            }
        }
    });
}

void ShellTerminalWidget::pollResult(const QString& requestId) {
    QTimer::singleShot(500, this, [this, requestId]() {
        QNetworkRequest req(QUrl(_serverUrl + "/api/mcp/result?request_id=" + requestId));
        req.setRawHeader("Cookie", _cookie.toUtf8());
        QNetworkReply* reply = _nam->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, requestId]() {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            reply->deleteLater();
            if (doc.isObject()) {
                QJsonObject obj = doc.object();
                if (obj.value("ok").toBool()) {
                    QString raw = obj.value("result").toString();
                    if (raw.isEmpty()) raw = obj.value("raw").toString();
                    if (raw.isEmpty()) raw = QJsonDocument(obj).toJson(QJsonDocument::Indented);
                    appendOutput(raw, QColor("#d4d4d4"));
                } else if (obj.value("status").toString() == "pending") {
                    pollResult(requestId);
                }
            }
        });
    });
}

void ShellTerminalWidget::onHistoryUp() {
    if (!_history.isEmpty() && _historyIdx > 0) {
        _historyIdx--;
        _input->setText(_history[_historyIdx]);
    }
}

void ShellTerminalWidget::onHistoryDown() {
    if (_historyIdx < _history.size() - 1) {
        _historyIdx++;
        _input->setText(_history[_historyIdx]);
    } else {
        _historyIdx = _history.size();
        _input->clear();
    }
}

void ShellTerminalWidget::appendOutput(const QString& text, const QColor& color) {
    _output->moveCursor(QTextCursor::End);
    _output->setTextColor(color);
    _output->insertPlainText(text + "\n");
    _output->moveCursor(QTextCursor::End);
}