#pragma once
#include <QWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QNetworkAccessManager>

// ═══════════════════════════════════════════════
// MCP 面板 — 主要工作区
// ═══════════════════════════════════════════════

class McpPanelWidget : public QFrame {
    Q_OBJECT
public:
    explicit McpPanelWidget(QWidget* parent = nullptr);
    void setSelectedAgent(const QString& hwid, const QString& serverUrl, const QString& cookie);

private slots:
    void callTool();
    void refreshTools();

private:
    void onToolResult(const QString& result);

    QString _hwid;
    QString _serverUrl;
    QString _cookie;
    QNetworkAccessManager* _nam;

    QComboBox* _toolCombo;
    QLineEdit* _paramInput;
    QPushButton* _runBtn;
    QTextEdit* _resultArea;
    QLabel* _statusLabel;
};
