#pragma once
#include <QFrame>
#include <QTableWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QNetworkAccessManager>
#include <QVector>
#include <QMap>
#include <QTimer>
#include "MainWindow.h"

class TaskOrchestratorWidget : public QFrame {
    Q_OBJECT
public:
    explicit TaskOrchestratorWidget(QWidget* parent = nullptr);
    void setAgents(const QVector<AgentInfo>& agents);
    void setServerInfo(const QString& serverUrl, const QString& cookie);

private slots:
    void onExecuteClicked();
    void onClearClicked();
    void onAutoRefresh();

private:
    void dispatchToAgent(const QString& hwid);
    void pollResult(const QString& hwid, const QString& requestId);
    void updateRow(const QString& hwid, const QString& status, const QString& result = "");

    QString _serverUrl, _cookie;
    QVector<AgentInfo> _agents;
    QNetworkAccessManager* _nam;
    QTextEdit* _commandInput;
    QTableWidget* _resultTable;
    QPushButton* _executeBtn;
    QPushButton* _clearBtn;
    QCheckBox* _targetAll;
    QCheckBox* _targetSelected;
    QTimer* _refreshTimer;
    QMap<QString, int> _hwidToRow;
};