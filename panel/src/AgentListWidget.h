#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QLabel>
#include <QVector>
#include <QMenu>
#include "AgentInfo.h"

class AgentListWidget : public QFrame {
    Q_OBJECT
public:
    explicit AgentListWidget(QWidget* parent = nullptr);
    void setAgents(const QVector<AgentInfo>& agents);
signals:
    void agentSelected(const QString& hwid);
private slots:
    void onFilterChanged();
    void onRowClicked();
    void onContextMenu(const QPoint& pos);
    void showDetails();
    void copyHwid();
private:
    void updateBadge();
    QLineEdit* _filter;
    QTableWidget* _table;
    QLabel* _badge;
    QVector<AgentInfo> _agents;
};