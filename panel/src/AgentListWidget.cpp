#include "AgentListWidget.h"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QMenu>
#include <QClipboard>
#include <QMessageBox>
#include <QApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

AgentListWidget::AgentListWidget(QWidget* parent) : QFrame(parent) {
    setFixedWidth(280);
    setStyleSheet("QFrame { background: #ffffff; border: 1px solid #e5e5ea; border-radius: 12px; }");

    QVBoxLayout* ll = new QVBoxLayout(this);
    ll->setContentsMargins(12, 14, 12, 12);
    ll->setSpacing(8);

    // 头部：标题 + 在线徽标
    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* header = new QLabel("📡 客户端");
    header->setStyleSheet("font-size: 15px; font-weight: 700; color: #1d1d1f;");
    headerLayout->addWidget(header);
    headerLayout->addStretch();

    _badge = new QLabel("📡 0 台在线");
    _badge->setStyleSheet("background: #dcfce7; color: #16a34a; font-size: 11px; font-weight: 600; padding: 2px 10px; border-radius: 12px;");
    headerLayout->addWidget(_badge);
    QVBoxLayout* headerWrap = new QVBoxLayout();
    headerWrap->addLayout(headerLayout);
    ll->addLayout(headerWrap);

    // 搜索框
    _filter = new QLineEdit();
    _filter->setPlaceholderText("🔍 搜索 HWID/用户/系统…");
    _filter->setFixedHeight(34);
    connect(_filter, &QLineEdit::textChanged, this, &AgentListWidget::onFilterChanged);
    QVBoxLayout* filterWrap = new QVBoxLayout();
    filterWrap->addWidget(_filter);
    ll->addLayout(filterWrap);

    // 表格
    _table = new QTableWidget();
    _table->setColumnCount(3);
    _table->setHorizontalHeaderLabels({"", "HWID", "用户 · 系统"});
    _table->verticalHeader()->setVisible(false);
    _table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    _table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    _table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    _table->verticalHeader()->setVisible(false);
    _table->setSelectionBehavior(QTableWidget::SelectRows);
    _table->setEditTriggers(QTableWidget::NoEditTriggers);
    _table->setShowGrid(false);
    _table->setContextMenuPolicy(Qt::CustomContextMenu);
    _table->setStyleSheet("QTableWidget { border: none; background: transparent; }");
    connect(_table, &QTableWidget::clicked, this, &AgentListWidget::onRowClicked);
    connect(_table, &QTableWidget::customContextMenuRequested, this, &AgentListWidget::onContextMenu);
    QVBoxLayout* tableWrap = new QVBoxLayout();
    tableWrap->addWidget(_table);
    ll->addLayout(tableWrap, 1);

    setLayout(ll);
}

void AgentListWidget::setAgents(const QVector<AgentInfo>& agents) {
    _agents = agents;
    onFilterChanged();
}

void AgentListWidget::onFilterChanged() {
    QString q = _filter->text().toLower();
    QVector<AgentInfo> filtered;
    for (const auto& a : _agents) {
        if (q.isEmpty() || a.hwid.toLower().contains(q) || a.user.toLower().contains(q) || a.os.toLower().contains(q)) {
            filtered.append(a);
        }
    }
    _table->setRowCount(filtered.size());
    for (int i = 0; i < filtered.size(); i++) {
        const auto& a = filtered[i];
        QTableWidgetItem* i0 = new QTableWidgetItem(a.online ? " ●" : " ○");
        i0->setForeground(a.online ? QColor("#34c759") : QColor("#c7c7cc"));
        i0->setTextAlignment(Qt::AlignCenter);
        _table->setItem(i, 0, i0);
        // 显示截断、数据完整：原来把 left(16) 的值当唯一 ID 下发，
        // 会让命令打到错误的机器上（前 16 字符相同即冲突）
        QTableWidgetItem* hwidItem = new QTableWidgetItem(a.hwid.left(16));
        hwidItem->setData(Qt::UserRole, a.hwid);
        _table->setItem(i, 1, hwidItem);
        _table->setItem(i, 2, new QTableWidgetItem(a.user + " · " + a.os.left(20)));
    }
    updateBadge();
}

void AgentListWidget::updateBadge() {
    int online = 0;
    for (const auto& a : _agents) if (a.online) online++;
    _badge->setText(QString("📡 %1 台在线").arg(online));
}

void AgentListWidget::onRowClicked() {
    int row = _table->currentRow();
    if (row >= 0 && row < _table->rowCount()) {
        QString hwid = _table->item(row, 1)->data(Qt::UserRole).toString();
        emit agentSelected(hwid);
    }
}

void AgentListWidget::onContextMenu(const QPoint& pos) {
    int row = _table->rowAt(pos.y());
    if (row < 0) return;
    _table->selectRow(row);
    QString hwid = _table->item(row, 1)->text();

    QMenu menu(this);
    QAction* actDetail = menu.addAction("📋 查看详情");
    QAction* actCopy = menu.addAction("📋 复制 HWID");
    QAction* actCopy2 = menu.addAction("📋 复制 IP");

    QAction* act = menu.exec(_table->viewport()->mapToGlobal(pos));
    if (act == actDetail) showDetails();
    else if (act == actCopy) QApplication::clipboard()->setText(_table->item(_table->currentRow(), 1)->text());
    else if (act == actCopy2) {
        // 修复点：表格只有 3 列（0/1/2），item(row,3) 恒为 nullptr，
        // 原来直接 ->text() 会访问违例崩溃（右键→复制 IP 必崩）。
        // IP 本来就没在表格里展示，从 _agents 里按 HWID 取。
        const int row = _table->currentRow();
        if (row >= 0) {
            QTableWidgetItem* it = _table->item(row, 1);
            const QString hwid = it ? it->data(Qt::UserRole).toString() : QString();
            for (const auto& a : _agents) {
                if (a.hwid == hwid) { QApplication::clipboard()->setText(a.ip); break; }
            }
        }
    }
}

void AgentListWidget::showDetails() {
    int row = _table->currentRow();
    if (row < 0) return;
    const auto& a = _agents[row];
    QString detail = QString(
        "HWID: %1\n用户: %2\n系统: %3\nIP: %4\n在线: %5\n最后上线: %6"
    ).arg(a.hwid).arg(a.user).arg(a.os).arg(a.ip).arg(a.online ? "在线" : "离线").arg(a.lastSeen);
    QMessageBox::information(this, "客户端详情", detail);
}

void AgentListWidget::copyHwid() {
    int row = _table->currentRow();
    if (row >= 0) QApplication::clipboard()->setText(_table->item(row, 1)->text());
}