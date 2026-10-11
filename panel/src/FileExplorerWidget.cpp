#include "FileExplorerWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkReply>
#include <QSslConfiguration>
#include <QFileDialog>
#include <QMessageBox>
#include <QMenu>
#include <QFileInfo>
#include <QHttpMultiPart>
#include <QHttpPart>
#include <QUrl>

FileExplorerWidget::FileExplorerWidget(QWidget* parent) : QFrame(parent) {
    setStyleSheet("QFrame { background: #ffffff; border: 1px solid #e5e5ea; border-radius: 12px; }");
    _nam = new QNetworkAccessManager(this);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(10);

    // 标题行
    QHBoxLayout* titleRow = new QHBoxLayout();
    QLabel* title = new QLabel("📁 远程文件管理");
    title->setStyleSheet("font-size: 15px; font-weight: 700; color: #1d1d1f;");
    titleRow->addWidget(title);
    titleRow->addStretch();
    _statusLabel = new QLabel("未连接");
    _statusLabel->setStyleSheet("font-size: 11px; color: #86868b;");
    titleRow->addWidget(_statusLabel);
    mainLayout->addLayout(titleRow);

    // 路径输入
    QHBoxLayout* pathRow = new QHBoxLayout();
    pathRow->setSpacing(8);
    pathRow->addWidget(new QLabel("路径:"));
    _pathInput = new QLineEdit("/");
    _pathInput->setPlaceholderText("远程路径");
    _pathInput->setStyleSheet("QLineEdit { background: #f5f5f7; border: 1px solid #e5e5ea; border-radius: 8px; padding: 8px 12px; }");
    connect(_pathInput, &QLineEdit::returnPressed, this, [this]() { navigateTo(_pathInput->text()); });
    pathRow->addWidget(_pathInput, 1);
    mainLayout->addLayout(pathRow);

    // 进度条
    _progress = new QProgressBar();
    _progress->setFixedHeight(4);
    _progress->setTextVisible(false);
    _progress->setStyleSheet("QProgressBar { background: #e5e5ea; border-radius: 2px; } QProgressBar::chunk { background: #007aff; border-radius: 2px; }");
    _progress->hide();
    mainLayout->addWidget(_progress);

    // 工具栏
    QHBoxLayout* toolbar = new QHBoxLayout();
    toolbar->setSpacing(8);
    auto addBtn = [&](const QString& text, auto slot) {
        QPushButton* btn = new QPushButton(text);
        btn->setFlat(true);
        connect(btn, &QPushButton::clicked, this, slot);
        toolbar->addWidget(btn);
    };
    addBtn("⟳ 刷新", &FileExplorerWidget::onRefreshClicked);
    addBtn("⬆ 上传", &FileExplorerWidget::onUploadClicked);
    addBtn("⬇ 下载", &FileExplorerWidget::onDownloadClicked);
    addBtn("🗑 删除", &FileExplorerWidget::onDeleteClicked);
    toolbar->addStretch();
    mainLayout->addLayout(toolbar);

    // 文件表格
    _table = new QTableWidget();
    _table->setColumnCount(4);
    _table->setHorizontalHeaderLabels({"名称", "大小", "修改时间", "类型"});
    _table->verticalHeader()->setVisible(false);
    _table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    _table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    _table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    _table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    _table->setSelectionBehavior(QTableWidget::SelectRows);
    _table->setEditTriggers(QTableWidget::NoEditTriggers);
    _table->setShowGrid(false);
    _table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(_table, &QTableWidget::cellDoubleClicked, this, &FileExplorerWidget::onRowDoubleClicked);
    mainLayout->addWidget(_table, 1);
}

void FileExplorerWidget::setAgent(const QString& hwid, const QString& serverUrl, const QString& cookie) {
    _hwid = hwid;
    _serverUrl = serverUrl;
    _cookie = cookie;
    _statusLabel->setText("已连接: " + hwid.left(16) + "…");
    navigateTo(_currentPath);
}

void FileExplorerWidget::navigateTo(const QString& path) {
    _currentPath = path;
    _pathInput->setText(path);
    showProgress("正在获取文件列表…");
    QNetworkRequest req(QUrl(_serverUrl + "/api/files/list?path=" + QUrl::toPercentEncoding(path)));
    if (_serverUrl.startsWith("https", Qt::CaseInsensitive)) {
        QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
        cfg.setPeerVerifyMode(QSslSocket::VerifyNone); // 自签证书，信任由部署边界保证
        req.setSslConfiguration(cfg);
    }
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        hideProgress();
        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        reply->deleteLater();
        if (doc.isArray()) {
            populateTable(doc.array());
        } else if (doc.isObject()) {
            QJsonObject obj = doc.object();
            if (obj.contains("files") && obj["files"].isArray())
                populateTable(obj["files"].toArray());
        }
    });
}

void FileExplorerWidget::populateTable(const QJsonArray& files) {
    _table->setRowCount(files.size());
    for (int i = 0; i < files.size(); i++) {
        QJsonObject f = files[i].toObject();
        bool isDir = f.value("is_dir").toBool();
        QString name = f.value("name").toString();
        _table->setItem(i, 0, new QTableWidgetItem((isDir ? "📁 " : "📄 ") + name));
        _table->item(i, 0)->setData(Qt::UserRole, name);
        qint64 size = f.value("size").toVariant().toLongLong();
        QString sizeStr = isDir ? "—" : QString::number(size) + " B";
        if (!isDir && size > 1024*1024) sizeStr = QString::number(size/1024.0/1024.0, 'f', 1) + " MB";
        _table->setItem(i, 1, new QTableWidgetItem(sizeStr));
        _table->setItem(i, 2, new QTableWidgetItem(f.value("mod_time").toString()));
        _table->setItem(i, 3, new QTableWidgetItem(isDir ? "文件夹" : "文件"));
    }
    _statusLabel->setText(QString("共 %1 项").arg(files.size()));
}

void FileExplorerWidget::onRefreshClicked() { navigateTo(_currentPath); }

void FileExplorerWidget::onUploadClicked() {
    QString filePath = QFileDialog::getOpenFileName(this, "选择上传文件");
    if (filePath.isEmpty()) return;
    showProgress("正在上传…");
    QHttpMultiPart* multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    QHttpPart filePart;
    filePart.setHeader(QNetworkRequest::ContentDispositionHeader,
        QVariant("form-data; name=\"file\"; filename=\"" + QFileInfo(filePath).fileName() + "\""));
    QFile file(filePath);
    file.open(QIODevice::ReadOnly);
    filePart.setBody(file.readAll());
    file.close();
    multiPart->append(filePart);
    QNetworkRequest req(QUrl(_serverUrl + "/api/files/upload"));
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->post(req, multiPart);
    multiPart->setParent(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        hideProgress();
        if (reply->error() == QNetworkReply::NoError) {
            QMessageBox::information(this, "成功", "上传完成");
            navigateTo(_currentPath);
        } else {
            QMessageBox::warning(this, "错误", reply->errorString());
        }
        reply->deleteLater();
    });
}

void FileExplorerWidget::onDownloadClicked() {
    int row = _table->currentRow();
    if (row < 0) return;
    QString fileName = _table->item(row, 0)->data(Qt::UserRole).toString();
    QString savePath = QFileDialog::getSaveFileName(this, "保存文件", fileName);
    if (savePath.isEmpty()) return;
    showProgress("正在下载…");
    QNetworkRequest req(QUrl(_serverUrl + "/api/files/get?name=" + QUrl::toPercentEncoding(_currentPath + "/" + fileName)));
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, savePath]() {
        hideProgress();
        if (reply->error() == QNetworkReply::NoError) {
            QFile out(savePath);
            if (out.open(QIODevice::WriteOnly)) { out.write(reply->readAll()); out.close(); }
            QMessageBox::information(this, "成功", "下载完成");
        } else {
            QMessageBox::warning(this, "错误", reply->errorString());
        }
        reply->deleteLater();
    });
}

void FileExplorerWidget::onDeleteClicked() {
    int row = _table->currentRow();
    if (row < 0) return;
    QString fileName = _table->item(row, 0)->data(Qt::UserRole).toString();
    if (QMessageBox::question(this, "确认", "删除 " + fileName + "?") != QMessageBox::Yes) return;
    QNetworkRequest req(QUrl(_serverUrl + "/api/files/delete?name=" + QUrl::toPercentEncoding(_currentPath + "/" + fileName)));
    if (_serverUrl.startsWith("https", Qt::CaseInsensitive)) {
        QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
        cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
        req.setSslConfiguration(cfg);
    }
    req.setRawHeader("Cookie", _cookie.toUtf8());
    QNetworkReply* reply = _nam->deleteResource(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        navigateTo(_currentPath);
    });
}

void FileExplorerWidget::onRowDoubleClicked(int row, int) {
    QTableWidgetItem* item = _table->item(row, 0);
    if (!item) return;
    navigateTo(_currentPath + "/" + item->data(Qt::UserRole).toString());
}

void FileExplorerWidget::showProgress(const QString& msg) {
    _progress->setRange(0, 0);
    _progress->show();
    _statusLabel->setText(msg);
}

void FileExplorerWidget::hideProgress() {
    _progress->hide();
}