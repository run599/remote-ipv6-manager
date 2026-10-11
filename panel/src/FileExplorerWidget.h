#pragma once
#include <QFrame>
#include <QTableWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QNetworkAccessManager>
#include <QVector>
#include <QMenu>
#include <QJsonArray>

class FileExplorerWidget : public QFrame {
    Q_OBJECT
public:
    explicit FileExplorerWidget(QWidget* parent = nullptr);
    void setAgent(const QString& hwid, const QString& serverUrl, const QString& cookie);

private slots:
    void onUploadClicked();
    void onDownloadClicked();
    void onDeleteClicked();
    void onRefreshClicked();
    void onRowDoubleClicked(int row, int col);

private:
    void navigateTo(const QString& path);
    void populateTable(const QJsonArray& files);
    void showProgress(const QString& msg);
    void hideProgress();

    QString _hwid, _serverUrl, _cookie, _currentPath = "/";
    QNetworkAccessManager* _nam;
    QTableWidget* _table;
    QLineEdit* _pathInput;
    QLabel* _statusLabel;
    QProgressBar* _progress;
};