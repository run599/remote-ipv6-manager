#pragma once
#include <QFrame>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QNetworkAccessManager>
#include <QVector>
#include <QTimer>

class ShellTerminalWidget : public QFrame {
    Q_OBJECT
public:
    explicit ShellTerminalWidget(QWidget* parent = nullptr);
    void setAgent(const QString& hwid, const QString& serverUrl, const QString& cookie);

private slots:
    void executeCommand();
    void onHistoryUp();
    void onHistoryDown();
    void insertShortcut(const QString& cmd);

private:
    void pollResult(const QString& requestId);
    void appendOutput(const QString& text, const QColor& color = QColor("#1d1d1f"));
    bool eventFilter(QObject* obj, QEvent* event) override;

    QString _hwid, _serverUrl, _cookie;
    QLabel* _statusLabel;
    QNetworkAccessManager* _nam;
    QTextEdit* _output;
    QLineEdit* _input;
    QPushButton* _runBtn;
    QVector<QString> _history;
    int _historyIdx = -1;
};