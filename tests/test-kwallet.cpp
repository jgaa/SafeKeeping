// Runs against a mock on a private D-Bus session; never opens a user's wallet.
#include "safekeeping/SafeKeeping.h"
#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QProcess>
#include <QtCore/qscopeguard.h>
#include <QtCore/QTemporaryDir>
#include <QtCore/QTimer>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtTest/QTest>

using jgaa::safekeeping::SafeKeeping;

class wallet_mock final : public QObject {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.kde.KWallet")
    QHash<QString, QString> entries_;
    int transaction_ = 0;
    bool empty_ = false;
    bool reject_ = false;
public slots:
    int openAsync(const QString &, qlonglong, const QString &, bool) {
        const int transaction = ++transaction_;
        QTimer::singleShot(150, this, [this, transaction] { emit walletAsyncOpened(transaction, reject_ ? -1 : 42); });
        return transaction;
    }
    bool isOpen(int) { return true; }
    bool hasFolder(int, const QString &, const QString &) { return true; }
    bool hasEntry(int, const QString &, const QString &key, const QString &) { return entries_.contains(key); }
    int entryType(int, const QString &, const QString &, const QString &) { return 1; }
    QString readPassword(int, const QString &, const QString &key, const QString &) { return empty_ ? QString{} : entries_.value(key); }
    int writePassword(int, const QString &, const QString &key, const QString &value, const QString &) { entries_[key] = value; return 0; }
    int removeEntry(int, const QString &, const QString &key, const QString &) { entries_.remove(key); return 0; }
    int close(int, bool, const QString &) { return 0; }
    void setEmptyReads(bool value) { empty_ = value; }
    void setRejectOpen(bool value) { reject_ = value; }
signals:
    void walletAsyncOpened(int transaction, int handle);
};

class kwallet_tests final : public QObject {
    Q_OBJECT
private slots:
    void delayed_open_services_events_and_empty_reads_report_wallet_context()
    {
        QProcess server;
        const auto stopServer = qScopeGuard([&] { server.terminate(); server.waitForFinished(); });
        server.start(QCoreApplication::applicationFilePath(), {"--mock"});
        QVERIFY(server.waitForStarted());
        QVERIFY(server.waitForReadyRead());
        QCOMPARE(server.readLine().trimmed(), QByteArray{"ready"});
        QDBusInterface control{"org.kde.kwalletd6", "/modules/kwalletd6", "org.kde.KWallet"};
        QVERIFY(control.isValid());
        SafeKeeping::setLinuxVaultBackend(SafeKeeping::LinuxVaultBackend::KWallet);
        int ticks = 0;
        QTimer timer;
        connect(&timer, &QTimer::timeout, this, [&] { ++ticks; });
        timer.start(10);
        auto created = SafeKeeping::createNew("responsive");
        QVERIFY(created.instance->isUnlocked());
        QVERIFY2(ticks >= 10, "UI events must continue while the wallet password prompt is pending");
        created.instance.reset();
        QVERIFY(control.call("setEmptyReads", true).type() != QDBusMessage::ErrorMessage);
        auto reopened = SafeKeeping::open("responsive");
        QVERIFY(reopened != nullptr);
        QVERIFY(!reopened->isUnlocked());
        QCOMPARE(reopened->latestError().error, SafeKeeping::Error::VaultError);
        const auto error = QString::fromStdString(reopened->latestError().message);
        QVERIFY(error.contains("64 hexadecimal"));
        QVERIFY(error.contains("kwallet"));
        QVERIFY2(error.contains("testwallet"), qPrintable(error));
        QVERIFY(error.contains("com.jgaa.SafeKeeping"));
        QVERIFY(control.call("setEmptyReads", false).type() != QDBusMessage::ErrorMessage);
        QVERIFY(SafeKeeping::open("responsive")->isUnlocked());
        QVERIFY(control.call("setRejectOpen", true).type() != QDBusMessage::ErrorMessage);
        auto rejected = SafeKeeping::open("responsive");
        QVERIFY(rejected != nullptr);
        QVERIFY(!rejected->isUnlocked());
        QCOMPARE(rejected->latestError().error, SafeKeeping::Error::VaultError);
    }
};

int main(int argc, char **argv)
{
    if (!qEnvironmentVariableIsSet("SAFEKEEPING_PRIVATE_TEST_BUS")) return 2;
    QTemporaryDir directory;
    if (!directory.isValid()) return 2;
    qputenv("XDG_CONFIG_HOME", directory.path().toUtf8());
    qputenv("SAFEKEEPING_DATA_DIR", directory.path().toUtf8());
    qunsetenv("SAFEKEEPING_TEST_FAKE_VAULT_DIR");
    qunsetenv("SAFEKEEPING_DISABLE_SYSTEM_VAULT");
    QCoreApplication app{argc, argv};
    QCoreApplication::setApplicationName("safekeeping-kwallet-test");
    QFile config{directory.filePath("kwalletrc")};
    if (!config.open(QIODevice::WriteOnly)) return 2;
    config.write("[Wallet]\nEnabled=true\nDefault Wallet=testwallet\n");
    config.close();
    if (app.arguments().contains("--mock")) {
        wallet_mock mock;
        auto bus = QDBusConnection::sessionBus();
        if (!bus.registerService("org.kde.kwalletd6")
            || !bus.registerObject("/modules/kwalletd6", &mock, QDBusConnection::ExportAllSlots | QDBusConnection::ExportAllSignals)) return 3;
        QFile output;
        if (!output.open(stdout, QIODevice::WriteOnly)) return 3;
        output.write("ready\n");
        output.flush();
        return app.exec();
    }
    kwallet_tests tests;
    return QTest::qExec(&tests, argc, argv);
}
#include "test-kwallet.moc"
