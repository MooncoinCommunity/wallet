// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MOONWORDDIALOG_H
#define BITCOIN_QT_MOONWORDDIALOG_H

#include <qt/walletmodel.h>

#include <QDialog>
#include <QMessageBox>
#include <QString>
#include <QTimer>

class ClientModel;
class OptionsModel;
class PlatformStyle;
class SendCoinsRecipient;

namespace Ui {
    class MoonWordDialog;
}

struct MoonWordFrom {
    QString address;
    CAmount amount;
    uint256 txhash;
    uint32_t out;
};

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending bitcoins */
class MoonWordDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MoonWordDialog(const PlatformStyle *platformStyle, WalletModel *model);
    ~MoonWordDialog();

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

public Q_SLOTS:
    void clear();
    void reject();
    void accept();
    void updateTabsAndLabels();

    /* New transaction, or transaction changed status */
    void updateTransaction();

private:
    Ui::MoonWordDialog *ui;
    WalletModel *model;
    std::unique_ptr<interfaces::Handler> m_handler_transaction_changed;
    bool fNewRecipientAllowed;
    const PlatformStyle *platformStyle;

    // Core signal will notify us of new TX to refresh the drop down lists
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    // Map of moonword int to char http://mooncoin.com/moonword/moonword.html
    std::map<int, char> moonwordMap;

    // Holds all addresses used to send messages from
    std::multimap<int, MoonWordFrom> fromAddressesMap;

    // Map of coin amounts calculated from the message to send
    std::vector<CAmount> moonwords;

    // Set of outputs from the selected from address
    std::multimap<CAmount, COutPoint> fromOutputs;

    // Process WalletModel::SendCoinsReturn and generate a pair consisting
    // of a message and message flags for use in Q_EMIT message().
    // Additional parameter msgArg can be used via .arg(msgArg).
    void processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg = QString());

    // Populate Moonword drop downs
    void populateFromAddresses();
    void populateReceivedAddresses();
    void populateSentAddresses();

    // Moonword lookups by char or int
    const int& moonCharLookup(const char& c);
    const char& moonCharLookup(const int& i);

    // Calculate bytes and fee for labels
    void getTransactionDetails(unsigned int& nBytes, CAmount& nPayFee);

    // Update list of Moonword CAmounts outputs, return truncated string if message too long
    void updateMoonwordOutputs(std::string &str, CAmount &total_amount);

    // Update inputs required to pay for message
    void updateMoonwordInputs(unsigned int &tx_bytes, CAmount &tx_fee, CAmount &total_amount);

private Q_SLOTS:
    void deleteClicked();
    void on_addressBookButton_clicked();
    void on_sendButton_clicked();
    void on_pasteButton_clicked();
    void on_btn_generate_clicked();
    void on_btn_generate_sent_clicked();
    void generateTextReport(std::ofstream &textFile, std::string &addressStr, std::map<uint256, CWalletTx> &transactions);

    // Drop down of from addresses selected
    void selectFromAddress(int selection);

    // Change to the message to be sent via moonwords
    void textChanged();

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);
};

class SendMoonWordConfirmationDialog : public QMessageBox
{
    Q_OBJECT

public:
    SendMoonWordConfirmationDialog(const QString &title, const QString &text, int secDelay = 0, QWidget *parent = nullptr);
    int exec();

    private Q_SLOTS:
    void countDown();
    void updateYesButton();
    
private:
    QAbstractButton * yesButton;
    QTimer countDownTimer;
    int secDelay;
};

#endif // BITCOIN_QT_MOONWORDDIALOG_H
