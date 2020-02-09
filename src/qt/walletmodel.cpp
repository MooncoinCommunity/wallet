// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/walletmodel.h>

#include <qt/addresstablemodel.h>
#include <qt/guiconstants.h>
#include <qt/moonworddialog.h>
#include <qt/optionsmodel.h>
#include <qt/paymentserver.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/transactiontablemodel.h>

#include <addressindex.h>
#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <ui_interface.h>
#include <util/system.h> // for GetBoolArg
#include <util/moneystr.h> // for FormatMoney
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>

#include <stdint.h>

#include <QDebug>
#include <QMessageBox>
#include <QSet>
#include <QTimer>


WalletModel::WalletModel(std::unique_ptr<interfaces::Wallet> wallet, interfaces::Node& node, const PlatformStyle *platformStyle, OptionsModel *_optionsModel, QObject *parent) :
    QObject(parent), m_wallet(std::move(wallet)), m_node(node), optionsModel(_optionsModel), addressTableModel(nullptr),
    transactionTableModel(nullptr),
    recentRequestsTableModel(nullptr),
    moonWordPage(nullptr),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{
    fHaveWatchOnly = m_wallet->haveWatchOnly();
    addressTableModel = new AddressTableModel(this);
    transactionTableModel = new TransactionTableModel(platformStyle, this);
    recentRequestsTableModel = new RecentRequestsTableModel(this);
    moonWordPage = new MoonWordDialog(platformStyle, this);

    // This timer will be fired repeatedly to update the balance
    pollTimer = new QTimer(this);
    connect(pollTimer, &QTimer::timeout, this, &WalletModel::pollBalanceChanged);
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus) {
        Q_EMIT encryptionStatusChanged();
    }
}

void WalletModel::pollBalanceChanged()
{
    // Try to get balances and return early if locks can't be acquired. This
    // avoids the GUI from getting stuck on periodical polls if the core is
    // holding the locks for a longer time - for example, during a wallet
    // rescan.
    interfaces::WalletBalances new_balances;
    int numBlocks = -1;
    if (!m_wallet->tryGetBalances(new_balances, numBlocks)) {
        return;
    }

    if(fForceCheckBalanceChanged || m_node.getNumBlocks() != cachedNumBlocks)
    {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        cachedNumBlocks = m_node.getNumBlocks();

        checkBalanceChanged(new_balances);
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();
    }
}

void WalletModel::checkBalanceChanged(const interfaces::WalletBalances& new_balances)
{
    if(new_balances.balanceChanged(m_cached_balances)) {
        m_cached_balances = new_balances;
        Q_EMIT balanceChanged(new_balances);
    }
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, const QString &purpose, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}

void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    Q_EMIT notifyWatchonlyChanged(fHaveWatchonly);
}

bool WalletModel::validateAddress(const QString &address)
{
    return IsValidDestinationString(address.toStdString());
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, CCoinControl& coinControl, const bool moonword)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;
    std::string nMLikeAddress;

    // Pre-check input data for validity
    for (const SendCoinsRecipient &rcp : recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;

#ifdef ENABLE_BIP70
        if (rcp.paymentRequest.IsInitialized())
        {   // PaymentRequest...
            CAmount subtotal = 0;
            const payments::PaymentDetails& details = rcp.paymentRequest.getDetails();
            for (int i = 0; i < details.outputs_size(); i++)
            {
                const payments::Output& out = details.outputs(i);
                if (out.amount() <= 0) continue;
                subtotal += out.amount();
                const unsigned char* scriptStr = (const unsigned char*)out.script().data();
                CScript scriptPubKey(scriptStr, scriptStr+out.script().size());
                CAmount nAmount = out.amount();
                CRecipient recipient = {scriptPubKey, nAmount, rcp.fSubtractFeeFromAmount};
                vecSend.push_back(recipient);
            }
            if (subtotal <= 0)
            {
                return InvalidAmount;
            }
            total += subtotal;
        }
        else
#endif
        {   // User-entered bitcoin address / amount:
            if(!validateAddress(rcp.address))
            {
                return InvalidAddress;
            }
            if(rcp.amount <= 0)
            {
                return InvalidAmount;
            }
            if (rcp.address.toStdString().rfind(Params().MLikesPrefix(), 0) != std::string::npos)
            {
                nMLikeAddress = rcp.address.toStdString();

                if (rcp.amount < 10000 * COIN)
                {
                    return MLikeAmountTooSmall;
                }
            }
            if (!nMLikeAddress.empty() && nAddresses > 0)
            {
                return MultipleMLike;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            CScript scriptPubKey = GetScriptForDestination(DecodeDestination(rcp.address.toStdString()));
            CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            total += rcp.amount;
        }
    }

    if(!moonword && setAddress.size() != nAddresses)
    {
        return DuplicateAddress;
    }

    CAmount nBalance = m_wallet->getAvailableBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    if (!nMLikeAddress.empty())
    {
        // Only a single recipient should be set for MLike TXs at this point
        if (vecSend.size() != 1)
        {
            return MLikeFailure;
        }

        // We need a "senders address" for prepareMLikeTransaction, if no output selected we'll select one here
        if (!coinControl.HasSelected())
        {
            interfaces::WalletTxOut selected_out{};
            COutPoint selected_output{};
            interfaces::WalletTxOut largest_out{};
            COutPoint largest_output{};
            CAmount target_value = vecSend[0].nAmount;

            const auto& coin_list = m_wallet->listCoins();

            // Iterate over all coins in wallet
            for (const auto& coins : coin_list)
            {
                for (const auto& outpair : coins.second)
                {
                    const COutPoint& output = std::get<0>(outpair);
                    const interfaces::WalletTxOut& out = std::get<1>(outpair);
                    if (m_wallet->isLockedCoin(output))
                        continue;

                    // Set largest out first time, or if new output is smaller than previous one
                    if (largest_out.txout.IsNull() || out.txout.nValue > largest_out.txout.nValue)
                    {
                        largest_out = out;
                        largest_output = output;
                    }

                    // Large enough to cover the amount
                    if (out.txout.nValue > target_value)
                    {
                        // Set for first time, or if new output is smaller than previous one
                        if (selected_out.txout.IsNull() || out.txout.nValue < selected_out.txout.nValue)
                        {
                            selected_out = out;
                            selected_output = output;
                        }
                    }
                }
            }

            // If we still have nothing we've failed
            if (selected_out.txout.IsNull() && largest_out.txout.IsNull())
            {
                return MLikeFailure;
            }

            if (selected_out.txout.IsNull())
            {
                coinControl.Select(largest_output);
                LogPrint(BCLog::MLIKE, "%s: output chosen TX: %s output: %d\n", __func__, largest_output.hash.GetHex(), largest_output.n);
            }
            else
            {
                coinControl.Select(selected_output);
                LogPrint(BCLog::MLIKE, "%s: output chosen TX: %s output: %d\n", __func__, selected_output.hash.GetHex(), selected_output.n);
            }

            // Lastly set coin control to allow other inputs as selected input may not be enough
            coinControl.fAllowOtherInputs = true;
        }

        if (!prepareMLikeTransaction(nMLikeAddress, vecSend, coinControl))
        {
            return MLikeFailure;
        }
    }

    {
        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;

        // MLike TXs should have change at the end of other outputs
        if (!nMLikeAddress.empty())
        {
            nChangePosRet = vecSend.size();
        }

        std::string strFailReason;

        auto& newTx = transaction.getWtx();
        newTx = m_wallet->createTransaction(vecSend, coinControl, true /* sign */, nChangePosRet, nFeeRequired, strFailReason, moonword, !nMLikeAddress.empty());
        transaction.setTransactionFee(nFeeRequired);
        if (fSubtractFeeFromAmount && newTx)
            transaction.reassignAmounts(nChangePosRet);

        if(!newTx)
        {
            if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            Q_EMIT message(tr("Send Coins"), QString::fromStdString(strFailReason),
                         CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // reject absurdly high fee. (This can never happen because the
        // wallet caps the fee at maxTxFee. This merely serves as a
        // belt-and-suspenders check)
        if (nFeeRequired > m_node.getMaxTxFee())
            return AbsurdFee;
    }

    return SendCoinsReturn(OK);
}

bool WalletModel::prepareMLikeTransaction(const std::string address, std::vector<CRecipient>& recipients, const CCoinControl& coinControl)
{
    // Address as key, value is map of height as key and amount paid as value
    std::map<std::string, std::map<int, CAmount>> payee_history;

    // Holds total valid amount paid to like address
    CAmount total_paid_to_mlike{0};

    if (!calculateHistoricalLikeTransactions(address, payee_history, total_paid_to_mlike))
    {
        return false;
    }

    // Save MLike recipient and clear vector
    CRecipient recipientMLike = recipients[0];
    recipients.clear();

    // Reduce to 10%, use this amount to calculate amount to pay others to keep in line with historical validation
    recipientMLike.nAmount /= 10;
    recipients.push_back({recipientMLike.scriptPubKey, recipientMLike.nAmount, recipientMLike.fSubtractFeeFromAmount});

    // Get senders address from first selected coin control item
    std::vector<COutPoint> control_outpoints;
    coinControl.ListSelected(control_outpoints);

    // Must be at least one selected outpoint
    if (control_outpoints.size() < 1)
    {
        return false;
    }

    // Get coin from first coin control output
    std::vector<interfaces::WalletTxOut> wtxs = m_wallet->getCoins(std::vector<COutPoint>{control_outpoints[0]});

    // Should be at least one entry
    if (wtxs.size() < 1)
    {
        LogPrint(BCLog::MLIKE, "%s: No coins returned for selected output. TX: %s\n", __func__, control_outpoints[0].ToString());
        return false;
    }

    // Get new mlike payee address from selected coin
    CTxDestination current_senders_dest;
    ExtractDestination(wtxs[0].txout.scriptPubKey, current_senders_dest);
    std::string current_senders_address{EncodeDestination(current_senders_dest)};

    // Add payee from new transaction to the payee_history used to calculate outputs
    payee_history[current_senders_address][std::numeric_limits<int>::max()] = recipientMLike.nAmount;

    // Add new mlike TX payment to total
    total_paid_to_mlike += recipientMLike.nAmount;

    LogPrint(BCLog::MLIKE, "%s: Total valid amount paid to like address: %s\n", __func__, FormatMoney(total_paid_to_mlike));

    // Work out how much of the TX amount each payee gets
    for (const auto& payee : payee_history)
    {
        CAmount payee_valid_total{0};
        for (const auto& payments : payee.second)
        {
            payee_valid_total += payments.second;
        }

        double payee_share = double(payee_valid_total) / total_paid_to_mlike;

        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(payee.first));
        CAmount payee_payment = (recipientMLike.nAmount * 9) * payee_share;

        LogPrint(BCLog::MLIKE, "%s: payee: %s payee total: %s all payees total: %s payee share: %f payee payment: %s\n",
                 __func__, payee.first, FormatMoney(payee_valid_total), FormatMoney(total_paid_to_mlike), payee_share, FormatMoney(payee_payment));

        // Current sender must be second output after MLike output
        if (payee.first == current_senders_address)
        {
            recipients.insert(++recipients.begin(), {scriptPubKey, payee_payment, false});
        }
        else
        {
            recipients.push_back({scriptPubKey, payee_payment, false});
        }
    }

    if (LogAcceptCategory(BCLog::MLIKE))
    {
        for (const auto& recp : recipients)
        {
            CTxDestination recp_dest;
            ExtractDestination(recp.scriptPubKey, recp_dest);
            std::string recp_address{};
            LogPrint(BCLog::MLIKE, "%s: recipients: %s amount: %s\n", __func__, EncodeDestination(recp_dest), FormatMoney(recp.nAmount));
        }
    }

    return true;
}

bool WalletModel::calculateHistoricalLikeTransactions(const std::string& address, std::map<std::string, std::map<int, CAmount>>& payee_history, CAmount& total_paid_to_mlike)
{
    // Holds transaction history information for like address
    std::vector<std::pair<CAddressIndexKey, CAmount>> addressIndex;

    // Holds transactions for like address
    std::set<std::pair<int, CTransactionRef>> mlike_transactions;

    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest))
    {
        LogPrint(BCLog::MLIKE, "%s: invalid destination: %s\n", __func__, address);
        return false;
    }

    const CScriptID *scriptID = boost::get<CScriptID>(&dest);
    if (!scriptID)
    {
        LogPrint(BCLog::MLIKE, "%s: address not valid script address: %s\n", __func__, address);
        return false;
    }

    uint256 hash;
    memcpy(&hash, scriptID, 20);

    if (!GetAddressIndex(hash, 2 /* script type */, addressIndex))
    {
        LogPrint(BCLog::MLIKE, "%s: unable to get history for address: %s\n", __func__, address);
        return false;
    }

    int nMatureHeight;
    {
        LOCK(cs_main);

        // Mature height is 10 confirmations, so current block less 9 equals 10 blocks total
        nMatureHeight = chainActive.Height() - 9;
    }

    for (auto it = addressIndex.cbegin(); it != addressIndex.cend(); it++)
    {
        if (it->first.blockHeight > nMatureHeight)
        {
            continue;
        }

        CTransactionRef tx;
        uint256 hash_block;
        if (!GetTransaction(it->first.txhash, tx, Params().GetConsensus(), hash_block))
        {
            return false;
        }

        // MLikes TX must have at least two outputs
        if (tx->vout.size() < 2)
        {
            continue;
        }

        mlike_transactions.insert(std::make_pair(it->first.blockHeight, tx));
    }

    // Print history for mlike address
    if (LogAcceptCategory(BCLog::MLIKE))
    {
        for (const auto& pair : mlike_transactions)
        {
            LogPrint(BCLog::MLIKE, "%s: mlike_transactions height: %d hash: %s\n", __func__, pair.first, pair.second->GetHash().GetHex());
        }
    }

    for (auto it = mlike_transactions.cbegin(); it != mlike_transactions.cend(); ++it)
    {
        // Get TX for vin[0]
        CTransactionRef tx;
        uint256 hash_block;
        if (!GetTransaction(it->second->vin[0].prevout.hash, tx, Params().GetConsensus(), hash_block))
        {
            LogPrint(BCLog::MLIKE, "%s: could not find TX hash: %s\n", __func__, it->second->vin[0].prevout.hash.GetHex());
            return false;
        }

        // Get from address from vin[0]
        CTxDestination from_dest_address;
        ExtractDestination(tx->vout[it->second->vin[0].prevout.n].scriptPubKey, from_dest_address);
        std::string from_address{EncodeDestination(from_dest_address)};

        // First output should be to the MLikes address
        CTxDestination to_like_address;
        ExtractDestination(it->second->vout[0].scriptPubKey, to_like_address);
        if (EncodeDestination(to_like_address) != address)
        {
            LogPrint(BCLog::MLIKE, "%s: skipping, first output not to like address. TX: %s\n", __func__, it->second->GetHash().GetHex());
            continue;
        }

        // Second output should match address in from address in vin[0]
        CTxDestination to_pay_to_self_address;
        ExtractDestination(it->second->vout[1].scriptPubKey, to_pay_to_self_address);
        if (EncodeDestination(to_pay_to_self_address) != from_address)
        {
            LogPrint(BCLog::MLIKE, "%s: skipping, second output does not match first input address. TX: %s\n", __func__, it->second->GetHash().GetHex());
            continue;
        }

        // Get total outgoing from TX
        CAmount nTXTotal{0};
        for (const auto& txout : it->second->vout)
        {
            nTXTotal += txout.nValue;
        }

        // Get amount paid to MLikes address
        CAmount mlikes_paid{it->second->vout[0].nValue};

        // Make sure MLikes has some value and total amount is large enough to be valid
        if (mlikes_paid == 0 || nTXTotal < mlikes_paid * 10)
        {
            LogPrint(BCLog::MLIKE, "%s: TX output value too low. amount: %s TX total: %s\n", __func__, FormatMoney(mlikes_paid), FormatMoney(nTXTotal));
            continue;
        }

        // Map of payees and mature total to validate outputs against
        std::map<std::string, CAmount> payee_totals;

        // Total mature paid set to mlikes_paid as start
        CAmount total_mature_paid{mlikes_paid};

        // Add payee from the transaction currently being validated, remove later if TX invalid
        if (payee_history[from_address].count(it->first) == 0)
        {
            payee_history[from_address][it->first] = mlikes_paid;
        }
        else
        {
            payee_history[from_address][it->first] += mlikes_paid;
        }

        // Work out total mature amount paid by each payee up to this TX
        for (const auto& payees : payee_history)
        {
            CAmount nPayeeTotal{0};

            // Payment needs to be mature at the time of this TX to be considered
            for (const auto& height_and_amount : payees.second)
            {
                // Mature is current block less 9 more making 10 confirms
                if (height_and_amount.first <= it->first - 9)
                {
                    nPayeeTotal += height_and_amount.second;
                }
                else
                {
                    // Once past mature height break loop
                    break;
                }
            }

            // payee may not have had any mature TXs at the time of the current TX being validated
            if (nPayeeTotal > 0)
            {
                payee_totals[payees.first] = nPayeeTotal;
                total_mature_paid += nPayeeTotal;
            }
        }

        // Validate that previous payees have been paid by this TX
        bool invalid{false};
        for (const auto& payees : payee_totals)
        {
            for (size_t i = 0; i < it->second->vout.size(); ++i)
            {
                CTxDestination tx_address;
                ExtractDestination(it->second->vout[i].scriptPubKey, tx_address);

                // Find the output to the previous payee
                if (payees.first == EncodeDestination(tx_address))
                {
                    // Work out how much of the total amount they contributed to
                    double payee_share = double(payees.second) / total_mature_paid;

                    // Make sure value is fair share of the remaining 90% of the amount sent
                    CAmount payee_amount = (mlikes_paid * 9) * payee_share;

                    LogPrint(BCLog::MLIKE, "%s: payee: %s payee total: %s all payees total: %s payee share: %f payee payment: %s\n",
                             __func__, payees.first, FormatMoney(payees.second), FormatMoney(total_mature_paid), payee_share, FormatMoney(payee_amount));

                    if (it->second->vout[i].nValue < payee_amount)
                    {
                        // Does not pay enough, set invalid and break loop
                        invalid = true;
                        LogPrint(BCLog::MLIKE, "%s: skipping, does not pay previous payees properly. vout: %d TX: %s\n", __func__, i, it->second->GetHash().GetHex());
                        break;
                    }
                }
            }

            // TX invalid break loop
            if (invalid)
            {
                break;
            }
        }

        // TX invalid continue to next TX
        if (invalid)
        {
            // If removing this TX mlike value from the users total leaves them without contribution
            // remove their entry. Then check if at removing at this height their contribution is zero
            // and remove their entry at height, if multiple payments at this height just reduce their amount.
            if (payee_totals[from_address] - mlikes_paid == 0)
            {
                payee_history.erase(from_address);
            }
            else if (payee_history[from_address][it->first] - mlikes_paid == 0)
            {
                payee_history[from_address].erase(it->first);
            }
            else
            {
                payee_history[from_address][it->first] -= mlikes_paid;
            }

            continue;
        }

        total_paid_to_mlike += mlikes_paid;
    }

    if (LogAcceptCategory(BCLog::MLIKE))
    {
        for (const auto& map : payee_history)
        {
            LogPrint(BCLog::MLIKE, "%s: payee_history: %s\n", __func__, map.first);
            for (const auto& pair : map.second)
            {
                LogPrint(BCLog::MLIKE, "%s: height: %d amount: %s\n", __func__, pair.first, FormatMoney(pair.second));
            }
        }
    }

    return true;
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction &transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        std::vector<std::pair<std::string, std::string>> vOrderForm;
        for (const SendCoinsRecipient &rcp : transaction.getRecipients())
        {
#ifdef ENABLE_BIP70
            if (rcp.paymentRequest.IsInitialized())
            {
                // Make sure any payment requests involved are still valid.
                if (PaymentServer::verifyExpired(rcp.paymentRequest.getDetails())) {
                    return PaymentRequestExpired;
                }

                // Store PaymentRequests in wtx.vOrderForm in wallet.
                std::string value;
                rcp.paymentRequest.SerializeToString(&value);
                vOrderForm.emplace_back("PaymentRequest", std::move(value));
            }
            else
#endif
            if (!rcp.message.isEmpty()) // Message from normal bitcoin:URI (bitcoin:123...?message=example)
                vOrderForm.emplace_back("Message", rcp.message.toStdString());
        }

        auto& newTx = transaction.getWtx();
        std::string rejectReason;
        if (!newTx->commit({} /* mapValue */, std::move(vOrderForm), rejectReason))
            return SendCoinsReturn(TransactionCommitFailed, QString::fromStdString(rejectReason));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << newTx->get();
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    // Add addresses / update labels that we've sent to the address book,
    // and emit coinsSent signal for each recipient
    for (const SendCoinsRecipient &rcp : transaction.getRecipients())
    {
        // Don't touch the address book when we have a payment request
#ifdef ENABLE_BIP70
        if (!rcp.paymentRequest.IsInitialized())
#endif
        {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = DecodeDestination(strAddress);
            std::string strLabel = rcp.label.toStdString();
            {
                // Check if we have a new address or an updated label
                std::string name;
                if (!m_wallet->getAddress(
                     dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    m_wallet->setAddressBook(dest, strLabel, "send");
                }
                else if (name != strLabel)
                {
                    m_wallet->setAddressBook(dest, strLabel, ""); // "" means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(this, rcp, transaction_array);
    }

    checkBalanceChanged(m_wallet->getBalances()); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits

    return SendCoinsReturn(OK);
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

RecentRequestsTableModel *WalletModel::getRecentRequestsTableModel()
{
    return recentRequestsTableModel;
}

MoonWordDialog *WalletModel::getMoonWordDialog()
{
    return moonWordPage;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!m_wallet->isCrypted())
    {
        return Unencrypted;
    }
    else if(m_wallet->isLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return m_wallet->encryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return m_wallet->lock();
    }
    else
    {
        // Unlock
        return m_wallet->unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    m_wallet->lock(); // Make sure wallet is locked before attempting pass change
    return m_wallet->changeWalletPassphrase(oldPass, newPass);
}

// Handlers for core signals
static void NotifyUnload(WalletModel* walletModel)
{
    qDebug() << "NotifyUnload";
    bool invoked = QMetaObject::invokeMethod(walletModel, "unload");
    assert(invoked);
}

static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
    assert(invoked);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel,
        const CTxDestination &address, const std::string &label, bool isMine,
        const std::string &purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(EncodeDestination(address));
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(QString, strPurpose),
                              Q_ARG(int, status));
    assert(invoked);
}

static void NotifyTransactionChanged(WalletModel *walletmodel, const uint256 &hash, ChangeType status)
{
    Q_UNUSED(hash);
    Q_UNUSED(status);
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
    assert(invoked);
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    bool invoked = QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
    assert(invoked);
}

static void NotifyWatchonlyChanged(WalletModel *walletmodel, bool fHaveWatchonly)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
                              Q_ARG(bool, fHaveWatchonly));
    assert(invoked);
}

static void NotifyCanGetAddressesChanged(WalletModel* walletmodel)
{
    bool invoked = QMetaObject::invokeMethod(walletmodel, "canGetAddressesChanged");
    assert(invoked);
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    m_handler_unload = m_wallet->handleUnload(std::bind(&NotifyUnload, this));
    m_handler_status_changed = m_wallet->handleStatusChanged(std::bind(&NotifyKeyStoreStatusChanged, this));
    m_handler_address_book_changed = m_wallet->handleAddressBookChanged(std::bind(NotifyAddressBookChanged, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
    m_handler_transaction_changed = m_wallet->handleTransactionChanged(std::bind(NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_show_progress = m_wallet->handleShowProgress(std::bind(ShowProgress, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_watch_only_changed = m_wallet->handleWatchOnlyChanged(std::bind(NotifyWatchonlyChanged, this, std::placeholders::_1));
    m_handler_can_get_addrs_changed = m_wallet->handleCanGetAddressesChanged(boost::bind(NotifyCanGetAddressesChanged, this));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    m_handler_unload->disconnect();
    m_handler_status_changed->disconnect();
    m_handler_address_book_changed->disconnect();
    m_handler_transaction_changed->disconnect();
    m_handler_show_progress->disconnect();
    m_handler_watch_only_changed->disconnect();
    m_handler_can_get_addrs_changed->disconnect();
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    bool was_locked = getEncryptionStatus() == Locked;
    if(was_locked)
    {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _relock):
        wallet(_wallet),
        valid(_valid),
        relock(_relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

void WalletModel::loadReceiveRequests(std::vector<std::string>& vReceiveRequests)
{
    vReceiveRequests = m_wallet->getDestValues("rr"); // receive request
}

bool WalletModel::saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest)
{
    CTxDestination dest = DecodeDestination(sAddress);

    std::stringstream ss;
    ss << nId;
    std::string key = "rr" + ss.str(); // "rr" prefix = "receive request" in destdata

    if (sRequest.empty())
        return m_wallet->eraseDestData(dest, key);
    else
        return m_wallet->addDestData(dest, key, sRequest);
}

bool WalletModel::bumpFee(uint256 hash, uint256& new_hash)
{
    CCoinControl coin_control;
    coin_control.m_signal_bip125_rbf = true;
    std::vector<std::string> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    if (!m_wallet->createBumpTransaction(hash, coin_control, 0 /* totalFee */, errors, old_fee, new_fee, mtx)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Increasing transaction fee failed") + "<br />(" +
            (errors.size() ? QString::fromStdString(errors[0]) : "") +")");
         return false;
    }

    // allow a user based fee verification
    QString questionString = tr("Do you want to increase the fee?");
    questionString.append("<br />");
    questionString.append("<table style=\"text-align: left;\">");
    questionString.append("<tr><td>");
    questionString.append(tr("Current fee:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("Increase:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), new_fee - old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("New fee:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), new_fee));
    questionString.append("</td></tr></table>");
    SendConfirmationDialog confirmationDialog(tr("Confirm fee bump"), questionString);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = static_cast<QMessageBox::StandardButton>(confirmationDialog.result());

    // cancel sign&broadcast if user doesn't want to bump the fee
    if (retval != QMessageBox::Yes) {
        return false;
    }

    WalletModel::UnlockContext ctx(requestUnlock());
    if(!ctx.isValid())
    {
        return false;
    }

    // sign bumped transaction
    if (!m_wallet->signBumpTransaction(mtx)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Can't sign transaction."));
        return false;
    }
    // commit the bumped transaction
    if(!m_wallet->commitBumpTransaction(hash, std::move(mtx), errors, new_hash)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Could not commit transaction") + "<br />(" +
            QString::fromStdString(errors[0])+")");
         return false;
    }
    return true;
}

bool WalletModel::isWalletEnabled()
{
   return !gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

bool WalletModel::privateKeysDisabled() const
{
    return m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
}

bool WalletModel::canGetAddresses() const
{
    return m_wallet->canGetAddresses();
}

QString WalletModel::getWalletName() const
{
    return QString::fromStdString(m_wallet->getWalletName());
}

QString WalletModel::getDisplayName() const
{
    const QString name = getWalletName();
    return name.isEmpty() ? "["+tr("default wallet")+"]" : name;
}

bool WalletModel::isMultiwallet()
{
    return m_node.getWallets().size() > 1;
}
