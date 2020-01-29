// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <checkqueue.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <hash.h>
#include <index/txindex.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <script/standard.h>
#include <shutdown.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <undo.h>
#include <util/system.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <validationinterface.h>
#include <warnings.h>

#include <future>
#include <sstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/thread.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#if defined(NDEBUG)
# error "Mooncoin cannot be compiled without assertions."
#endif

#define MICRO 0.000001
#define MILLI 0.001

/**
 * Global state
 */
namespace {
    struct CBlockIndexWorkComparator
    {
        bool operator()(const CBlockIndex *pa, const CBlockIndex *pb) const {
            // First sort by most total work, ...
            if (pa->nChainWork > pb->nChainWork) return false;
            if (pa->nChainWork < pb->nChainWork) return true;

            // ... then by earliest time received, ...
            if (pa->nSequenceId < pb->nSequenceId) return false;
            if (pa->nSequenceId > pb->nSequenceId) return true;

            // Use pointer address as tie breaker (should only happen with blocks
            // loaded from disk, as those all have id 0).
            if (pa < pb) return false;
            if (pa > pb) return true;

            // Identical blocks.
            return false;
        }
    };
} // anon namespace

enum DisconnectResult
{
    DISCONNECT_OK,      // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED   // Something else went wrong.
};

class ConnectTrace;

/**
 * CChainState stores and provides an API to update our local knowledge of the
 * current best chain and header tree.
 *
 * It generally provides access to the current block tree, as well as functions
 * to provide new data, which it will appropriately validate and incorporate in
 * its state as necessary.
 *
 * Eventually, the API here is targeted at being exposed externally as a
 * consumable libconsensus library, so any functions added must only call
 * other class member functions, pure functions in other parts of the consensus
 * library, callbacks via the validation interface, or read/write-to-disk
 * functions (eventually this will also be via callbacks).
 */
class CChainState {
private:
    /**
     * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
     * missing the data for the block.
     */
    std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    CCriticalSection cs_nBlockSequenceId;
    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    int32_t nBlockSequenceId = 1;
    /** Decreasing counter (used by subsequent preciousblock calls). */
    int32_t nBlockReverseSequenceId = -1;
    /** chainwork for the last block that preciousblock has been applied to. */
    arith_uint256 nLastPreciousChainwork = 0;

    /** In order to efficiently track invalidity of headers, we keep the set of
      * blocks which we tried to connect and found to be invalid here (ie which
      * were set to BLOCK_FAILED_VALID since the last restart). We can then
      * walk this set and check if a new header is a descendant of something in
      * this set, preventing us from having to walk mapBlockIndex when we try
      * to connect a bad block and fail.
      *
      * While this is more complicated than marking everything which descends
      * from an invalid block as invalid at the time we discover it to be
      * invalid, doing so would require walking all of mapBlockIndex to find all
      * descendants. Since this case should be very rare, keeping track of all
      * BLOCK_FAILED_VALID blocks in a set should be just fine and work just as
      * well.
      *
      * Because we already walk mapBlockIndex in height-order at startup, we go
      * ahead and mark descendants of invalid blocks as FAILED_CHILD at that time,
      * instead of putting things in this set.
      */
    std::set<CBlockIndex*> m_failed_blocks;

    /**
     * the ChainState CriticalSection
     * A lock that must be held when modifying this ChainState - held in ActivateBestChain()
     */
    CCriticalSection m_cs_chainstate;

public:
    CChain chainActive;
    BlockMap mapBlockIndex GUARDED_BY(cs_main);
    std::multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;
    CBlockIndex *pindexBestInvalid = nullptr;

    bool LoadBlockIndex(const Consensus::Params& consensus_params, CBlockTreeDB& blocktree) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock);

    /**
     * If a block header hasn't already been seen, call CheckBlockHeader on it, ensure
     * that it doesn't descend from an invalid block, and then add it to mapBlockIndex.
     */
    bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Block (dis)connection on a given view:
    DisconnectResult DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view);
    bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                      CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Block disconnection on our pcoinsTip:
    bool DisconnectTip(CValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions* disconnectpool) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Manual block validity manipulation:
    bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex* pindex) LOCKS_EXCLUDED(cs_main);
    bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindex);
    void ResetBlockFailureFlags(CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool ReplayBlocks(const CChainParams& params, CCoinsView* view);
    bool RewindBlockIndex(const CChainParams& params);
    bool LoadGenesisBlock(const CChainParams& chainparams);

    void PruneBlockIndexCandidates();

    void UnloadBlockIndex();

private:
    bool ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    CBlockIndex* AddToBlockIndex(const CBlockHeader& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Create a new block index entry for a given block hash */
    CBlockIndex* InsertBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /**
     * Make various assertions about the state of the block index.
     *
     * By default this only executes fully when using the Regtest chain; see: fCheckBlockIndex.
     */
    void CheckBlockIndex(const Consensus::Params& consensusParams);

    void InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    CBlockIndex* FindMostWorkChain() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void ReceivedBlockTransactions(const CBlock& block, CBlockIndex* pindexNew, const CDiskBlockPos& pos, const Consensus::Params& consensusParams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! Mark a block as not having block data
    void EraseBlockData(CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
} g_chainstate;

/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
RecursiveMutex cs_main;

BlockMap& mapBlockIndex = g_chainstate.mapBlockIndex;
CChain& chainActive = g_chainstate.chainActive;
CBlockIndex *pindexBestHeader = nullptr;
Mutex g_best_block_mutex;
std::condition_variable g_best_block_cv;
uint256 g_best_block;
int nScriptCheckThreads = 0;
std::atomic_bool fImporting(false);
std::atomic_bool fReindex(false);
bool fHavePruned = false;
bool fPruneMode = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;
bool fEnableReplacement = DEFAULT_ENABLE_REPLACEMENT;

uint256 hashAssumeValid;
arith_uint256 nMinimumChainWork;

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;

CBlockPolicyEstimator feeEstimator;
CTxMemPool mempool(&feeEstimator);
std::atomic_bool g_is_mempool_loaded{false};

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const std::string strMessageMagic = "Mooncoin Signed Message:\n";

// Internal stuff
namespace {
    CBlockIndex *&pindexBestInvalid = g_chainstate.pindexBestInvalid;

    /** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     * Pruned nodes may have entries where B is missing data.
     */
    std::multimap<CBlockIndex*, CBlockIndex*>& mapBlocksUnlinked = g_chainstate.mapBlocksUnlinked;

    CCriticalSection cs_LastBlockFile;
    std::vector<CBlockFileInfo> vinfoBlockFile;
    int nLastBlockFile = 0;
    /** Global flag to indicate we should check to see if there are
     *  block/undo files that should be deleted.  Set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool fCheckForPruning = false;

    /** Dirty block index entries. */
    std::set<CBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    std::set<int> setDirtyFileInfo;
} // anon namespace

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    AssertLockHeld(cs_main);

    // Find the latest block common to locator and chain - we expect that
    // locator.vHave is sorted descending by height.
    for (const uint256& hash : locator.vHave) {
        CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex) {
            if (chain.Contains(pindex))
                return pindex;
            if (pindex->GetAncestor(chain.Height()) == chain.Tip()) {
                return chain.Tip();
            }
        }
    }
    return chain.Genesis();
}

std::unique_ptr<CCoinsViewDB> pcoinsdbview;
std::unique_ptr<CCoinsViewCache> pcoinsTip;
std::unique_ptr<CBlockTreeDB> pblocktree;

enum class FlushStateMode {
    NONE,
    IF_NEEDED,
    PERIODIC,
    ALWAYS
};

// See definition for documentation
static bool FlushStateToDisk(const CChainParams& chainParams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight=0);
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks = nullptr);
static FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);

bool CheckFinalTx(const CTransaction &tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = chainActive.Height() + 1;

    // BIP113 requires that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                             ? chainActive.Tip()->GetMedianTimePast()
                             : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!chainActive.Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTxMemPool& pool, const CTransaction& tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    CBlockIndex* tip = chainActive.Tip();
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip.get(), pool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (const int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

// Returns the script flags which should be checked for a given block
static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& chainparams);

static void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age) {
    int expired = pool.Expire(GetTime() - age);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state)
{
    return strprintf("%s%s (code %i)",
        state.GetRejectReason(),
        state.GetDebugMessage().empty() ? "" : ", "+state.GetDebugMessage(),
        state.GetRejectCode());
}

static bool IsCurrentForFeeEstimation() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    if (IsInitialBlockDownload())
        return false;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (chainActive.Height() < pindexBestHeader->nHeight - 1)
        return false;
    return true;
}

/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

static void UpdateMempoolForReorg(DisconnectedBlockTransactions &disconnectpool, bool fAddToMempool) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!fAddToMempool || (*it)->IsCoinBase() ||
            !AcceptToMemoryPool(mempool, stateDummy, *it, nullptr /* pfMissingInputs */,
                                nullptr /* plTxnReplaced */, true /* bypass_limits */, 0 /* nAbsurdFee */)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (mempool.exists((*it)->GetHash())) {
            vHashUpdate.push_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);

    // We also need to remove any now-immature transactions
    mempool.removeForReorg(pcoinsTip.get(), chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(mempool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
}

// Used to avoid mempool polluting consensus critical paths if CCoinsViewMempool
// were somehow broken and returning the wrong scriptPubKeys
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& view, const CTxMemPool& pool,
                 unsigned int flags, bool cacheSigStore, PrecomputedTransactionData& txdata) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);

    // pool.cs should be locked already, but go ahead and re-take the lock here
    // to enforce that mempool doesn't change between when we check the view
    // and when we actually call through to CheckInputs
    LOCK(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);

        // At this point we haven't actually checked if the coins are all
        // available (or shouldn't assume we have, since CheckInputs does).
        // So we just return failure if the inputs are not available here,
        // and then only have to check equivalence for available inputs.
        if (coin.IsSpent()) return false;

        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->GetHash() == txin.prevout.hash);
            assert(txFrom->vout.size() > txin.prevout.n);
            assert(txFrom->vout[txin.prevout.n] == coin.out);
        } else {
            const Coin& coinFromDisk = pcoinsTip->AccessCoin(txin.prevout);
            assert(!coinFromDisk.IsSpent());
            assert(coinFromDisk.out == coin.out);
        }
    }

    return CheckInputs(tx, state, view, true, flags, cacheSigStore, true, txdata);
}

static bool AcceptToMemoryPoolWorker(const CChainParams& chainparams, CTxMemPool& pool, CValidationState& state, const CTransactionRef& ptx,
                              bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                              bool bypass_limits, const CAmount& nAbsurdFee, std::vector<COutPoint>& coins_to_uncache, bool test_accept) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    std::vector<std::string> forbidtx = {"465e9dfb27","61f9018c6b","405eb50c1f","63d25ed869","e485c52f14","b09c9c4e42","8f34cd33fe","f323a23887",
                                         "20bf7f06d3","237d8a4bae","79ce6dfec6","58bff431eb","eb72817e34","03847f0174","ed91cd6fb0","407776c21c","c5c830e983","e9a9303d70",
                                         "9c68373ff0","a4cb9af65f","64ac268a23","6c6659e69d","27acd535ae","6a445499dc","c1e5c9d207","570a2678cb","e779c17ebe","0bac1bde5f",
                                         "7edf9a1fc1","6bd372da6b","3501c2d446","c38e50d9d9","c39d315c39","eb8957bc80","e7976e4c46","f86c75bb3a","f85fa7fd20","d102021e8e",
                                         "39493b5c5a","e28ed14089","6ca8c54379","a73cc543d4","7615754a94","d101796905","0313df5468","7c0039ac81","4bb826dc60","9b292b8bd0",
                                         "d0d8e15d65","d25ca8cbf7","c4e089fdba","25b9bbd9e6","5b3fdf02b8","4e4f3181ea","dbf98a79ff","de1b1db34d","6fb568e704","8a5287da9b",
                                         "d1cc24f0ed","4733ad3bd3","885367e74c","b061f31ebd","d325116c2a","4afbdea57b","db5059e58b","e720d6d35f","b8df85c703","7181b9ef31",
                                         "20ddf67f69","59ee6eb501","5d0e75d7e2","2f43b42c4b","fe5f79740d","d32d8ecf7a","766ece15a4","69bfef60ab","dbda347daa","2a9b9e810e",
                                         "36fd3fd67c","2db2157627","83a96bc1dd","4e77db8006","08428ff78e","6ff48a58f4","5753477765","7862c455b3","3e400dccc1","f50baa662e",
                                         "c6eb6e0248","abc260e7fc","23bf735052","559cbd2769","63f772572d","44a8df8310","a8ad36ae7d","a6e120e1e2","4053d9f6cf","898d5d4458",
                                         "43fffc0d07","be59f8b6e6","db4a33a35e","a7ac71eda9","9612520418","411f8ed275","68cadbd621","04248ecd20","1e77c959f2","3689eb19eb",
                                         "214ea74075","43ea7dc59a","8ddfde7dca","f02132daa4","0c449a3609","47c5226b19","0eef7d3b9c","0094f4ec2d","c32bc30c72","7767be6140",
                                         "a03ee20ebf","cb3f4c82e6","3193196ae0","9d6120c75c","3e91f263d4","e879df4ce5","f781702c33","e7b4913c4c","0a9693b628","25001ecbd3",
                                         "c1f27d0b6c","54f210f9aa","843ab7b08c","88cdad90bf","079565d7e4","f2353d3620","5a7c562ab1","d010e473f5","deade4043e","5d26c58030",
                                         "693d58f097","4f5a115ce2","01b143e315","f3c14b3516","6259aeda11","10d7dba3b1","635a1c2b94","5c47369b1a","e7e2c823f7","c738e3bccf",
                                         "c8094ba931","286f1a800f","52c6d6f15f","478f28cdcb","a206bec63f","c8aa8fcc48","05503e6284","29ed80b434","49edf73d2e","b9d4c723ad",
                                         "da7c2932ee","649096f7ac","e406e4f5f1","737dc42049","78f542faa1","b59e753903","529e916627","303cc0dec6","0291dd23e2","6a88557f51",
                                         "7eab441e92","a5fb75b237","f21e87c051","1393e4b704","5b98445edb","a9882e2bf1","f496c2f42a","c58bb4885b","f9c8b1dfb5","6f3f271534",
                                         "c83b08b950","14a76108f1","5de0afe592","e44dd22caa","a3b7a50067","3f02024082","ae82ebb6bc","62e0353114","1936d77054","4cae463309",
                                         "b27ed7b257","10550125be","36fbf05cff","ea8c22e0e2","4e68d1a39d","5aa28451b1","423abe2425","38af12ccd3","d58a3e34cb","64422acef4",
                                         "db35e52f4a","677173eb77","2e9c38a57b","ea970f0d27","0e1c516c6e","b01527259c","a288d4b64e","eff4cdd45e","5b47a72843","d1e5e77ca9",
                                         "515493ac82","63fbe69bb3","e28ad822f2","fc6dda31c7","beded1e05d","0a26947b9f","f876f51956","f5e136fa2d","bfc5f43ecf","615862862e",
                                         "9931f93746","6d562446e8","a0319221c7","3a9f4266a8","952af2928a","aba29ea044","2cb1ce1fcc","8061c5650e","7b856cf71e","9d9e4d093c",
                                         "92938dd93f","86b49fa64c","95f2e37295","945a6b53b1","fce652227e","a87dd310ab","4c5340a001","764bebd1dc","337708cbd5","83acd795bd",
                                         "1913265bc0","3e5c72eaa3","050c456266","093c1fb09a","6c97aa9826","6b218fc39f","c279d3c0a1","56beeda5d3","f2325cf3ce","a4955b1bb6",
                                         "435278ca7d","5969988470","f227b230f2","530c162364","85c143bb98","af8c2f87ae","6aec12f322","d6bd1bd321","1b446609e5","61ce42d140",
                                         "aedabb7a8a","d559beaf16","e0fdbf2ef8","d679756bdb","a9f3d0e86c","a3e5ec58bd","2a39743eec","a03ab7c260","d7e36bbe60","5629e12b8d",
                                         "6cdb67cc93","d7f7b9b24b","3effef55b9","b139cc1d37","3130097636","4ba84e3fd3","d9dd3b2fc0","f5e9b60e7c","8d0932bb29","73d0860e93",
                                         "38f3dd51ff","a0888d8dc0","baca9cb592","41d6bb0d4a","31234f5179","146839effa","b3455894bf","f677cc2a71","f841e88ca7","fed4c49b40",
                                         "8c131c517a","7488a2a1d4","4f92a5e245","e4bb212f9e","7a411855af","af7969e72b","4de82de0e2","0679f7ea79","ba410832c8","1f01bc771c",
                                         "4c37ba09fd","542a8eb2c4","36efc19fed","8a0a27d586","532e1f5701","a0ff6716cb","97a3c57069","5dafd50456","98dcf23462","26f12aca99",
                                         "700b831098","0fbd42ba5b","b0247f8b0d","948c9072d7","ac4fadd96b","b016f88685","4582aab1a9","cfd846cf68","d3061bd004","494e68e3d3",
                                         "bf15d5eda3","159a5fd3a0","3ab5894303","f1c2abeaf5","49da9aba51","c8fe8d8813","276e7e6b70","57450da9dd","0e37d081c7","05825965d7",
                                         "932731e5f4","a8a0349a9a","e6f1e20161","c6faad18a0","6d287f425f","7597da442f","e04e763117","6197201c23","61e3655a8a","7dc636c597",
                                         "bfb9a6322e","cc8532dcc5","40ca29d158","204451ad47","7d8b1e9fb0","32fe014b3a","35bc3edd1a","ef7bf4aabc","39564dd9b1","c9b3203a15",
                                         "9092713659","63f3ced48c","cc25331094","d90698461b","35bf8be144","eac5700ce5","79b5905d29","59079d32d9","b7db37e6cc","08874d523c",
                                         "cad856a75e","481a2de2c8","4ec0dd58b0","9b16976381","e263dee340","d7f147b70e","395a36e1e4","929b825b7a","9bdf96a6c3","036f9cb18c",
                                         "3c4e171042","0809f52e77","844507e13b","297cf2a67a","a3f9ee04ac","2dde156498","da03601a0b","b45b050877","1948f76f80","aa426c442a",
                                         "099e61cb04","37ba3f8698","854ee7da41","5f3bd54c35","442bbe70fd","626cb8e12d","45cf44047f","a1e2255e9c","08ebe206a0","6eefe2569a",
                                         "52cf5b8045","1631089987","e31dbd0d21","7d09bf779c","6b0f52d6e1","323bf383b9","d82330e1b7","f7c19bfe91","3502b8af85","693a55f4a5",
                                         "62d2b80cfa","975a91224e","27f31d22c2","d6b1fdecc1","3997804186","535be9b880","712c9646ac","eb6600bc4a","61e32322ac","20add4b154",
                                         "1042f319bd","79e6dd8a1e","41bbf48b5d","6b5ecd7616","c62d472abf","169b565a56","aad980aa5a","846f4b0ecc","447bea5cf6","3eee22ab98",
                                         "0dc00655b2","de530b7250","22edf276b1","ed7a830610","49cbd91356","758d76bdb4","28bf57f6ad","736472d07c","4ba68b783f","0dcf248fe2",
                                         "2a9fb6f327","2f4319c30b","410f0e3491","de9a4aaac5","6e73b0dd15","21b38bc27b","0658582b8c","74541cd432","b15ffa5e4b","a58630ba7d",
                                         "aa2c945d60","dbd9553678","6dcb7789f3","e01f664bc2","74764590a2","e2032fdf6a","d2121f82c8","d515dcc80e","720369e9a6","e9c9df71a4",
                                         "35c7dbdd6d","790243bcd0","a24fea26d9","d8d3033b3a","275c00dabf","65f6356e7d","783100740b","0fc9fa2a6d","8b76a34746","869be9282d",
                                         "5aba6b6202","3c775a304d","5f1a1d23a1","2ce154d5ab","b5e680e186","7a45a067a5","e55a0d1b5b","41ec1623e1","ce197f3b45","e9bb0a7f87",
                                         "fa88057979","2f4f4d6cb5","8b52b56ebc","76c41b3ccc","bf1a2ccf01","e869aedf41","8c020a1ff2","c8cc1f8d1e","8ebd17cb14","87c4fbd27e",
                                         "dccada6d72","2520530528","2a1ea40c3f","c4021c8fd9","80d157596d","c85b6ff1aa","fe05687959","b2ef5a2090","beb40083db","bb369dfdd3",
                                         "64bde62ae0","14b6ddfe7f","8c48b80ac4","ef320775b8","e902402999","e6c9ab186b","adcbd062ff","bd9475cee6","2d55849196","c5bcda3a6f",
                                         "54c1d5f4e5","3aa4fc27aa","f99d1e04d1","88e2d50597","08cda91094","014468a58d","09af5c2a5d","afbaa44273","0b9d5d1fef","028b06b03a",
                                         "8d76fa2a50","803cc0df61","475bb064ea","515926fe04","ec759655be","a390faaa79","d0d0089c63","30695980ad","9580d23045","1c239f1413",
                                         "9aad6f7aa3","354b0ae01f","69e1113cb4","4f6622a1a0","a9c06ca38e","9d63ba2e19","a469f39761","246a16e087","1ada5ca6ca","084746be70",
                                         "4dd3195912","825e3a7c73","1b906d5fea","d4c5236fb4","a9379f0390","52e4246c94","4034925861","981aa02c18","c39a129127","6a226f23d8",
                                         "9fea9fc226","e873d327b2","e3896951ad","86dace96a4","707687fbdf","4bbc2cdf35","973d49b4fd","65b0a1d8ae","c15ff9225b","e07d07fb13",
                                         "7262f7452c","372182afc0","6bb34c1492","b91e39c97c","09db50d7b7","d10fc648b1","4cae41cb2e","48c6a870b8","61f7611f28","8bfda68038",
                                         "99106e4866","6d62ef4f55","8f86f47aa1","834f729c2f","5e7948ea16","029aa9c209","b59474abbd","86532cf6bc","c4d6be7665","e0218973f4",
                                         "c9c9561e99","9420260ae1","336f9b9875","6125189dcb","fcf6311f1f","30f28f9a63","f720c584d2","43fec8502e","20c660c918","c1269f6994",
                                         "bd54c36837","8f466c7753","fb6b90118d","560051afb8","f95bbefb3a","69cf73028a","929d170f91","f8d47c33f9","97be682631","bf10572da3",
                                         "a05d180270","e91984d296","46e3084283","58c3618aa3","ea5a45ede6","85e6379d6d","6f9229c2b8","110e8be36f","f26bdccd28","92812e42f6",
                                         "55052aa944","0529234627","249ee69d7a","7cc2a22d37","203b086d36","fdbe8640a0","62f97134a4","ee124ebcbf","42759c0e2e","d7bcf8a334",
                                         "4a84783e9c","edfde78fa9","358302e8e0","0efbd61109","77915683c9","67c419f9bc","57eb67d6fd","6ad226e485","0a8b69ab4f","5b656ea63f",
                                         "82ab7ef7e3","7c67ba1c0a","bee05072b1","8eca794ff4","679b181124","ba39329ea0","1692973e3e","5c641bd91a","99fd3e8ca4","3e984f423e",
                                         "b6ab12ec48","0a2dcb9e4e","76aafd3a59","91534111e4","5c18026b1c","da7fa079ad","3603dded78","90e22d9e59","f2e176fbd9","7edcc8b510",
                                         "10d81eb24e","22739c4a7e","b03ede645e","0979bfbb4f","6ded35c2c9","322d768667","5afddbf729","07d9c36f62","8d18cef7eb","f595abfa77",
                                         "61e55fb7c6","3dab06387a","11f90751bc","33dd5e8765","ca505fc281","08279d2079","e1a549d36a","580cc2a9de","3cb52a8420","7384fd88b3",
                                         "60f2314708","6d4ed18e07","db689f5165","94be3dbeec","2aa03e3b1b","06d3ee6b8c","d0696f61ef","8b03b50d0c","1bc9afbea7","733177a10d",
                                         "5d34dfd44f","c20d3c1232","956d646203","453ebcaf5f","b3721cda90","db7cdd13d2","8c9165cff0","30cb7c8d6a","9e88dc8029","aa13e2bb07",
                                         "28683b999f","63a3b15b02","ba178723b2","bb34da1964","741b29ed9a","3576a86691","9a0bc385f2","aa3118711e","af159a2e38","b29267a79b",
                                         "333d575a30","74c387e254","fcf5804aaa","74cad5ffbf","89fa055b87","065838fb67","acd3a23aa3","11ff3230fb","fbaa426327","78e65ad3c8",
                                         "7bf35c6ed5","c49a7085d2","06e24f319a","df52f40d03","6c62805b04","0a219a34fe","7a66e1c564","3c06251b2c","15d2ddcf75","0ab34168a1",
                                         "a6d9fa53cf","463d77d65f","539bcb80ed","27c86a7d54","057d7b4135","2037ef3bcb","76016cccaf","3a323eb8bf","8eee1d8052","929533fe74",
                                         "055f88e86d","9a99d7fc7e","9e5dc9538a","0aeebc6b91","2c666976e2","e23dec44fd","aa0a015ea9","5311d421f2","0fc534b513","b35e3a624d",
                                         "56d0a2625c","b8bdf221ad","c63ea1261a","720ff840d8","2f59fc0220","77a780c3fc","7d52cb5141","1407b6ef5b","818b141f99","8591d3e40e",
                                         "160685607f","44fe8e8e8b","a560ce17ec","1c18fd85f5","ae456d3f50","682811c3c1","60447a91b6","d2f2c6c1c9","114cc52b6c","dafad6e16e",
                                         "d1509ef17b","6ae905d4f0","2e7fcfd39f","2f51fcc06e","e5fd5b2f2c","732c330b92","e8a6756382","f78dbf05a2","095227da45","14a94f99c9",
                                         "e781115e60","1b422773da","45e60d0858","4d4945d5c2","54b0da7307","10c2ffa248","ce3426f644","df9a84aa88","7dde9d4d14","d519b02567",
                                         "e0941a6001","327dddcaa7","4f97fca0c9","ce7030803b","31d4315b81","8d5d82e08d","3f53aaadb8","9624678935","a0795d2e1f","0e75c9da4c",
                                         "ae0940db23","b2fc5a948b","c527565365","68c509b450","4b0983fdc1","4c2f736df5","92eca44e73","9621e3d8db","085d72cabc","4f4b42b902",
                                         "aad36a65bc","b29ee5b34d","5e892e9d07","5ebb6f0ef8","67b16ad1da","d216ed4e63","f4778bd587","f68e76689f","f93afe8768","76b848a4d3",
                                         "1b330e7e79","81116abdda","814f81ee50","1bd3712313","897b59c190","1e26e69cdf","91357b43aa","9a30dbbca7","9b5c6fb56a","b394a0da50",
                                         "bae97b2248","657ff5137c","cae78f06ee","cbd54b6023","cf98559e36","32913d3b7b","dc996b6b03","de077233fa","74031cd393","740d932d4e",
                                         "ebbff1b14a","f42d1400f8","16f7303fb8","7611d9f63e","35f928dc1f","3c62d7830d","81a4ce2361","907eaf4c9b","4c2a4b8ff6","23ef749b91",
                                         "4e8bb9ff71","5450a83424","ac0fca1e0e","5a3e968cce","128c683ae9","b37d1560d6","be3cc998d0","642cfd8f64","c2ec49b24c","cd4a0b4f7a",
                                         "69107d95f3","0a2c969034","d00027d315","6bfdaa3588","71a6b8b3b8","14b3b0b5da","33c680866d","dcfe722e4c","e275838bfb","e75979d43b",
                                         "74571b3fb7","e9ada1ed98","f4bde24db7","3ae0ec79ab","780db8d674","78971f7d05","7bb4490a9b","405320cc7a","40c9938479","827d916642",
                                         "86ab5f1723","d95768a9d0","dc6ce893e2","34aac9a71c","e0aca84a51","e58a4dffae","f40ddb7154","758872121a","ff7b04586b","7fefa96f7d",
                                         "1d90c563a4","85ad0ca74c","118b3bb6c6","4c11bee74b","8bb9ed945b","8cc8aad979","4e7d6a4da8","093483c415","537d423cb8","9e4b16cdd0",
                                         "a361e2dc33","ae57c3cd7a","bfe853d5e6","c0fa951755","c3396dda5c","6a18328548","c60f8ba83b","cc4a90c36c","6ecad68136","d49a69a02c",
                                         "7290c0da1b","d578bccf04","d9a9bcdfb6","db5a9309c7","073ccb9f05","f440380734","789598d676","ff42b0c81e","79f994d264","7e10cba4d2",
                                         "435a61bd1f","801fcc312e","8627df394d","20db344e5d","92ea3af4c9","93831538cd","9a4f5ca2c1","9fbed23cfa","55408c0f8b","01e9dca744",
                                         "13e861ab43","b6a797c905","ba224020ba","be7201558b","bf86f52d74","c8b5ab8256","cb7e0f7976","713a5e83e5","3654c105ad","3906da3065",
                                         "196e0205aa","754049771c","eca1fda300","f2e4556244","76c362ba1a","f4afcbf015","fb79a7b57c","411f002f15","85080ac079","1ffb8ea215",
                                         "89b228fb38","4ceb23da5c","4e8a49ce54","9b053e033a","12b88fdad8","2be79b1e12","a752b9b414","2c24fb71b8","57bd63631b","589b817944",
                                         "5df507503d","b310192882","b962e8f8b7","bb7b07bd21","13d82656be","e735deaf77","791262c4b1","a73d13a8f8","6c1ed73234","299927e57a",
                                         "56a4b332b4","3306225fdd","c9f00ea064","9aed0164af","02f6179dec","c75cfd0baf","6f170c602f","73949b428e","dd93f6ea58","01ec382c2a",
                                         "043fc418b4","4a2ea277ce","51d5554ee1","537c9db6aa","2a51a26803","a11d14b293","6617a0b231","70bd2f07a2","d10625236a","d7421ac78e",
                                         "f0f9d49461","f1ef78e9d2","f58df783f7","f82737588d","7b267b987a","7e8660208e","854437503a","51b9f3c0bd","a0e370e514","a70c213fe8",
                                         "b2b4a154d3","689f4842a0","ce1a83c312","da68fcd566","e60918ac80","77bff60f99","f6e51e0843","07bf5bdc37","88a5d845a1","50952284c4",
                                         "963536d3d1","96f587a90c","0252c7a6a8","3103088f5f","69d370dd19","d325915906","0f8d49591a","46c229983e","87fc2e005b","8a86aa71ba",
                                         "4dbaab2c86","974f369884","52d7979230","c29d1b0d5b","cb202aea42","d369c1110c","155aff85b6","d5af1dd5f7","163a2bf667","e32f8919bb",
                                         "e9c4a2aa0b","7cb2442551","0eeda8cf37","43959aeb87","11840bde45","9404759c5e","51ce65c27f","9993f820ef","55bb5e7796","ab6097913f",
                                         "ab638cb6c7","66bfc4c4c3","336ea6d3af","d6fcb68e52","0ad3d3e4db","dc2b3e5840","f0a92acb9a","19838409f6","4af99b34c6","1c8b05e9b7",
                                         "92d2393411","9bc002c748","9be428272e","295873a4be","9d2233a165","9e75bec0a1","e1ccb576a2","3feabedcb0","8b2d54ad83","7aeaa0faac",
                                         "b6e887be39","03f543e4ec","30e1997058","08774456e2","87ee4c6e38","1b20fc5fd2","72483e5f16","0b63225648","6bb976f957","0dfb6b4cc8",
                                         "dc1ff4aeab","3486be8c60","f2a3e535a8","43cb6c0c36","27f225f6a3","5202af3825","40d98ad5f2","d26f59c017","f5893451d5","fc6c1f98dd",
                                         "12eb64ff47","623c5dd8c6","0bb9ab33e0","7ae6c05ad9","66ac68ca20","ee7ca80095","4b53721ea2","10e9edaefb","0b667d6a42","55d102149c",
                                         "8b923d1324","7c0e8cb48f","703e161403","c8bf956547","e67cf783a5","6ae1bd5be2","29562a8921","e601b30eaa","d5b1bad0c7","b84c0f9253",
                                         "caa2a19539","a6d37dbe9d","c9d12bf90e","7a2b460136","a136f5a472","9ce3cf48b0","534b63d786","9c9a1e2135","2016332ddc","86f10777c8",
                                         "b972627d57","4fbb7fe1b0","ee66027e83","cc2e4e3f0b","7786e4ffdf","fd6d448c42","17961b3e4f","a7c9164f06","e0269e9786","65086e1f94",
                                         "b15b31fdc9","5927646851","0eadb41cf2","d86e8c6129","607889b35d","11bf2a2e84","f069cfb691","198e6d0e55","c37257650c","5d91387852",
                                         "b96ebb2ce4","ac70169669","8be31a2ca5","70233c21e2","f50a48b384","3840dabefc","c8fa6b327e","d44ad6b2af","984c797514","2bbf241d5c",
                                         "d98ec8ffdc","24d6874b09","9273f6b409","7547e825f2","2eec388af9","8e62e90428","8b8f2fcf1f","ca1de95f15","7474b69fbc","3db2f3fce9",
                                         "14ad0ab453","dd1c2b1920","7fb6e12c9e","7ebfb56342","88aa575d11","fa1fe76af9","863fe289c2","b08199f5c2","c0500f9214","b2adc5c484",
                                         "f55acd1f6a","894199cf22","657152e4b5","e55cc3826e","8a487e7021","8d8cc131d5","6eafad35ae","21ba929766","db072ed444","e879855f8b",
                                         "82672fe71f","4d75037ae1","e817af70ac","cbf421b1b5","08ac98df4c","788d130f37","e11ace7f35","4ff54430e8","b0ea087f90","c08d1a00f2",
                                         "b290f80cab","f756425a64","3671c3f19c","8fb8ba3455","363237909f","b9d6bf1777","354b8f2859","aca3fc838b","17cc850db5","c8673798e3",
                                         "c61496a932","07d67a3ea9","00e1a63f6d","bd761112b1","9a6acd7b6a","1929578906","d05609e89e","d8cb6723d9","c9c9796a8c","ab723cb630",
                                         "1e1a6a279e","65103a63ab","000f7d71c4","a4fe251d03","0d63061cbf","e213e37c7d","4ec623db41","55d3980641","4f0ba4d988","8755af8997",
                                         "47e6f9ff3a","ff4c2bd8ee","e37ff22bb6","aa41a5e14b","6ca65000d8","9bffe229a5","ec6e0d31ce","9f141dc137","170bde20f4","0f5b3a9b74",
                                         "4008588c39","fd2eb4f66f","71b1c1a79d","e705e06c8c","7c54832cbb","a306ef3891","3291b20cb4","34bda82cbf","2c4bccc54e","651eb0849e",
                                         "a5d8e2f62b","383dfe0ba9","2c57060a0e","077306f33b","9948a9080e","1be414d8f9","7558ea5508","9bf06d8448","a553819f21","fb3e920628",
                                         "625d8e565e","37cdc90051","63fb80dd7a","39d369d42b","65269472cc","838e6aaa98","b86bee0828","484f80b7e2","4bc364ca7c","3f245bbef5",
                                         "ffbc938a70","3b64537f4c","41f7b2c801","7c8e6abeb1","5769017213","b84bada3a8","1a1fa3be1e","429bc4934b","00a426e631","ed9ad6c372",
                                         "20c95fe561","8bf3f5fa74","0cbda6120e","00b558370b","10ca8fa369","ffe07de89d","984f221f96","f5d2572a27","821bc3a979","75f7c1d161",
                                         "b491b9b47c","ff4796ab1e","ab6e8b47b3","a5b771ba01","398032e98f","1feb875267","9074728d7a","79db30665e","b8135ea524","d2d6d94980",
                                         "c71ec9eb5b","ff63834415","f6850daf03","e1b2db7827","bd6bdc2d37","6a9494ff6d","92c33bf55a","8e2cc07ce7","c54b4085c7","34159e4fbd",
                                         "5f584876af","f3e57f470c","5d62b0d078","75fa75f9fb","6e66488329","5e1f69d05d","8a6a749c99","c5ec9a3536","ebcc69207f","ff60e963c5",
                                         "303db9f915","f6508e15d1","5d2d3101ab","5055134abc","1f1b0724d5","9e2b878b8d","0b96677fb5","18a631b334","ffa334a574","a3e11e452f",
                                         "1cca90e53d","8be353d240","57fd1e735a","bb484bf39c","e2fa9aa230","3b32a5f1eb","1e5a62110e","d5230df289","79a6d18dd7","e27a679455",
                                         "7e526a4d78","31e3623c37","7d0ec21282","6fab5db750","efb7edafa9","7eb1aa8723","b734fcc815","fd3f93c243","116fbda5f3","233727f186",
                                         "99e39041c3","3a2067eeb1","e8ef6dca14","655ff9fd64","75382c161e","fcbf44fe43","927bd87fb7","7b32c6099b","385fad0887","b684d17d5f",
                                         "0823341ea8","69db036ecd","33f74e972c","3b17daa2ff","b44c25ced9","62b5adc8d1","315cf6d315","2e5609fd6f","fd79550200","7c9545f70a",
                                         "0578ebd4bd","f99abe8f2b","a8be50c687","c1a901e084","b1809d34b8","89c5d7ae99","7950edc408","faf1dbb65e","28d2089afe","5ce293ad6d",
                                         "52cb721f88","b38e939748","5584819362","12e3e1ea67","41ae47f73a","e7191297c1","e7bee76e73","dacc8628c4","8b5db3bc1a","ab530fc91b",
                                         "bacf03b207","50a9fc938a","34647583d9","300c6b9dc0","68d655b17b","71cb771e0b","a4b8e3fb08","f42ad584d9","7ce6f2654a","08070a340d",
                                         "aec8cd20b0","f345bc64b7","97f7120c80","d5375a98b9","fd9d001e67","158a579abf","1d394a5fbc","331db72457","000da84338","b06a28e2a5",
                                         "f853970ae9","74bc6e3ef5","020f6bb381","18691d11ad","11b9624a52","afd1d1e267","4952eec45e","05eba9607e","91d5de3368","17575cd406",
                                         "691bd752b4","ed0cd1b6f0","93a2b6c369","e52f8c9df5","14fd6e28a5","e2670abac7","43c0397aae","98bef32839","4f29ac6f7d","c800c6b831",
                                         "ee2b9c99ce","2eb2a83aff","9565f3bf28","e7880a68f1","d7d4bb9168","52a29686f4","e7afe48c56","dd781e1490","4f218ae2db","7a7d51762f",
                                         "20dbd9313c","00de386087","993f29887b","8e22679e4a","6fea811985","0a5bad948f","7a54f14cb8","900dcdef00","40240f390d","dd7df527e2",
                                         "415a68148d","35182090a6","6fd16cf8b5","af1afbe21b","22e28a0781","3e360f24e9","19984ed5a2","384c654aa6","a1355e6a94","c72a320d54",
                                         "1144dd4b37","f6795b8172","71d0bcba36","a197ab573d","d7a63364ec","d702be80ea","74e9c2af8b","9ee5e039fd","c41d982c8f","6bc447b43f",
                                         "33dbc93cf9","d2393bd0c1","334cd76637","ffd6ef9b95","0d9ac09cd0","31826e1970","53175cfca2","9d212a43c4","15400a3364","4cbc95a8b0",
                                         "b48fca9699","95e65fc7e6","4269234fd5","5350b96edb","79e21092e7","f7fe6c8c64","c043432a45","6feb8b1af6","ba4d77534a","50db416173",
                                         "7867303b9e","4e40df2ca5","4d3178dd89","5b0ec7dc8a","23e6e3e3a0","2d65a3c2ad","35fac35106","e4339d88b8","1dbd262fd9","bf65b6480d",
                                         "7428e1e6e1","36818f74fc","eadb4d170f","9a3e43f174","8a97f4e469","eb7eab30f5","744d5e3ab2","9b8ea5c979","520e30b2a0","5c0b7c263c",
                                         "ec13d8e29a","fc23d8b212","609d9e40bb","466296e284","ecc8035b57","b55c5406bf","86d1403d68","b94a501519","3eb9362b1a","f2e3224775",
                                         "46cfbd6929","a712859586","d7eb3c4f7e","23f1ade1a9","27429b01b1","10b227a4d0","ef13e39edb","e55e4e5c2c","2b5c2e49e5","a392ff612e",
                                         "a91d8fe290","f6db50f4db","30ce32ec7a","38ad8ed3aa","d2000654b2","f3a49c5cc5","b8f2f42414","ad065ba86b","cce940b1b1","989875dbd5",
                                         "b92b44c571","e53925dfd8","b967c24fee","936209b9b9","7d3017be8c","b65317b61c","6517cd2ddc","622f649dbf","ef7e149875","1a0d9479ac",
                                         "97a67e8985","3e116d9294","43e8a124de","83e374e5d8","8139c5cc1b","c2a95e36c8","9c2f4ca328","25b506b1d1","11fe590ba4","cd6d04d347",
                                         "c5419cac73","1768567a0b","109988f192","b60f69894a","572b8c0dcd","ea7ee57a49","c6184088c0","69849b748b","3a1bba004d","1660e3309b",
                                         "a6aef08343","09364498b6","b442580cfc","2fc1aa411e","cb8bb31d8e","4aaaaa8ceb","f0a1c3e58c","0f11df5eb6","c5a2d7f2f2","53b23d360b",
                                         "495b089940","aae73d0e9a","ec6e9d8353","3ec17803d6","7df114d236","8932b3dfe8","d5cd0cd331","b397c953f6","4c13e51511","c56e2adc0d",
                                         "fcf7a36aa1","cc2d80d631","a74f72872b","b35f0e097a","1c37bcfc33","78e6d84477","7323f88afa","2b7abb72d0","cd37f15b3a","fc4b9e8cf4",
                                         "2f712fb41c","6009536014","03cd6a0f48","d6e20b88b7","310315f100","90f8cf0f47","5b8ae29449","fae77f8874","62d1029bd8","6db0eab71a",
                                         "426aa5e109","bc1e27026a","bfccbd0931","1a451887f9","64372a7795","db685dbaac","ddc58ce3cd","1e60fc4cbd","80ab1e40a4","b456f2b08f",
                                         "ccb6746182","0720e73996","726f7c75bb","2253b4470e","9d0221342a","c84b0f7923","6e8a0b0f32","3b2e9d7e04","45a00b25cb","424e9694bd",
                                         "5153b19ec6","639abd8335","df07f04df3","1fb0a56ff9","6994273d9b","514b0cbc3b","e898546689","3236186309","c578537783","618a3ea035",
                                         "57c50597d9","2d3c05d8bb","83bac04aa8","e9f33f5254","3375c83ed6","5bec311a16","bb31d99bd5","8362d9b6bc","98e16ab8b2","b6028c285c",
                                         "4f307b0d60","54994bfee8","f3c2b84b1e","3501f2dfb2","987e96ea8c","0387963c6b","b2cf2503ed","8024e2c7a7","db6403a7b2","cdf2685d05",
                                         "7c063963a5","c7d3564f41","c6fc3c8c78","4655188a93","9740b3a9a9","1e12795169","54667681f4","6bb973d381","e22850638c","8c799d2a32",
                                         "f44a204e8d","74ba449a8c","98a49add23","ac823fd14f","c674428092","6699d149e2","e709b1f43f","40c7592ed9","aacf349cb7","949bee4453",
                                         "e3fe177ea6","82169ec95d","638f1daf53","ee76f6273a","5c171a2d23","f456cc5eb6","d7a98c38ef","08d735e822","2b3d870a7e","b7e8c3c5b2",
                                         "b6d8afa471","4e9163b6da","fb6c7652b8","d432aae731","3a99bffb09","da6df4ebc6","d3fcb0c188","9143c657e3","95a57ad790","ddda1136e6",
                                         "7ae482a842","ecd8431d8b","41ef91a48f","d18e4bb04b","dad3f3a42f","4edd38e529","4e01d31744","416509510f","ed166ea060","1427d29272",
                                         "1a2ced0e1e","c009cbc14c","25bedc4b66","5ec36f9701","1b7744475d","253b355864","225a132705","7c252a4bb1","cc17dac9d9","0d025fcb42",
                                         "fd1fcffe27","e9242207a9","332e28e6a9","cac164281f","69d921dad9","7b07038211","30635c99d3","49f1902952","1a4763adf2","90ba178270",
                                         "91e229d907","e040bf20af","263091ab76","07e8238f4b","16e709fe91","e79e4a83bd","d3d6cb8504","be1316441f","04171fc04a","879b55e99d",
                                         "a98b704615","7cbbe6f921","f89f86b1e9","8f6975ae7d","a2bf3d9a03","e3b50221ac","03114e90f4","34ee24d298","fa5e05c583","02029ef036",
                                         "7993ee6107","2340cce8e0","4dc970958b","8b177129b1","f66a72be87","16b1be2497","df33f361f6","24d5db297b","b70490ae3b","2031bc2a25",
                                         "95c9e7b2c8","684ae8bc4b","f76aad04e2","f5fd586076","927df6840d","3a64d7aa02","8189199cbe","a5465d0ce5","77c67ae76e","84208c4855",
                                         "60031cb0d9","84622a116d","fff3379a33","d6185ea31e","a744599193","7cc58e0dbb","2f646fa47a","1d771fb88f","2db99f94e2","a633e5b37f",
                                         "22f85958ab","7a0d6e64e3","43a6526203","83b47a817d","4aa34a43e0","6764632284","a35a1e4e42","30153773cf","eecdf3b0b7","e34bf58b00",
                                         "71462a8f24","633243ff41","4706f3ffc0","bc2dab60c1","7bd4e3098e","60798e72dc","9ac7d24edb","3d25b80052","d028a7cb3e","3a6f478a1e",
                                         "d892d1fed7","abc47e4e6f","b74f0c6d26","98368aee58","1ef7958b56","432653ea05","d31a7f3083","cf8579620f","fc9b61c180","81fc4188bf",
                                         "3d98e71774","e2393ecfba","4146de5c05","3365af0014","d91d096414","6d354efa3e","e8665174e1","6b551d31e6","4c07578a31","60cd411b22",
                                         "3f3442f3c7","2ef77056b9","2735f5cc59","bb660b22cd","ca65720f95","db054aad88","d050c3f0ee","f892211c74","d55dc16e30","6fe1ead336",
                                         "0ebcef6adc","6a8b72cffd","a3c9cfc489","bb6baf9642","adff411eb5","e5ffedd5b5","59fab7f43b","392278676e","cafe20ca98","26619465d7",
                                         "dbc853651f","e9253f1568","69bc0966da","fc24ecd5ec","7417c7fb5e","67d21b0775","19126d6a82","8cf888f1a2","9900b35bc1","994836f6d5",
                                         "387c084cad","a18c6d7b8a","fbaddcbe8d","417a8e22a1","abfcd1fada","1aa168f57f","ac6d3eef55","596e647e35","bfb0afb4c1","c4c1d87e56",
                                         "5cdfa87bcd","c60545e7cb","3a73e6f566","676750149b","d403cd61be","2e6e18e9be","48118a70c7","7dd8211165","4a1aefef14","4a6b956aa6",
                                         "0637380680","4dd48c12c4","a71fc12e97","391b8bc5ca","5404f9c557","a362c9b2df","d88251a740","526fffdf2e","8ced5be11f","bc2758581b",
                                         "e04d81a6cd","8da452afe1","49dd996e07","4dda67e425","53d32b5acc","ada320b4c3","ef154ca6f0","8102d380bf","fabbc9f116","4f64168f06",
                                         "b619a3c9b6","64b5130226","f81b6168fa","e1171a652f","708d3b8bff","cf2b43fc28","514d5467ad","5a9fcfbc06","60388c76e6","f593cf0c02",
                                         "c74bfe9610","39bca2eeb5","87d71ad0d3","51e03bb097","1550170c3a","9778613a61","d616b2e136","b682ad5243","d82229cb90","35649bfcd3",
                                         "cf1ea599d2","be6f30326d","f7ed4fd824","d26fa163b7","b4f69636bc","4f1f3fba93","a197aa357a","a8c85e7327","846b567fcb","a97a2b3e66",
                                         "9642893c83","ca7a649f9c","5f81405b03","e29b66d8df","8290b12f52","ab4d0b2bf1","6016ea3edc","162ac26934","958c2a632a","85feaa6c6e",
                                         "5dc19c6065","46bbdfd54f","a59cf31c60","b57473282f","f7b7c87fa0","c859a82551","7f265fc465","cbee68aa95","a73d86152c","4d8087b238",
                                         "3d12076d77","76d5f13d1d","8e8ce15da5","a7162ab95f","800e623b4e","29b72382b1","c570a69896","3b308d8f17","d56e8e2e02","abc59a3737",
                                         "4a351fd2c9","7e1baba89f","12d069a2f3","b2c4510885","3fb99da5e2","9f5947889c","299c2fb509","87761d00d8","ea875e5de3","783f081d9d",
                                         "1bdaf39aa4","958ee88e01","4e17680214","a9936b3ba3","0810d82d2f","02d0190de7","508dd09103","b8fce5cc90","07d32dda4c","da22adc644",
                                         "ba5c9bba50","049f842b5d","6ecb2cac65","2b34110f4e","91c78264c4","17003c5c07","9b405b2b76","4c152ea91b","52bb17dede","abc1de790e",
                                         "500864d352","189b7207ef","c15f3f8eff","c24243195d","5dbc527dc0","25b3c88629","64655033f3","d5d15859fd","d9cdc51ff4","706d607507",
                                         "d0f5f54d4d","4687862b2b","821d193432","7ec31a71eb","2e5342d531","09438ddf4a","65ada75927","10e5e93c34","00a8299219","32a4a6d6d9",
                                         "3c2ebda0ea","908857ca1e","9957ca587e","9bad879235","9fae860c58","0bdc176ec3","179b441d09","4dc2e0cb8b","a1e74a9dc8","b93a78a923",
                                         "ba0a27d424","bfbe68501d","c5718ab1e5","06703cb9fb","0f3e1b5fbc","cb0b310fdd","cc7741b836","6aaed246ca","db0a4b7204","e19dc9b7c9",
                                         "e36155134c","2d5cab2979","e44e7de5d2","e4adcba59c","f6943fcc97","83a6ab335a","128228bdba","885f9aa6fb","8eca4b6948","6832ec436b",
                                         "e9abee351f","d32a589f4e","904ab7f075","f3e0aab7f6","d7fbf0e427","b67cd9a6a0","90007f47e1","78b517c50c","8d7589ca0c","dce0fd839b",
                                         "f492ab567f","10392387db","6bd3d371fb","dadd470ee9","305b7596cb","9373722499","14907babd5","d8d788b602","11fc7b8c13","fe097aed85",
                                         "97c1e92a6d","a985506f23","a7ba444bb6","e2c74337a5","f1fea65b8e","ad10262211","9d3c26b332","d00eba58bf","2c57db0d0e","fcf00e656b",
                                         "2a356b6eb8","8e398b384e","9daeeba57b","d9becdfb16","c9c166c85b","b110ea896b","dec31de9ec","860ca9dc50","e3d1783f88","3f975f1c8b",
                                         "6c8a089351","5d845cf587","860c65d256","36f6d81b66","4359e82dcc","f2c1032704","29901f5bb4","cd636d99af","c5957c5043","361fd59714",
                                         "8e9ddb7982","aa1441e996","bf73b1d321","c329eb4976","ffdb627427","026ef92184","1521f3f289","2bf5833700","5dd4bf8f5a","fa9055cb07",
                                         "484b66835f","7ae3d5e725","38d1c937f3","d5977a1c14","83f5f8fdc2","14f6afc39a","0026adac27","5d88c795f5","d90560fd59","bfa35b5788",
                                         "898de74030","1413355e57","1d57a84f0f","3fb6ba28a5","452a9b9b9e","ef43bd0097","f534c58d8c","2206b7fb0c","f83a70fde8","44721b3091",
                                         "5baf672d9e","201ad5bdc4","811edcc785","6cfa1fff79","f46bc82914","052b744961","9c64fbf7b5","3da8784a8e","36bbf2121c","d617cd541d",
                                         "0697f273f6","6c54198644","3b2afabe92","70545518c5","5f2af8969c","920eb08113","444b605506","fc3100f5cb","2f47a41778","a475680380",
                                         "e3b18207ba","df94d1d4f7","e3febb7b65","e32d50109c","513b849a67","2b6cf072a6","0645fc6243","6870b2721e","b4c83793a0","95ff2a9821",
                                         "d69a5621db","ca74ee9ea4","57c0153fee","22a1ae7483","a076517c05","c832589062","b52c7f9ca8","671f962ee9","86d55e3cc0","4f04c7c33f",
                                         "e4da5c7670","ab591609a6","a1a319433f","b3ea3575ee","f54df261fc","18aa93de7a","8ed38d6683","a6e7aed7fc","0ed9d95906","0c0bca9e2d",
                                         "443d0ac6b7","bc130bb96f","98120bd999","5910c33192","3bd6305157","2bdf2ce338","c782335b11","4d2415974c","a537a48208","b9f34c7088",
                                         "48687a5edf","48f4e0c3e6","2e3f5f4412","2a3352ab15","3380f185ca","40df520cd0","0842743a7c","864a03d004","8e3998f51b","d3023c52a6",
                                         "bce4a4ca81","4001ae2971","88e7051348","222e4f9258","58ebd10657","7b59daf875","f8d1586fff","8993042405","b8f2a32b83","acc0160d91",
                                         "cb91c5fb52","346bdc247e","4357b72c33","9ab33b6da7","be5c30dccf","ccf35c9a74","594e8c7dbe","0db0fb3e66","213de3c33c","9b63fd625c",
                                         "6b47589fe6","11bf1e898c","d0cf1718b5","dcd3e99197","0d8d9d0f0a","9aea1166f2","e87f50a0a8","d52de22abd","ccae5f9dc6","ffb06cce87",
                                         "ca06093323","046e139789","c34a5fc824","05de1f7a3d","9760e30145","64a90757fc","d16435f34f","ef3946be28","c48dc830d3","2f809041d8",
                                         "4d9bb929cf","90a22e927b","08f8ba9eca","14d78df78e","e7ae145e94","94ec9a9a11","e9bb61dbad","02afa09161","26bd0447ab","f2f24acb94",
                                         "63f08b0d75","ae78eadabf","3c5d0d7abb","33086413ef","f4456e05e0","bec24c693a","8ab9873c09","784f89749c","98222480e6","db4805ee6b",
                                         "2bd629e1a1","020b328504","f10ee3474d","a7629d4dc1","b37074139d","3a98ca48af","974f30fe8a","89a91fd42f","e94312902e","dce579e850",
                                         "b72fc0a4c7","8592f94d3f","c46b9c1543","60e55bc296","edf58bdb15","23f22f6044","f127f9440d","26852a79ea","fd289b41e3","b7e25dc286",
                                         "f970b0c6a6","75d13fa371","6e6f15cc21","37a5a5f7e9","56b706c2de","ee796f27d4","7185747a9f","a73fd5ea5e","f419934c5e","2f8babdb80",
                                         "b5d14c6a44","73c3266e24","520b0d6d52","223e97c547","ecd4a46fab","f06733d112","ba96f1079b","139f3314cf","f2c8a9d209","2d23308893",
                                         "6637939005","87255025d5","cf82071887","57677f28d6","69cb3a0aa0","ead4dbf6ee","2804e0de95","6a4226329c","4fb291e152","ee582b03ba",
                                         "592dc9f092","b291c9ec2f","6bce9f58cf","d92f71c132","b099f63f97","8431b9b438","e849c2c461","e2a701f3a5","5f048fce78","47747936d0",
                                         "793c5fabc8","6cc8f2309f","1b726434c5","faee8ab90b","576f7146ca","f86594eb1b","0700107b77","5a70720a2e","66d31ef290","56089e473c",
                                         "5ad24601f5","0b81335222","156506222c","14338c0bc2","a9e4807b3c","217e25de50","b680f212aa","1229ec996c","ff0587453a","14d173a9f5",
                                         "7aeb6cbe3a","77cab06130","491f5af15d","19181a0fe1","12e2b206cc","0b1931b4e6","63d9deaf9b","6442ca9b23","491393f0eb","614a4c2177",
                                         "87660d0722","709bd17ff1","c0e55a0cb7","e884626fff","a41dada39f","be2ce0e472","991b358429","674f73e413","82133047c2","676725e958",
                                         "8e3126a235","964a659bc8","a3b5d4a172","10a30f8054","9113f64360","c021006bc2","6da125a97c","46080863aa","f00b76ab18","beecd938ba",
                                         "a61ff52940","f3cde591c0","c7127f399f","aa4068ae69","27d0510fd4","bc32512a58","18980bb784","216ca08203","7ab01df67a","7f26f4db74",
                                         "55cf1930cf","cf96c74b14","61d89d128f","21a7eb375d","8417bfaaac","aec7081f04","a4cfa3ede2","478459e523","a67d8d5df8","2daea7e714",
                                         "915f2c7f8f","7273ac4860","65b516bb81","df0bfbc2b6","67b9803673","09fbd5cb6d","2de5389f02","b29eb2a88e","1cca56f0e6","6d72b6854a",
                                         "4d183ce1fe","0c1a3d1f53","d9c84a3cf6","308f646417","599a687e4d","ebbbff144b","3bfc5e166f","b34ef45298","976d1366a8","925c5a48b9",
                                         "ddb0349a45","af1bbb9260","210c3fae5e","7bcfc4306b","9db709e668","d4e1491b96","0294526afb","ee47fa4075","f764d8af58","8091b86105",
                                         "838f601cf8","24ac267fbe","9e7c49300b","0f7ba1c8b1","4f2ee99c70","4f6399df0e","0fc8b62e05","5db98fbd1d","64ea108cef","da40d92928",
                                         "d6fe2a93b8","40beb77b4b","0f5f6843c5","fb8d8a6869","5a27663cd8","3410803665","e8b0b12371","7eb06fb062","0b8561f164","7e3f372452",
                                         "59ce43a6f7","f927017166","911c9bdee8","2221f603cb","25d2053dd1","d8499a5a88","b18944a7ef","40008e3b07","704dc6c544","c7414373e8",
                                         "c04a57288b","1622d54fa7","d899b96375","da6b4107ec","f12ef38984","0396e8cd50","f61df4ba0d","8ae199573d","32636b5fec","c43bd5dd54",
                                         "a4bd48541c","51611f7d14","8521277673","032e285f8c","1f5016f6b9","5b2ddb9993","6bc3ad49aa","a107446a6a","36d1fd3085","10eac9f43a",
                                         "c01b7ac236","6dca1418ae","8368ca137f","98f04690b7","d32256b9c3","91b6793329","f4ebd1a187","299ac7771b","81475d6c0d","0eb8801958",
                                         "dfce193e9c","8e045183fa","2d3ae019ab","8f04e6e896","e5db5387e7","a586b3bd7e","baac2b9956","0310d519aa","3fef1880b9","1079da6d6e",
                                         "d1424197d6","da6eb3e41b","75d4afd9bd","73ed79b736","dbf8437fc0","f593c152a8","103f4de5dc","c6b2758943","eaedf6624d","8533f8b18c",
                                         "8161b0352c","472c0ff7cd","72e9cba3ce","fcab45a347","1622e4166f","29c2804d40","af57af0b4b","2ab1351037","5952012331","0755a1a468",
                                         "5cfe16d770","c424f647a7","ca7b683d07","333541d16e","76df5c48a9","8de3c281b6","28cd8d3fdc","28fcc2f877","b83c7620f0","2daff9e569",
                                         "2ee9b22ad6","0094604531","cd7944c79c","3adae57c88","00f0d77400","efddd3ea22","eeca75e991","4036b8f901","9831f5766c","d5b5029b9f",
                                         "eff03bc753","5800161f0b","b39f809122","bd5a1aacdf","2b2865fac4","5b42912937","c5beaab1a8","65416a5a09","d9950a92aa","dd331c6ea8",
                                         "e85a1eba9e","3e2bf6e3ad","9c4dd3da4c","894654004a","999579121a","2e6e37d079","c20a432316","d8f3ef4eba","b528bf7564","cc60b58ac8",
                                         "d0ae9c4c22","e2dad220f5","005695c01c","f86e8d8601","87e6debc2b","fbe64bb05d","fc026dd4ff","9ac493b9b2","9ceb0479fc","4983254527",
                                         "a2f2655314","06dd9ed4f6","a9f91e0a69","b080d83374","506fcad296","b57cc9d6ad","bfb7bf4ab7","c3fdcfde38","c98edacbbd","2fe23d15e2",
                                         "61c7616477","30fcd1f836","69f24c2ad1","382e8634f6","773a47e8cc","ec0f9a3f10","f0532452e2","834dfa8e98","f5c6623ec9","8efd8141a1",
                                         "8fb2c34a2e","905ff31b46","0f3e3e34d0","a3b91f3fb3","2a13403193","bdba580a0e","ed1a3f566f","f45bbab4c4","3f6807e8e2","44881cefd8",
                                         "5f78660810","63cfb058a7","79c0fcbb49","e8d0cb53f0","221cef78f1","5f574b9ea1","d2954062d9","9b09cc0c72","d02156a215","7427772d1f",
                                         "383a77914b","4e26543506","c5ffb0c5c2","eedfb5e3bf","83bc125214","14fc31833e","9dc6e9f776","a1d2a8b061","29f5b25ce4","f0fb561940",
                                         "c1f77141ec","365209d9fc","4517072aaf","6f73a2146d","6fb38b57a4","73100284c4","4e8d3941dc","b92526b45e","baeecdcf8a","2023259e0a",
                                         "6ba049258f","7426db9152","d1db53b990","25dde5ce2e","0375e8bc92","35fcbfaa5b","6cfb781196","4efeaa934c","e1324a96f8","26a385af0e",
                                         "c33b0b4700","164ba3b9a3","4448c59d60","f1c7b7fba6","3c581eb0bc","41cf6d996a","c0a94635b7","5276d19bb8","62da943943","fe2abf5e74",
                                         "4055121d2e","88e17d18c8","36183c7306","a5d3509eee","de67c75cf9","22a201c184","53e0d93a23","55bc0e137d","0d38d2e86f","1549e4e8f6",
                                         "f06f9a8e82","40b65c43a6","d51be612b8","dd8276d0e1","60ede15013","9eb4c12e2d","20ab9d541d","d921b1326b","f14aa12be7","8ea50185db",
                                         "5ca463f80b","83904d512d","09b1d05d58","636858bf4c","f471f2aba6","15ef288eca","2d264f8db4","f227e2150d","6d2a63ab9a","8eb5fc8786",
                                         "8797306f66","a062986d89","2f27f67595","f59a2f6614","f1cbe0f96f","c6667350e1","08007efc6c","9c6c15667c","b3d06979f7","f4b9ff826c",
                                         "526786f434","e0c34773c0","558f315bf8","5188be94b6","142bd6399a","8d5f6d35e6","3718e878c4","02b01d6d3e","fd0a1c27af","aabaaf8bf5",
                                         "8c7b3d719b","97e3762c4d","2fbe8cced6","472fd5b432","fb90effff4","44ab3e77d0","de1f48c913","3db515ae13","0bd8646b6b","8a6e5c2d95",
                                         "bfd70a1698","19c102ebce","e6bc647e08","4f3b49cd7f","a02ee2512f","7871494862","af3877f6a8","b18e4baf60","9363d56043","b808c71ea0",
                                         "781345470f","d582f8876f","99875ceb19","5061e68044","bf0da3cc99","4f26a9b788","c1ed7a195a","a1f9422142","b19c8cdacc","48ca69666e",
                                         "483c12907d","bd0752852a","9bcd1f52eb","bb0251b0e5","e1417de7dc","debb160573","ffb5e9fe69","ab77efd594","1f23289782","3aacf13245",
                                         "e59256fee2","67cb426c71","535d6e25c5","6acf96d574","74569ab9e3","2bd0ee7c72","a7d9b4535e","531aacec01","10aa313c1a","4219f118b3",
                                         "2b3a7f54fb","92ec541a7a","3a37d4d71c","600b1a3492","ccf6f66496","3f62b78348","e50b57d4fc","eb3a6c5750","8f5201e7e7","ea7d435201",
                                         "7e9b422452","f5c7095e23","fa0368c17a","274d759bc4","a88c607b7a","5845cddfde","13a6a8840a","411a816133","1ad9ff90f8","01a53ab8f5",
                                         "a2f7098563","afef12024d","c0eac2cb67","c74d73c82c","707938c6a3","d3e1183b80","ed594cba52","7f1f0a1c0d","96bdc560dc","9f307077fa",
                                         "ae83fa92fe","58141c20a9","6585a51d61","723e0853dd","2984a61d5d","31ddac6b42","21771ca985","bfac9855e7","d6e89de422","7b5a70ca7c",
                                         "f56000097a","453a4e5d4e","4b180748e8","3a81101f11","fa27e6bfac","2062a45122","cee742e38f","1a65fe9c3f","ee08381bab","7356ff15c4",
                                         "1c3ae30146","103281acd8","bd8a73e620","e106842326","a6af3b36ff","d9b6bc6ab9","fe39cd91c5","3ed11cc73c","0f187a2116","b489f03b64",
                                         "d15fc73353","705d26cdf5","229bab9f51","f827acd708","0a1faa33c2","b36bc84e21","ce979013c7","d8d4565095","7a5106cdf6","4afca4ab5d",
                                         "cc0f868183","bade09518a","4a9a30736e","845d24fa17","d27370ba51","20af5564bf","c657ed1b3a","0a5d3f7126","8da48afacc","f515acdd69",
                                         "c98effc31d","aaaba98420","3c01226d09","2557aba695","aa3ee31497","d7ed88c13c","01875b9482","a32e81c411","be837ad88a"};

    const CTransaction& tx = *ptx;
    const uint256 hash = tx.GetHash();
    AssertLockHeld(cs_main);
    LOCK(pool.cs); // mempool "read lock" (held through GetMainSignals().TransactionAddedToMempool())
    if (pfMissingInputs) {
        *pfMissingInputs = false;
    }

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    // Reject spending of vout's in forbidtx vector
    std::size_t txdebug = 0;
    if (!IsInitialBlockDownload()){
        for (const auto& n : forbidtx) {
            txdebug = tx.ToString().find(n);
            if (txdebug != std::string::npos) {
                LogPrintf("tx: %s has triggered forbiddentx alert (n=%d, txdebug=%d)\n", tx.ToString(), n, txdebug);
                return state.DoS(100, error("AcceptToMemoryPool: Attempted spend of forbiddentx."),REJECT_INVALID, "FORBIDTX");
            }
        }
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);

    // Do not work on transactions that are too small.
    // A transaction with 1 segwit input and 1 P2WPHK output has non-witness size of 82 bytes.
    // Transactions smaller than this are not relayed to reduce unnecessary malloc overhead.
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) < MIN_STANDARD_TX_NONWITNESS_SIZE)
        return state.DoS(0, false, REJECT_NONSTANDARD, "tx-size-small");

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // is it already in the memory pool?
    if (pool.exists(hash)) {
        return state.Invalid(false, REJECT_DUPLICATE, "txn-already-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    std::set<uint256> setConflicts;
    for (const CTxIn &txin : tx.vin)
    {
        const CTransaction* ptxConflicting = pool.GetConflictTx(txin.prevout);
        if (ptxConflicting) {
            if (!setConflicts.count(ptxConflicting->GetHash()))
            {
                // Allow opt-out of transaction replacement by setting
                // nSequence > MAX_BIP125_RBF_SEQUENCE (SEQUENCE_FINAL-2) on all inputs.
                //
                // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by
                // non-replaceable transactions. All inputs rather than just one
                // is for the sake of multi-party protocols, where we don't
                // want a single party to be able to disable replacement.
                //
                // The opt-out ignores descendants as anyone relying on
                // first-seen mempool behavior should be checking all
                // unconfirmed ancestors anyway; doing otherwise is hopelessly
                // insecure.
                bool fReplacementOptOut = true;
                if (fEnableReplacement)
                {
                    for (const CTxIn &_txin : ptxConflicting->vin)
                    {
                        if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE)
                        {
                            fReplacementOptOut = false;
                            break;
                        }
                    }
                }
                if (fReplacementOptOut) {
                    return state.Invalid(false, REJECT_DUPLICATE, "txn-mempool-conflict");
                }

                setConflicts.insert(ptxConflicting->GetHash());
            }
        }
    }

    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        LockPoints lp;
        CCoinsViewMemPool viewMemPool(pcoinsTip.get(), pool);
        view.SetBackend(viewMemPool);

        // do all inputs exist?
        for (const CTxIn& txin : tx.vin) {
            if (!pcoinsTip->HaveCoinInCache(txin.prevout)) {
                coins_to_uncache.push_back(txin.prevout);
            }
            if (!view.HaveCoin(txin.prevout)) {
                // Are inputs missing because we already have the tx?
                for (size_t out = 0; out < tx.vout.size(); out++) {
                    // Optimistically just do efficient check of cache for outputs
                    if (pcoinsTip->HaveCoinInCache(COutPoint(hash, out))) {
                        return state.Invalid(false, REJECT_DUPLICATE, "txn-already-known");
                    }
                }
                // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
                if (pfMissingInputs) {
                    *pfMissingInputs = true;
                }
                return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
            }
        }

        // Bring the best block into scope
        view.GetBestBlock();

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);

        // Only accept BIP68 sequence locked transactions that can be mined in the next
        // block; we don't want our mempool filled up with transactions that can't
        // be mined yet.
        // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
        // CoinsViewCache instead of create its own
        if (!CheckSequenceLocks(pool, tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
            return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");

        CAmount nFees = 0;
        if (!Consensus::CheckTxInputs(tx, state, view, GetSpendHeight(view), nFees)) {
            return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

        // Check for non-standard witness in P2WSH
        if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, view))
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-witness-nonstandard", true);

        int64_t nSigOpsCost = GetTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS);

        // nModifiedFees includes any fee deltas from PrioritiseTransaction
        CAmount nModifiedFees = nFees;
        pool.ApplyDelta(hash, nModifiedFees);

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;
        for (const CTxIn &txin : tx.vin) {
            const Coin &coin = view.AccessCoin(txin.prevout);
            if (coin.IsCoinBase()) {
                fSpendsCoinbase = true;
                break;
            }
        }

        CTxMemPoolEntry entry(ptx, nFees, nAcceptTime, chainActive.Height(),
                              fSpendsCoinbase, nSigOpsCost, lp);
        unsigned int nSize = entry.GetTxSize();

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                strprintf("%d", nSigOpsCost));

        CAmount mempoolRejectFee = pool.GetMinFee(gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(nSize);
        if (!bypass_limits && mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false, strprintf("%d < %d", nModifiedFees, mempoolRejectFee));
        }

        // No transactions are allowed below minRelayTxFee except from disconnected blocks
        if (!bypass_limits && nModifiedFees < ::minRelayTxFee.GetFee(nSize)) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "min relay fee not met", false, strprintf("%d < %d", nModifiedFees, ::minRelayTxFee.GetFee(nSize)));
        }

        if (nAbsurdFee && nFees > nAbsurdFee)
            return state.Invalid(false,
                REJECT_HIGHFEE, "absurdly-high-fee",
                strprintf("%d > %d", nFees, nAbsurdFee));

        // Calculate in-mempool ancestors, up to a limit.
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!pool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-chain", false, errString);
        }

        // A transaction that spends outputs that would be replaced by it is invalid. Now
        // that we have the set of all ancestors we can detect this
        // pathological case by making sure setConflicts and setAncestors don't
        // intersect.
        for (CTxMemPool::txiter ancestorIt : setAncestors)
        {
            const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
            if (setConflicts.count(hashAncestor))
            {
                return state.DoS(10, false,
                                 REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
                                 strprintf("%s spends conflicting transaction %s",
                                           hash.ToString(),
                                           hashAncestor.ToString()));
            }
        }

        // Check if it's economically rational to mine this transaction rather
        // than the ones it replaces.
        CAmount nConflictingFees = 0;
        size_t nConflictingSize = 0;
        uint64_t nConflictingCount = 0;
        CTxMemPool::setEntries allConflicting;

        // If we don't hold the lock allConflicting might be incomplete; the
        // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
        // mempool consistency for us.
        const bool fReplacementTransaction = setConflicts.size();
        if (fReplacementTransaction)
        {
            CFeeRate newFeeRate(nModifiedFees, nSize);
            std::set<uint256> setConflictsParents;
            const int maxDescendantsToVisit = 100;
            const CTxMemPool::setEntries setIterConflicting = pool.GetIterSet(setConflicts);
            for (const auto& mi : setIterConflicting) {
                // Don't allow the replacement to reduce the feerate of the
                // mempool.
                //
                // We usually don't want to accept replacements with lower
                // feerates than what they replaced as that would lower the
                // feerate of the next block. Requiring that the feerate always
                // be increased is also an easy-to-reason about way to prevent
                // DoS attacks via replacements.
                //
                // We only consider the feerates of transactions being directly
                // replaced, not their indirect descendants. While that does
                // mean high feerate children are ignored when deciding whether
                // or not to replace, we do require the replacement to pay more
                // overall fees too, mitigating most cases.
                CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
                if (newFeeRate <= oldFeeRate)
                {
                    return state.DoS(0, false,
                            REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                            strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                                  hash.ToString(),
                                  newFeeRate.ToString(),
                                  oldFeeRate.ToString()));
                }

                for (const CTxIn &txin : mi->GetTx().vin)
                {
                    setConflictsParents.insert(txin.prevout.hash);
                }

                nConflictingCount += mi->GetCountWithDescendants();
            }
            // This potentially overestimates the number of actual descendants
            // but we just want to be conservative to avoid doing too much
            // work.
            if (nConflictingCount <= maxDescendantsToVisit) {
                // If not too many to replace, then calculate the set of
                // transactions that would have to be evicted
                for (CTxMemPool::txiter it : setIterConflicting) {
                    pool.CalculateDescendants(it, allConflicting);
                }
                for (CTxMemPool::txiter it : allConflicting) {
                    nConflictingFees += it->GetModifiedFee();
                    nConflictingSize += it->GetTxSize();
                }
            } else {
                return state.DoS(0, false,
                        REJECT_NONSTANDARD, "too many potential replacements", false,
                        strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                            hash.ToString(),
                            nConflictingCount,
                            maxDescendantsToVisit));
            }

            for (unsigned int j = 0; j < tx.vin.size(); j++)
            {
                // We don't want to accept replacements that require low
                // feerate junk to be mined first. Ideally we'd keep track of
                // the ancestor feerates and make the decision based on that,
                // but for now requiring all new inputs to be confirmed works.
                if (!setConflictsParents.count(tx.vin[j].prevout.hash))
                {
                    // Rather than check the UTXO set - potentially expensive -
                    // it's cheaper to just check if the new input refers to a
                    // tx that's in the mempool.
                    if (pool.exists(tx.vin[j].prevout.hash)) {
                        return state.DoS(0, false,
                                         REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
                                         strprintf("replacement %s adds unconfirmed input, idx %d",
                                                  hash.ToString(), j));
                    }
                }
            }

            // The replacement must pay greater fees than the transactions it
            // replaces - if we did the bandwidth used by those conflicting
            // transactions would not be paid for.
            if (nModifiedFees < nConflictingFees)
            {
                return state.DoS(0, false,
                                 REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                                 strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                                          hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
            }

            // Finally in addition to paying more fees than the conflicts the
            // new transaction must pay for its own bandwidth.
            CAmount nDeltaFees = nModifiedFees - nConflictingFees;
            if (nDeltaFees < ::incrementalRelayFee.GetFee(nSize))
            {
                return state.DoS(0, false,
                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                        strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                              hash.ToString(),
                              FormatMoney(nDeltaFees),
                              FormatMoney(::incrementalRelayFee.GetFee(nSize))));
            }
        }

        constexpr unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        PrecomputedTransactionData txdata(tx);
        if (!CheckInputs(tx, state, view, true, scriptVerifyFlags, true, false, txdata)) {
            // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
            // need to turn both off, and compare against just turning off CLEANSTACK
            // to see if the failure is specifically due to witness validation.
            CValidationState stateDummy; // Want reported failures to be from first CheckInputs
            if (!tx.HasWitness() && CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, false, txdata) &&
                !CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, false, txdata)) {
                // Only the witness is missing, so the transaction itself may be fine.
                state.SetCorruptionPossible();
            }
            return false; // state filled in by CheckInputs
        }

        // Check again against the current block tip's script verification
        // flags to cache our script execution flags. This is, of course,
        // useless if the next block has different script flags from the
        // previous one, but because the cache tracks script flags for us it
        // will auto-invalidate and we'll just have a few blocks of extra
        // misses on soft-fork activation.
        //
        // This is also useful in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks (using TestBlockValidity), however allowing such
        // transactions into the mempool can be exploited as a DoS attack.
        unsigned int currentBlockScriptVerifyFlags = GetBlockScriptFlags(chainActive.Tip(), chainparams.GetConsensus());
        if (!CheckInputsFromMempoolAndCache(tx, state, view, pool, currentBlockScriptVerifyFlags, true, txdata)) {
            return error("%s: BUG! PLEASE REPORT THIS! CheckInputs failed against latest-block but not STANDARD flags %s, %s",
                    __func__, hash.ToString(), FormatStateMessage(state));
        }

        if (test_accept) {
            // Tx was accepted, but not added
            return true;
        }

        // Remove conflicting transactions from the mempool
        for (CTxMemPool::txiter it : allConflicting)
        {
            LogPrint(BCLog::MEMPOOL, "replacing tx %s with %s for %s MOON additional fees, %d delta bytes\n",
                    it->GetTx().GetHash().ToString(),
                    hash.ToString(),
                    FormatMoney(nModifiedFees - nConflictingFees),
                    (int)nSize - (int)nConflictingSize);
            if (plTxnReplaced)
                plTxnReplaced->push_back(it->GetSharedTx());
        }
        pool.RemoveStaged(allConflicting, false, MemPoolRemovalReason::REPLACED);

        // This transaction should only count for fee estimation if:
        // - it isn't a BIP 125 replacement transaction (may not be widely supported)
        // - it's not being re-added during a reorg which bypasses typical mempool fee limits
        // - the node is not behind
        // - the transaction is not dependent on any other transactions in the mempool
        bool validForFeeEstimation = !fReplacementTransaction && !bypass_limits && IsCurrentForFeeEstimation() && pool.HasNoInputsOf(tx);

        // Store transaction in memory
        pool.addUnchecked(entry, setAncestors, validForFeeEstimation);

        // trim mempool and check if tx was trimmed
        if (!bypass_limits) {
            LimitMempoolSize(pool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
            if (!pool.exists(hash))
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
        }
    }

    GetMainSignals().TransactionAddedToMempool(ptx);

    return true;
}

/** (try to) add transaction to memory pool with a specified acceptance time **/
static bool AcceptToMemoryPoolWithTime(const CChainParams& chainparams, CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    std::vector<COutPoint> coins_to_uncache;
    bool res = AcceptToMemoryPoolWorker(chainparams, pool, state, tx, pfMissingInputs, nAcceptTime, plTxnReplaced, bypass_limits, nAbsurdFee, coins_to_uncache, test_accept);
    if (!res) {
        for (const COutPoint& hashTx : coins_to_uncache)
            pcoinsTip->Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    CValidationState stateDummy;
    FlushStateToDisk(chainparams, stateDummy, FlushStateMode::PERIODIC);
    return res;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept)
{
    const CChainParams& chainparams = Params();
    return AcceptToMemoryPoolWithTime(chainparams, pool, state, tx, pfMissingInputs, GetTime(), plTxnReplaced, bypass_limits, nAbsurdFee, test_accept);
}

/**
 * Return transaction in txOut, and if it was found inside a block, its hash is placed in hashBlock.
 * If blockIndex is provided, the transaction is fetched from the corresponding block.
 */
bool GetTransaction(const uint256& hash, CTransactionRef& txOut, const Consensus::Params& consensusParams, uint256& hashBlock, const CBlockIndex* const block_index)
{
    LOCK(cs_main);

    if (!block_index) {
        CTransactionRef ptx = mempool.get(hash);
        if (ptx) {
            txOut = ptx;
            return true;
        }

        if (g_txindex) {
            return g_txindex->FindTx(hash, hashBlock, txOut);
        }
    } else {
        CBlock block;
        if (ReadBlockFromDisk(block, block_index, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = block_index->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(block, fileout.GetVersion());
    fileout << messageStart << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (!CheckProofOfWork(block.GetPoWHash(), block.nBits, consensusParams))
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    CDiskBlockPos blockPos;
    {
        LOCK(cs_main);
        blockPos = pindex->GetBlockPos();
    }

    if (!ReadBlockFromDisk(block, blockPos, consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& message_start)
{
    CDiskBlockPos hpos = pos;
    hpos.nPos -= 8; // Seek back 8 bytes for meta header
    CAutoFile filein(OpenBlockFile(hpos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return error("%s: OpenBlockFile failed for %s", __func__, pos.ToString());
    }

    try {
        CMessageHeader::MessageStartChars blk_start;
        unsigned int blk_size;

        filein >> blk_start >> blk_size;

        if (memcmp(blk_start, message_start, CMessageHeader::MESSAGE_START_SIZE)) {
            return error("%s: Block magic mismatch for %s: %s versus expected %s", __func__, pos.ToString(),
                    HexStr(blk_start, blk_start + CMessageHeader::MESSAGE_START_SIZE),
                    HexStr(message_start, message_start + CMessageHeader::MESSAGE_START_SIZE));
        }

        if (blk_size > MAX_SIZE) {
            return error("%s: Block data is larger than maximum deserialization size for %s: %s versus %s", __func__, pos.ToString(),
                    blk_size, MAX_SIZE);
        }

        block.resize(blk_size); // Zeroing of memory is intentional here
        filein.read((char*)block.data(), blk_size);
    } catch(const std::exception& e) {
        return error("%s: Read from block file failed: %s for %s", __func__, e.what(), pos.ToString());
    }

    return true;
}

bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CBlockIndex* pindex, const CMessageHeader::MessageStartChars& message_start)
{
    CDiskBlockPos block_pos;
    {
        LOCK(cs_main);
        block_pos = pindex->GetBlockPos();
    }

    return ReadRawBlockFromDisk(block, block_pos, message_start);
}

namespace  {
const long hextable[] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 10-19
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 30-39
    -1, -1, -1, -1, -1, -1, -1, -1,  0,  1,
     2,  3,  4,  5,  6,  7,  8,  9, -1, -1,         // 50-59
    -1, -1, -1, -1, -1, 10, 11, 12, 13, 14,
    15, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 70-79
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, 10, 11, 12,         // 90-99
    13, 14, 15, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 110-109
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 130-139
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 150-159
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 170-179
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 190-199
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 210-219
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // 230-239
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1
};

long hex2long(const char* hexString)
{
    long ret = 0;

    while (*hexString && ret >= 0)
    {
        ret = (ret << 4) | hextable[(uint8_t)*hexString++];
    }

    return ret;
}

int static generateMTRandom(unsigned int s, int range)
{
    boost::mt19937 gen(s);
    boost::uniform_int<> dist(1, range);
    return dist(gen);
}
} // namespace


CAmount GetBlockSubsidy(const int nHeight, const uint256 prevHash)
{
    CAmount nSubsidy = 29531 * COIN; // the lunar cycle is 29.53059 days, so we rounded it up

    std::string cseed_str = prevHash.ToString().substr(7,7);
    const char* cseed = cseed_str.c_str();
    long seed = hex2long(cseed);

    // cases for block 1 - 384400
    if(nHeight <= 100000)
    {
        nSubsidy = (1 + generateMTRandom(seed, 1999999)) * COIN;
    }
    else if(nHeight > 193076 && nHeight < 203158)
    {
        nSubsidy = 2519841 * COIN; // for _roughly_ one week, the cost of the Apollo program will be paid back -- 25.4bn MOON!
    }
    else if(nHeight <= 203518)
    {
        nSubsidy = (1 + generateMTRandom(seed, 999999)) * COIN;
    }
    else if(nHeight <= 250000)
    {
        nSubsidy = (1 + generateMTRandom(seed, 599999)) * COIN;
    }
    else if(nHeight <= 300000)
    {
        nSubsidy = (1 + generateMTRandom(seed, 349999)) * COIN;
    }
    else if(nHeight <= 350000)
    {
        nSubsidy = (1 + generateMTRandom(seed, 174999)) * COIN;
    }
    else if(nHeight <= 375000)
    {
        nSubsidy = (1 + generateMTRandom(seed, 99999)) * COIN;
    }
    else if(nHeight <= 384400)
    {
        nSubsidy = (1 + generateMTRandom(seed, 49999)) * COIN;
    }

    // cases for block 384401 - 1099999
    if (nHeight % 29531 == 0)
    {
        // a prize for ever lunar cycle
        nSubsidy = nSubsidy * 2;
    }

    // cases for block 1100000+
    if (nHeight > 1099999)
    {
        nSubsidy = floor( 19697202017 / (floor(nHeight/100000)*100000) ) * COIN;
    }

    // case for block 5432100000 onwards
    if (nHeight > 5432099999)
    {
        nSubsidy = 0 * COIN;
    }

    return nSubsidy;
}

bool IsInitialBlockDownload()
{
    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (chainActive.Tip() == nullptr)
        return true;
    if (chainActive.Tip()->nChainWork < nMinimumChainWork)
        return true;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    latchToFalse.store(true, std::memory_order_relaxed);
    return false;
}

CBlockIndex *pindexBestForkTip = nullptr, *pindexBestForkBase = nullptr;

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
}

static void CheckForkWarningConditions() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && chainActive.Height() - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = nullptr;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > chainActive.Tip()->nChainWork + (GetBlockProof(*chainActive.Tip()) * 6)))
    {
        if (!GetfLargeWorkForkFound() && pindexBestForkBase)
        {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                pindexBestForkBase->phashBlock->ToString() + std::string("'");
            AlertNotify(warning);
        }
        if (pindexBestForkTip && pindexBestForkBase)
        {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                   pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                   pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            SetfLargeWorkForkFound(true);
        }
        else
        {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            SetfLargeWorkInvalidChainFound(true);
        }
    }
    else
    {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

static void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = chainActive.Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || pindexNewForkTip->nHeight > pindexBestForkTip->nHeight) &&
            pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
            chainActive.Height() - pindexNewForkTip->nHeight < 72)
    {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

void static InvalidChainFound(CBlockIndex* pindexNew) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), FormatISO8601DateTime(pindexNew->GetBlockTime()));
    CBlockIndex *tip = chainActive.Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      tip->GetBlockHash().ToString(), chainActive.Height(), log(tip->nChainWork.getdouble())/log(2.0),
      FormatISO8601DateTime(tip->GetBlockTime()));
    CheckForkWarningConditions();
}

void CChainState::InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state) {
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        m_failed_blocks.insert(pindex);
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin) {
            txundo.vprevout.emplace_back();
            bool is_spent = inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
            assert(is_spent);
        }
    }
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;
    return VerifyScript(scriptSig, m_tx_out.scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *txdata), &error);
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBlockIndex* pindexPrev = LookupBlockIndex(inputs.GetBestBlock());
    return pindexPrev->nHeight + 1;
}


static CuckooCache::cache<uint256, SignatureCacheHasher> scriptExecutionCache;
static uint256 scriptExecutionCacheNonce(GetRandHash());

void InitScriptExecutionCache() {
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, gArgs.GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) / 2), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = scriptExecutionCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu/2 requested for script execution cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, (nMaxCacheSize*2)>>20, nElems);
}

/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Non-static (and re-declared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!tx.IsCoinBase())
    {
        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip script verification when connecting blocks under the
        // assumevalid block. Assuming the assumevalid block is valid this
        // is safe because block merkle hashes are still computed and checked,
        // Of course, if an assumed valid block is invalid due to false scriptSigs
        // this optimization would allow an invalid chain to be accepted.
        if (fScriptChecks) {
            // First check if script executions have been cached with the same
            // flags. Note that this assumes that the inputs provided are
            // correct (ie that the transaction hash which is in tx's prevouts
            // properly commits to the scriptPubKey in the inputs view of that
            // transaction).
            uint256 hashCacheEntry;
            // We only use the first 19 bytes of nonce to avoid a second SHA
            // round - giving us 19 + 32 + 4 = 55 bytes (+ 8 + 1 = 64)
            static_assert(55 - sizeof(flags) - 32 >= 128/8, "Want at least 128 bits of nonce for script execution cache");
            CSHA256().Write(scriptExecutionCacheNonce.begin(), 55 - sizeof(flags) - 32).Write(tx.GetWitnessHash().begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
            AssertLockHeld(cs_main); //TODO: Remove this requirement by making CuckooCache not require external locks
            if (scriptExecutionCache.contains(hashCacheEntry, !cacheFullScriptStore)) {
                return true;
            }

            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint &prevout = tx.vin[i].prevout;
                const Coin& coin = inputs.AccessCoin(prevout);
                assert(!coin.IsSpent());

                // We very carefully only pass in things to CScriptCheck which
                // are clearly committed to by tx' witness hash. This provides
                // a sanity check that our caching is not introducing consensus
                // failures through additional data in, eg, the coins being
                // spent being checked as a part of CScriptCheck.

                // Verify signature
                CScriptCheck check(coin.out, tx, i, flags, cacheSigStore, &txdata);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(coin.out, tx, i,
                                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheSigStore, &txdata);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. an invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after soft-fork
                    // super-majority signaling has occurred.
                    return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                }
            }

            if (cacheFullScriptStore && !pvChecks) {
                // We executed all of the provided scripts, and were told to
                // cache the result. Do so now.
                scriptExecutionCache.insert(hashCacheEntry);
            }
        }
    }

    return true;
}

namespace {

bool UndoWriteToDisk(const CBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(blockundo, fileout.GetVersion());
    fileout << messageStart << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

static bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex *pindex)
{
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        return error("%s: no undo data available", __func__);
    }

    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << pindex->pprev->GetBlockHash();
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
static bool AbortNode(const std::string& strMessage, const std::string& userMessage="")
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

static bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage="")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

} // namespace

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // The potential_overwrite parameter to AddCoin is only allowed to be false if we know for
    // sure that the coin did not already exist in the cache. As we have queried for that above
    // using HaveCoin, we don't need to guess. When fClean is false, a coin already existed and
    // it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult CChainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view)
{
    bool fClean = true;

    CBlockUndo blockUndo;
    if (!UndoReadFromDisk(blockUndo, pindex)) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();
        bool is_coinbase = tx.IsCoinBase();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                bool is_spent = view.SpendCoin(out, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase) {
                    fClean = false; // transaction output mismatch
                }
            }
        }

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);
    bool status = true;

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            status &= TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        status &= FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            status &= TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        status &= FileCommit(fileOld);
        fclose(fileOld);
    }

    if (!status) {
        AbortNode("Flushing block file to disk failed. This is likely the result of an I/O error.");
    }
}

static bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

static bool WriteUndoDataForBlock(const CBlockUndo& blockundo, CValidationState& state, CBlockIndex* pindex, const CChainParams& chainparams)
{
    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull()) {
        CDiskBlockPos _pos;
        if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, CLIENT_VERSION) + 40))
            return error("ConnectBlock(): FindUndoPos failed");
        if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
            return AbortNode(state, "Failed to write undo data");

        // update nUndoPos in block index
        pindex->nUndoPos = _pos.nPos;
        pindex->nStatus |= BLOCK_HAVE_UNDO;
        setDirtyBlockIndex.insert(pindex);
    }

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("mooncoin-scriptch");
    scriptcheckqueue.Thread();
}

VersionBitsCache versionbitscache GUARDED_BY(cs_main);

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, static_cast<Consensus::DeploymentPos>(i), versionbitscache);
        if (state == ThresholdState::LOCKED_IN || state == ThresholdState::STARTED) {
            nVersion |= VersionBitsMask(params, static_cast<Consensus::DeploymentPos>(i));
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    explicit WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const override { return 0; }
    int64_t EndTime(const Consensus::Params& params) const override { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS] GUARDED_BY(cs_main);

static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& consensusparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);

    unsigned int flags = SCRIPT_VERIFY_NONE;
    
    // Start enforcing P2SH (BIP16)
    if (pindex->nHeight >= consensusparams.BIP16Height) {
        flags |= SCRIPT_VERIFY_P2SH;
    }

    // Start enforcing the DERSIG (BIP66) rule
    if (pindex->nHeight >= consensusparams.BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
    if (pindex->nHeight >= consensusparams.BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    if (VersionBitsState(pindex->pprev, consensusparams, Consensus::DEPLOYMENT_CSV, versionbitscache) == ThresholdState::ACTIVE) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Start enforcing WITNESS rules using versionbits logic.
    if (IsWitnessEnabled(pindex->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_WITNESS;
    }

    // Start enforcing NULLDUMMY rules using versionbits logic.
    if (IsNullDummyEnabled(pindex->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    return flags;
}



static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;
static int64_t nBlocksTotal = 0;

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool CChainState::ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    assert(pindex);
    assert(*pindex->phashBlock == block.GetHash());
    int64_t nTimeStart = GetTimeMicros();

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see RewindBlockIndex()
    // for one general approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // GetAdjustedTime() to go backward).
    if (!CheckBlock(block, state, chainparams.GetConsensus(), !fJustCheck, !fJustCheck)) {
        if (state.CorruptionPossible()) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return AbortNode(state, "Corrupt block found indicating potential hardware failure; shutting down");
        }
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    nBlocksTotal++;

    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator  it = mapBlockIndex.find(hashAssumeValid);
        if (it != mapBlockIndex.end()) {
            if (it->second->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->nChainWork >= nMinimumChainWork) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // The equivalent time check discourages hash power from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (GetBlockProofEquivalentTime(*pindexBestHeader, *pindex, *pindexBestHeader, chainparams.GetConsensus()) <= 60 * 60 * 24 * 7 * 2);
            }
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime1 - nTimeStart), nTimeCheck * MICRO, nTimeCheck * MILLI / nBlocksTotal);

    assert(pindex->pprev);

    for (const auto& tx : block.vtx) {
        for (size_t o = 0; o < tx->vout.size(); o++) {
            if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"),
                                 REJECT_INVALID, "bad-txns-BIP30");
            }
        }
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindex->pprev, chainparams.GetConsensus(), Consensus::DEPLOYMENT_CSV, versionbitscache) == ThresholdState::ACTIVE) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Get the script flags for this block
    unsigned int flags = GetBlockScriptFlags(pindex, chainparams.GetConsensus());

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime2 - nTime1), nTimeForks * MICRO, nTimeForks * MILLI / nBlocksTotal);

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : nullptr);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        if (!tx.IsCoinBase())
        {
            CAmount txfee = 0;
            if (!Consensus::CheckTxInputs(tx, state, view, pindex->nHeight, txfee)) {
                return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));
            }
            nFees += txfee;
            if (!MoneyRange(nFees)) {
                return state.DoS(100, error("%s: accumulated fee in the block out of range.", __func__),
                                 REJECT_INVALID, "bad-txns-accumulated-fee-outofrange");
            }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) {
                return state.DoS(100, error("%s: contains a non-BIP68-final transaction", __func__),
                                 REJECT_INVALID, "bad-txns-nonfinal");
            }
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST)
            return state.DoS(100, error("ConnectBlock(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        txdata.emplace_back(tx);
        if (!tx.IsCoinBase())
        {
            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            if (!CheckInputs(tx, state, view, fScriptChecks, flags, fCacheResults, fCacheResults, txdata[i], nScriptCheckThreads ? &vChecks : nullptr))
                return error("ConnectBlock(): CheckInputs on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);
    }
    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

    uint256 prevHash;
    if(pindex->pprev)
    {
        prevHash = pindex->pprev->GetBlockHash();
    }
    CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, prevHash);
    if (block.vtx[0]->GetValueOut() > blockReward)
        return state.DoS(100,
                         error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                               block.vtx[0]->GetValueOut(), blockReward),
                               REJECT_INVALID, "bad-cb-amount");

    if (!control.Wait())
        return state.DoS(100, error("%s: CheckQueue failed", __func__), REJECT_INVALID, "block-validation-failed");
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n", nInputs - 1, MILLI * (nTime4 - nTime2), nInputs <= 1 ? 0 : MILLI * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * MICRO, nTimeVerify * MILLI / nBlocksTotal);

    if (fJustCheck)
        return true;

    if (!WriteUndoDataForBlock(blockundo, state, pindex, chainparams))
        return false;

    if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    assert(pindex->phashBlock);
    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime5 - nTime4), nTimeIndex * MICRO, nTimeIndex * MILLI / nBlocksTotal);

    int64_t nTime6 = GetTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    LogPrint(BCLog::BENCH, "    - Callbacks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime6 - nTime5), nTimeCallbacks * MICRO, nTimeCallbacks * MILLI / nBlocksTotal);

    return true;
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 *
 * If FlushStateMode::NONE is used, then FlushStateToDisk(...) won't do anything
 * besides checking if we need to prune.
 */
bool static FlushStateToDisk(const CChainParams& chainparams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight) {
    int64_t nMempoolUsage = mempool.DynamicMemoryUsage();
    LOCK(cs_main);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    std::set<int> setFilesToPrune;
    bool full_flush_completed = false;
    try {
    {
        bool fFlushForPrune = false;
        bool fDoFullFlush = false;
        LOCK(cs_LastBlockFile);
        if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
            if (nManualPruneHeight > 0) {
                FindFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
            } else {
                FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
                fCheckForPruning = false;
            }
            if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!fHavePruned) {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        int64_t nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0) {
            nLastFlush = nNow;
        }
        int64_t nMempoolSizeMax = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
        int64_t cacheSize = pcoinsTip->DynamicMemoryUsage();
        int64_t nTotalSpace = nCoinCacheUsage + std::max<int64_t>(nMempoolSizeMax - nMempoolUsage, 0);
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FlushStateMode::PERIODIC && cacheSize > std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE * 1024 * 1024);
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FlushStateMode::IF_NEEDED && cacheSize > nTotalSpace;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FlushStateMode::PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FlushStateMode::PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        fDoFullFlush = (mode == FlushStateMode::ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(0, true))
                return state.Error("out of disk space");
            // First make sure all block and undo data is flushed to disk.
            FlushBlockFile();
            // Then update all block file information (which may refer to block and undo files).
            {
                std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Failed to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune)
                UnlinkPrunedFiles(setFilesToPrune);
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush && !pcoinsTip->GetBestBlock().IsNull()) {
            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->GetCacheSize()))
                return state.Error("out of disk space");
            // Flush the chainstate (which may refer to block index entries).
            if (!pcoinsTip->Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
            full_flush_completed = true;
        }
    }
    if (full_flush_completed) {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().ChainStateFlushed(chainActive.GetLocator());
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk() {
    CValidationState state;
    const CChainParams& chainparams = Params();
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::ALWAYS)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, FormatStateMessage(state));
    }
}

void PruneAndFlush() {
    CValidationState state;
    fCheckForPruning = true;
    const CChainParams& chainparams = Params();
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::NONE)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, FormatStateMessage(state));
    }
}

static void DoWarning(const std::string& strWarning)
{
    static bool fWarned = false;
    SetMiscWarning(strWarning);
    if (!fWarned) {
        AlertNotify(strWarning);
        fWarned = true;
    }
}

/** Private helper function that concatenates warning messages. */
static void AppendWarning(std::string& res, const std::string& warn)
{
    if (!res.empty()) res += ", ";
    res += warn;
}

/** Check warning conditions and do some notifications on new chain tip set. */
void static UpdateTip(const CBlockIndex *pindexNew, const CChainParams& chainParams) {
    // New best block
    mempool.AddTransactionsUpdated(1);

    {
        LOCK(g_best_block_mutex);
        g_best_block = pindexNew->GetBlockHash();
        g_best_block_cv.notify_all();
    }

    std::string warningMessages;
    if (!IsInitialBlockDownload())
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexNew;
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(), warningcache[bit]);
            if (state == ThresholdState::ACTIVE || state == ThresholdState::LOCKED_IN) {
                const std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                if (state == ThresholdState::ACTIVE) {
                    DoWarning(strWarning);
                } else {
                    AppendWarning(warningMessages, strWarning);
                }
            }
        }
        // Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != nullptr; i++)
        {
            int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            AppendWarning(warningMessages, strprintf(_("%d of last 100 blocks have unexpected version"), nUpgraded));
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)", __func__, /* Continued */
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, pindexNew->nVersion,
      log(pindexNew->nChainWork.getdouble())/log(2.0), (unsigned long)pindexNew->nChainTx,
      FormatISO8601DateTime(pindexNew->GetBlockTime()),
      GuessVerificationProgress(chainParams.TxData(), pindexNew), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->GetCacheSize());
    if (!warningMessages.empty())
        LogPrintf(" warning='%s'", warningMessages); /* Continued */
    LogPrintf("\n");

}

/** Disconnect chainActive's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling UpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool CChainState::DisconnectTip(CValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool)
{
    CBlockIndex *pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()))
        return AbortNode(state, "Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(pcoinsTip.get());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
    }
    LogPrint(BCLog::BENCH, "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * MILLI);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED))
        return false;

    if (disconnectpool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }
        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    chainActive.SetTip(pindexDelete->pprev);

    UpdateTip(pindexDelete->pprev, chainparams);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    GetMainSignals().BlockDisconnected(pblock);
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

struct PerBlockConnectTrace {
    CBlockIndex* pindex = nullptr;
    std::shared_ptr<const CBlock> pblock;
    std::shared_ptr<std::vector<CTransactionRef>> conflictedTxs;
    PerBlockConnectTrace() : conflictedTxs(std::make_shared<std::vector<CTransactionRef>>()) {}
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class also tracks transactions that are removed from the mempool as
 * conflicts (per block) and can be used to pass all those transactions
 * through SyncTransaction.
 *
 * This class assumes (and asserts) that the conflicted transactions for a given
 * block are added via mempool callbacks prior to the BlockConnected() associated
 * with those transactions. If any transactions are marked conflicted, it is
 * assumed that an associated block will always be added.
 *
 * This class is single-use, once you call GetBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;
    CTxMemPool &pool;
    boost::signals2::scoped_connection m_connNotifyEntryRemoved;

public:
    explicit ConnectTrace(CTxMemPool &_pool) : blocksConnected(1), pool(_pool) {
        m_connNotifyEntryRemoved = pool.NotifyEntryRemoved.connect(std::bind(&ConnectTrace::NotifyEntryRemoved, this, std::placeholders::_1, std::placeholders::_2));
    }

    void BlockConnected(CBlockIndex* pindex, std::shared_ptr<const CBlock> pblock) {
        assert(!blocksConnected.back().pindex);
        assert(pindex);
        assert(pblock);
        blocksConnected.back().pindex = pindex;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& GetBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pindex);
        assert(blocksConnected.back().conflictedTxs->empty());
        blocksConnected.pop_back();
        return blocksConnected;
    }

    void NotifyEntryRemoved(CTransactionRef txRemoved, MemPoolRemovalReason reason) {
        assert(!blocksConnected.back().pindex);
        if (reason == MemPoolRemovalReason::CONFLICT) {
            blocksConnected.back().conflictedTxs->emplace_back(std::move(txRemoved));
        }
    }
};

/**
 * Connect a new block to chainActive. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool CChainState::ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool)
{
    assert(pindexNew->pprev == chainActive.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "Failed to read block");
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }
    const CBlock& blockConnecting = *pthisBlock;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(BCLog::BENCH, "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * MILLI, nTimeReadFromDisk * MICRO);
    {
        CCoinsViewCache view(pcoinsTip.get());
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view, chainparams);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);
            return error("%s: ConnectBlock %s failed, %s", __func__, pindexNew->GetBlockHash().ToString(), FormatStateMessage(state));
        }
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime3 - nTime2) * MILLI, nTimeConnectTotal * MICRO, nTimeConnectTotal * MILLI / nBlocksTotal);
        bool flushed = view.Flush();
        assert(flushed);
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCH, "  - Flush: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime4 - nTime3) * MILLI, nTimeFlush * MICRO, nTimeFlush * MILLI / nBlocksTotal);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "  - Writing chainstate: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime5 - nTime4) * MILLI, nTimeChainState * MICRO, nTimeChainState * MILLI / nBlocksTotal);
    // Remove conflicting transactions from the mempool.;
    mempool.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
    disconnectpool.removeForBlock(blockConnecting.vtx);
    // Update chainActive & related variables.
    chainActive.SetTip(pindexNew);
    UpdateTip(pindexNew, chainparams);

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCH, "  - Connect postprocess: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime5) * MILLI, nTimePostConnect * MICRO, nTimePostConnect * MILLI / nBlocksTotal);
    LogPrint(BCLog::BENCH, "- Connect block: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime1) * MILLI, nTimeTotal * MICRO, nTimeTotal * MILLI / nBlocksTotal);

    connectTrace.BlockConnected(pindexNew, std::move(pthisBlock));
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex* CChainState::FindMostWorkChain() {
    do {
        CBlockIndex *pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !chainActive.Contains(pindexTest)) {
            assert(pindexTest->HaveTxsDownloaded() || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == nullptr || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void CChainState::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 */
bool CChainState::ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);

    const CBlockIndex *pindexOldTip = chainActive.Tip();
    const CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex *pindexConnect : reverse_iterate(vpindexToConnect)) {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible()) {
                        InvalidChainFound(vpindexToConnect.front());
                    }
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    UpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || chainActive.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        UpdateMempoolForReorg(disconnectpool, true);
    }
    mempool.check(pcoinsTip.get());

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static void NotifyHeaderTip() LOCKS_EXCLUDED(cs_main) {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = nullptr;
    CBlockIndex* pindexHeader = nullptr;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
    }
}

static void LimitValidationInterfaceQueue() {
    AssertLockNotHeld(cs_main);

    if (GetMainSignals().CallbacksPending() > 10) {
        SyncWithValidationInterfaceQueue();
    }
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either nullptr or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 *
 * ActivateBestChain is split into steps (see ActivateBestChainStep) so that
 * we avoid holding cs_main for an extended period of time; the length of this
 * call may be quite long during reindexing or a substantial reorg.
 */
bool CChainState::ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(cs_main);

    // ABC maintains a fair degree of expensive-to-calculate internal state
    // because this function periodically releases cs_main so that it does not lock up other threads for too long
    // during large connects - and to allow for e.g. the callback queue to drain
    // we use m_cs_chainstate to enforce mutual exclusion so that only one caller may execute this function at a time
    LOCK(m_cs_chainstate);

    CBlockIndex *pindexMostWork = nullptr;
    CBlockIndex *pindexNewTip = nullptr;
    int nStopAtHeight = gArgs.GetArg("-stopatheight", DEFAULT_STOPATHEIGHT);
    do {
        boost::this_thread::interruption_point();

        // Block until the validation queue drains. This should largely
        // never happen in normal operation, however may happen during
        // reindex, causing memory blowup if we run too far ahead.
        // Note that if a validationinterface callback ends up calling
        // ActivateBestChain this may lead to a deadlock! We should
        // probably have a DEBUG_LOCKORDER test for this in the future.
        LimitValidationInterfaceQueue();

        {
            LOCK(cs_main);
            CBlockIndex* starting_tip = chainActive.Tip();
            bool blocks_connected = false;
            do {
                // We absolutely may not unlock cs_main until we've made forward progress
                // (with the exception of shutdown due to hardware issues, low disk space, etc).
                ConnectTrace connectTrace(mempool); // Destructed before cs_main is unlocked

                if (pindexMostWork == nullptr) {
                    pindexMostWork = FindMostWorkChain();
                }

                // Whether we have anything to do at all.
                if (pindexMostWork == nullptr || pindexMostWork == chainActive.Tip()) {
                    break;
                }

                bool fInvalidFound = false;
                std::shared_ptr<const CBlock> nullBlockPtr;
                if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace))
                    return false;
                blocks_connected = true;

                if (fInvalidFound) {
                    // Wipe cache, we may need another branch now.
                    pindexMostWork = nullptr;
                }
                pindexNewTip = chainActive.Tip();

                for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                    assert(trace.pblock && trace.pindex);
                    GetMainSignals().BlockConnected(trace.pblock, trace.pindex, trace.conflictedTxs);
                }
            } while (!chainActive.Tip() || (starting_tip && CBlockIndexWorkComparator()(chainActive.Tip(), starting_tip)));
            if (!blocks_connected) return true;

            const CBlockIndex* pindexFork = chainActive.FindFork(starting_tip);
            bool fInitialDownload = IsInitialBlockDownload();

            // Notify external listeners about the new tip.
            // Enqueue while holding cs_main to ensure that UpdatedBlockTip is called in the order in which blocks are connected
            if (pindexFork != pindexNewTip) {
                // Notify ValidationInterface subscribers
                GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

                // Always notify the UI if a new block tip was connected
                uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        if (nStopAtHeight && pindexNewTip && pindexNewTip->nHeight >= nStopAtHeight) StartShutdown();

        // We check shutdown only after giving ActivateBestChainStep a chance to run once so that we
        // never shutdown before connecting the genesis block during LoadChainTip(). Previously this
        // caused an assert() failure during shutdown in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (ShutdownRequested())
            break;
    } while (pindexNewTip != pindexMostWork);
    CheckBlockIndex(chainparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::PERIODIC)) {
        return false;
    }

    return true;
}

bool ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    return g_chainstate.ActivateBestChain(state, chainparams, std::move(pblock));
}

bool CChainState::PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex)
{
    {
        LOCK(cs_main);
        if (pindex->nChainWork < chainActive.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        }
        if (chainActive.Tip()->nChainWork > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        }
        nLastPreciousChainwork = chainActive.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->HaveTxsDownloaded()) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, params, std::shared_ptr<const CBlock>());
}
bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex) {
    return g_chainstate.PreciousBlock(state, params, pindex);
}

bool CChainState::InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex)
{
    CBlockIndex* to_mark_failed = pindex;
    bool pindex_was_in_chain = false;
    int disconnected = 0;

    // Disconnect (descendants of) pindex, and mark them invalid.
    while (true) {
        if (ShutdownRequested()) break;

        // Make sure the queue of validation callbacks doesn't grow unboundedly.
        LimitValidationInterfaceQueue();

        LOCK(cs_main);
        if (!chainActive.Contains(pindex)) break;
        pindex_was_in_chain = true;
        CBlockIndex *invalid_walk_tip = chainActive.Tip();

        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        DisconnectedBlockTransactions disconnectpool;
        bool ret = DisconnectTip(state, chainparams, &disconnectpool);
        // DisconnectTip will add transactions to disconnectpool.
        // Adjust the mempool to be consistent with the new tip, adding
        // transactions back to the mempool if disconnecting was succesful,
        // and we're not doing a very deep invalidation (in which case
        // keeping the mempool up to date is probably futile anyway).
        UpdateMempoolForReorg(disconnectpool, /* fAddToMempool = */ (++disconnected <= 10) && ret);
        if (!ret) return false;
        assert(invalid_walk_tip->pprev == chainActive.Tip());

        // We immediately mark the disconnected blocks as invalid.
        // This prevents a case where pruned nodes may fail to invalidateblock
        // and be left unable to start as they have no tip candidates (as there
        // are no blocks that meet the "have data and are not invalid per
        // nStatus" criteria for inclusion in setBlockIndexCandidates).
        invalid_walk_tip->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(invalid_walk_tip);
        setBlockIndexCandidates.erase(invalid_walk_tip);
        setBlockIndexCandidates.insert(invalid_walk_tip->pprev);
        if (invalid_walk_tip->pprev == to_mark_failed && (to_mark_failed->nStatus & BLOCK_FAILED_VALID)) {
            // We only want to mark the last disconnected block as BLOCK_FAILED_VALID; its children
            // need to be BLOCK_FAILED_CHILD instead.
            to_mark_failed->nStatus = (to_mark_failed->nStatus ^ BLOCK_FAILED_VALID) | BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(to_mark_failed);
        }

        // Track the last disconnected block, so we can correct its BLOCK_FAILED_CHILD status in future
        // iterations, or, if it's the last one, call InvalidChainFound on it.
        to_mark_failed = invalid_walk_tip;
    }

    {
        LOCK(cs_main);
        if (chainActive.Contains(to_mark_failed)) {
            // If the to-be-marked invalid block is in the active chain, something is interfering and we can't proceed.
            return false;
        }

        // Mark pindex (or the last disconnected block) as invalid, even when it never was in the main chain
        to_mark_failed->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(to_mark_failed);
        setBlockIndexCandidates.erase(to_mark_failed);
        m_failed_blocks.insert(to_mark_failed);

        // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
        // add it again.
        BlockMap::iterator it = mapBlockIndex.begin();
        while (it != mapBlockIndex.end()) {
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->HaveTxsDownloaded() && !setBlockIndexCandidates.value_comp()(it->second, chainActive.Tip())) {
                setBlockIndexCandidates.insert(it->second);
            }
            it++;
        }

        InvalidChainFound(to_mark_failed);
    }

    // Only notify about a new block tip if the active chain was modified.
    if (pindex_was_in_chain) {
        uiInterface.NotifyBlockTip(IsInitialBlockDownload(), to_mark_failed->pprev);
    }
    return true;
}

bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex) {
    return g_chainstate.InvalidateBlock(state, chainparams, pindex);
}

void CChainState::ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->HaveTxsDownloaded() && setBlockIndexCandidates.value_comp()(chainActive.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = nullptr;
            }
            m_failed_blocks.erase(it->second);
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
            m_failed_blocks.erase(pindex);
        }
        pindex = pindex->pprev;
    }
}

void ResetBlockFailureFlags(CBlockIndex *pindex) {
    return g_chainstate.ResetBlockFailureFlags(pindex);
}

CBlockIndex* CChainState::AddToBlockIndex(const CBlockHeader& block)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nTimeMax = (pindexNew->pprev ? std::max(pindexNew->pprev->nTimeMax, pindexNew->nTime) : pindexNew->nTime);
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == nullptr || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
void CChainState::ReceivedBlockTransactions(const CBlock& block, CBlockIndex* pindexNew, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (IsWitnessEnabled(pindexNew->pprev, consensusParams)) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->HaveTxsDownloaded()) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (chainActive.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, chainActive.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }
}

static bool FindBlockPos(CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos, true)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

static bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos, true)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

static bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetPoWHash(), block.nBits, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    return true;
}

bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    for (const auto& tx : block.vtx)
        if (!CheckTransaction(*tx, state, true))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    return (VersionBitsState(pindexPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == ThresholdState::ACTIVE);
}

bool IsNullDummyEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    return (VersionBitsState(pindexPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == ThresholdState::ACTIVE);
}

// Compute at which vout of the block's coinbase transaction the witness
// commitment occurs, or -1 if not found.
static int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            if (block.vtx[0]->vout[o].scriptPubKey.size() >= 38 && block.vtx[0]->vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0]->vout[o].scriptPubKey[1] == 0x24 && block.vtx[0]->vout[o].scriptPubKey[2] == 0xaa && block.vtx[0]->vout[o].scriptPubKey[3] == 0x21 && block.vtx[0]->vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0]->vout[o].scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}

void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pindexPrev, consensusParams) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        if (commitpos == -1) {
            uint256 witnessroot = BlockWitnessMerkleRoot(block, nullptr);
            CHash256().Write(witnessroot.begin(), 32).Write(ret.data(), 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            CMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(out);
            block.vtx[0] = MakeTransactionRef(std::move(tx));
        }
    }
    UpdateUncommittedBlockStructures(block, pindexPrev, consensusParams);
    return commitment;
}

// this function is required for the fix in 'ContextualCheckBlockHeader'
double ConvertBitsToDouble(unsigned int nBits)
{
    int nShift = (nBits >> 24) & 0xff;
    double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);
    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }
    return dDiff;
}

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 *  NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& params, const CBlockIndex* pindexPrev, int64_t nAdjustedTime)
{
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work
    const Consensus::Params& consensusParams = params.GetConsensus();
    if(nHeight >= consensusParams.nPoWForkOne && nHeight < consensusParams.nPoWForkTwo){
        unsigned int nBitsNext = GetNextWorkRequired(pindexPrev, &block, consensusParams);
        double n1 = ConvertBitsToDouble(block.nBits);
        double n2 = ConvertBitsToDouble(nBitsNext);
        if (std::abs(n1-n2) > n1*0.5){
            return state.DoS(100, error("%s : incorrect proof of work (DGW pre-fork) - %f %f %f at %d", __func__, abs(n1-n2), n1, n2, nHeight),
                                                REJECT_INVALID, "bad-diffbits");
        }
    } else if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams)){
        return state.DoS(100, error("%s : incorrect proof of work at %d", __func__, nHeight),
                                            REJECT_INVALID, "bad-diffbits");
    }

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // MapBlockIndex.
        CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(params.Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight)
            return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight), REJECT_CHECKPOINT, "bad-fork-prior-to-checkpoint");
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.GetBlockTime() > nAdjustedTime + MAX_FUTURE_BLOCK_TIME)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if((block.nVersion < 2 && nHeight >= consensusParams.BIP34Height) ||
       (block.nVersion < 3 && nHeight >= consensusParams.BIP66Height) ||
       (block.nVersion < 4 && nHeight >= consensusParams.BIP65Height))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    if (block.nVersion < VERSIONBITS_TOP_BITS && IsWitnessEnabled(pindexPrev, consensusParams))
        return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    return true;
}

/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_CSV, versionbitscache) == ThresholdState::ACTIVE) {
        assert(pindexPrev != nullptr);
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? pindexPrev->GetMedianTimePast()
                              : block.GetBlockTime();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (nHeight >= consensusParams.BIP34Height)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness reserved value (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness reserved value). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == ThresholdState::ACTIVE) {
        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != -1) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-nonce-size", true, strprintf("%s : invalid witness reserved value size", __func__));
            }
            CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0]->vin[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-merkle-match", true, strprintf("%s : witness merkle commitment mismatch", __func__));
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
      for (const auto& tx : block.vtx) {
            if (tx->HasWitness()) {
                return state.DoS(100, false, REJECT_INVALID, "unexpected-witness", true, strprintf("%s : unexpected witness data found", __func__));
            }
        }
    }

    // After the coinbase witness reserved value and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-weight", false, strprintf("%s : weight limit failed", __func__));
    }

    return true;
}

bool CChainState::AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf = mapBlockIndex.find(hash);
    CBlockIndex *pindex = nullptr;
    if (hash != chainparams.GetConsensus().hashGenesisBlock) {
        if (miSelf != mapBlockIndex.end()) {
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(error("%s: block %s is marked invalid", __func__, hash.ToString()), 0, "duplicate");
            return true;
        }

        if (!CheckBlockHeader(block, state, chainparams.GetConsensus()))
            return error("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "prev-blk-not-found");
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");
        if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        /* Determine if this block descends from any block which has been found
         * invalid (m_failed_blocks), then mark pindexPrev and any blocks between
         * them as failed. For example:
         *
         *                D3
         *              /
         *      B2 - C2
         *    /         \
         *  A             D2 - E2 - F2
         *    \
         *      B1 - C1 - D1 - E1
         *
         * In the case that we attempted to reorg from E1 to F2, only to find
         * C2 to be invalid, we would mark D2, E2, and F2 as BLOCK_FAILED_CHILD
         * but NOT D3 (it was not in any of our candidate sets at the time).
         *
         * In any case D3 will also be marked as BLOCK_FAILED_CHILD at restart
         * in LoadBlockIndex.
         */
        if (!pindexPrev->IsValid(BLOCK_VALID_SCRIPTS)) {
            // The above does not mean "invalid": it checks if the previous block
            // hasn't been validated up to BLOCK_VALID_SCRIPTS. This is a performance
            // optimization, in the common case of adding a new block to the tip,
            // we don't need to iterate over the failed blocks list.
            for (const CBlockIndex* failedit : m_failed_blocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    assert(failedit->nStatus & BLOCK_FAILED_VALID);
                    CBlockIndex* invalid_walk = pindexPrev;
                    while (invalid_walk != failedit) {
                        invalid_walk->nStatus |= BLOCK_FAILED_CHILD;
                        setDirtyBlockIndex.insert(invalid_walk);
                        invalid_walk = invalid_walk->pprev;
                    }
                    return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");
                }
            }
        }
    }
    if (pindex == nullptr)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, CValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex, CBlockHeader *first_invalid)
{
    if (first_invalid != nullptr) first_invalid->SetNull();
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            CBlockIndex *pindex = nullptr; // Use a temp pindex instead of ppindex to avoid a const_cast
            if (!g_chainstate.AcceptBlockHeader(header, state, chainparams, &pindex)) {
                if (first_invalid) *first_invalid = header;
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }
    NotifyHeaderTip();
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
static CDiskBlockPos SaveBlockToDisk(const CBlock& block, int nHeight, const CChainParams& chainparams, const CDiskBlockPos* dbp) {
    unsigned int nBlockSize = ::GetSerializeSize(block, CLIENT_VERSION);
    CDiskBlockPos blockPos;
    if (dbp != nullptr)
        blockPos = *dbp;
    if (!FindBlockPos(blockPos, nBlockSize+8, nHeight, block.GetBlockTime(), dbp != nullptr)) {
        error("%s: FindBlockPos failed", __func__);
        return CDiskBlockPos();
    }
    if (dbp == nullptr) {
        if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart())) {
            AbortNode("Failed to write block");
            return CDiskBlockPos();
        }
    }
    return blockPos;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool CChainState::AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDummy = nullptr;
    CBlockIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    if (!AcceptBlockHeader(block, state, chainparams, &pindex))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreOrSameWork = (chainActive.Tip() ? pindex->nChainWork >= chainActive.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;    // This is a previously-processed block that was pruned
        if (!fHasMoreOrSameWork) return true; // Don't process less-work chains
        if (fTooFarAhead) return true;        // Block height is too high

        // Protect against DoS attacks from low-work chains.
        // If our tip is behind, a peer could try to send us
        // low-work blocks on a fake chain that we would never
        // request; don't process these.
        if (pindex->nChainWork < nMinimumChainWork) return true;
    }

    if (!CheckBlock(block, state, chainparams.GetConsensus()) ||
        !ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindex->pprev)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return error("%s: %s", __func__, FormatStateMessage(state));
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!IsInitialBlockDownload() && chainActive.Tip() == pindex->pprev)
        GetMainSignals().NewPoWValidBlock(pindex, pblock);

    // Write block to history file
    if (fNewBlock) *fNewBlock = true;
    try {
        CDiskBlockPos blockPos = SaveBlockToDisk(block, pindex->nHeight, chainparams, dbp);
        if (blockPos.IsNull()) {
            state.Error(strprintf("%s: Failed to find position to write new block to disk", __func__));
            return false;
        }
        ReceivedBlockTransactions(block, pindex, blockPos, chainparams.GetConsensus());
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    FlushStateToDisk(chainparams, state, FlushStateMode::NONE);

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool *fNewBlock)
{
    AssertLockNotHeld(cs_main);

    {
        CBlockIndex *pindex = nullptr;
        if (fNewBlock) *fNewBlock = false;
        CValidationState state;

        // CheckBlock() does not support multi-threaded block validation because CBlock::fChecked can cause data race.
        // Therefore, the following critical section must include the CheckBlock() call as well.
        LOCK(cs_main);

        // Ensure that CheckBlock() passes before calling AcceptBlock, as
        // belt-and-suspenders.
        bool ret = CheckBlock(*pblock, state, chainparams.GetConsensus());
        if (ret) {
            // Store to disk
            ret = g_chainstate.AcceptBlock(pblock, state, chainparams, &pindex, fForceProcessing, nullptr, fNewBlock);
        }
        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED (%s)", __func__, FormatStateMessage(state));
        }
    }

    NotifyHeaderTip();

    CValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!g_chainstate.ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed (%s)", __func__, FormatStateMessage(state));

    return true;
}

bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainActive.Tip());
    CCoinsViewCache viewNew(pcoinsTip.get());
    uint256 block_hash(block.GetHash());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;
    indexDummy.phashBlock = &block_hash;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, FormatStateMessage(state));
    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));
    if (!g_chainstate.ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true))
        return false;
    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    LOCK(cs_LastBlockFile);

    uint64_t retval = 0;
    for (const CBlockFileInfo &file : vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    LOCK(cs_LastBlockFile);

    for (const auto& entry : mapBlockIndex) {
        CBlockIndex* pindex = entry.second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator _it = range.first;
                range.first++;
                if (_it->second == pindex) {
                    mapBlocksUnlinked.erase(_it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBlockPos pos(*it, 0);
        fs::remove(GetBlockPosFilename(pos, "blk"));
        fs::remove(GetBlockPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight)
{
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP);
    int count=0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(int nManualPruneHeight)
{
    CValidationState state;
    const CChainParams& chainparams = Params();
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::NONE, nManualPruneHeight)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, FormatStateMessage(state));
    }
}

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)chainActive.Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        // On a prune event, the chainstate DB is flushed.
        // To avoid excessive prune events negating the benefit of high dbcache
        // values, we should not prune too rapidly.
        // So when pruning in IBD, increase the buffer a bit to avoid a re-prune too soon.
        if (IsInitialBlockDownload()) {
            // Since this is only relevant during IBD, we use a fixed 10%
            nBuffer += nPruneTarget / 10;
        }

        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint(BCLog::PRUNE, "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
           nLastBlockWeCanPrune, count);
}

bool CheckDiskSpace(uint64_t nAdditionalBytes, bool blocks_dir)
{
    uint64_t nFreeBytesAvailable = fs::space(blocks_dir ? GetBlocksDir() : GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

static FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return nullptr;
    fs::path path = GetBlockPosFilename(pos, prefix);
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, fReadOnly ? "rb": "rb+");
    if (!file && !fReadOnly)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return nullptr;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

/** Open an undo file (rev?????.dat) */
static FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetBlocksDir() / strprintf("%s%05u.dat", prefix, pos.nFile);
}

CBlockIndex * CChainState::InsertBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);

    if (hash.IsNull())
        return nullptr;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CChainState::LoadBlockIndex(const Consensus::Params& consensus_params, CBlockTreeDB& blocktree)
{
    if (!blocktree.LoadBlockIndexGuts(consensus_params, [this](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return this->InsertBlockIndex(hash); }))
        return false;

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const std::pair<int, CBlockIndex*>& item : vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        pindex->nTimeMax = (pindex->pprev ? std::max(pindex->pprev->nTimeMax, pindex->nTime) : pindex->nTime);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->HaveTxsDownloaded()) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                } else {
                    pindex->nChainTx = 0;
                    mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nChainTx = pindex->nTx;
            }
        }
        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev && (pindex->pprev->nStatus & BLOCK_FAILED_MASK)) {
            pindex->nStatus |= BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(pindex);
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->HaveTxsDownloaded() || pindex->pprev == nullptr))
            setBlockIndexCandidates.insert(pindex);
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == nullptr || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    return true;
}

bool static LoadBlockIndexDB(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!g_chainstate.LoadBlockIndex(chainparams.GetConsensus(), *pblocktree))
        return false;

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    if(fReindexing) fReindex = true;

    return true;
}

bool LoadChainTip(const CChainParams& chainparams)
{
    AssertLockHeld(cs_main);

    if (chainActive.Tip() && chainActive.Tip()->GetBlockHash() == pcoinsTip->GetBestBlock()) return true;

    if (pcoinsTip->GetBestBlock().IsNull() && mapBlockIndex.size() == 1) {
        // In case we just added the genesis block, connect it now, so
        // that we always have a chainActive.Tip() when we return.
        LogPrintf("%s: Connecting genesis block...\n", __func__);
        CValidationState state;
        if (!ActivateBestChain(state, chainparams)) {
            LogPrintf("%s: failed to activate chain (%s)\n", __func__, FormatStateMessage(state));
            return false;
        }
    }

    // Load pointer to end of best chain
    CBlockIndex* pindex = LookupBlockIndex(pcoinsTip->GetBestBlock());
    if (!pindex) {
        return false;
    }
    chainActive.SetTip(pindex);

    g_chainstate.PruneBlockIndexCandidates();

    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
        chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(),
        FormatISO8601DateTime(chainActive.Tip()->GetBlockTime()),
        GuessVerificationProgress(chainparams.TxData(), chainActive.Tip()));
    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks..."), 0, false);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100, false);
}

bool CVerifyDB::VerifyDB(const CChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindex;
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    CValidationState state;
    int reportDone = 0;
    LogPrintf("[0%%]..."); /* Continued */
    for (pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        boost::this_thread::interruption_point();
        const int percentageDone = std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone); /* Continued */
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_("Verifying blocks..."), percentageDone, false);
        if (pindex->nHeight <= chainActive.Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, chainparams.GetConsensus()))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!UndoReadFromDisk(undo, pindex)) {
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            assert(coins.GetBestBlock() == pindex->GetBlockHash());
            DisconnectResult res = g_chainstate.DisconnectBlock(block, pindex, coins);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // store block count as we move pindex at check level >= 4
    int block_count = chainActive.Height() - pindex->nHeight;

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            const int percentageDone = std::max(1, std::min(99, 100 - (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * 50)));
            if (reportDone < percentageDone/10) {
                // report every 10% step
                LogPrintf("[%d%%]...", percentageDone); /* Continued */
                reportDone = percentageDone/10;
            }
            uiInterface.ShowProgress(_("Verifying blocks..."), percentageDone, false);
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!g_chainstate.ConnectBlock(block, state, pindex, coins, chainparams))
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s (%s)", pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", block_count, nGoodTransactions);

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
bool CChainState::RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params)
{
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, params.GetConsensus())) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn &txin : tx->vin) {
                inputs.SpendCoin(txin.prevout);
            }
        }
        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, true);
    }
    return true;
}

bool CChainState::ReplayBlocks(const CChainParams& params, CCoinsView* view)
{
    LOCK(cs_main);

    CCoinsViewCache cache(view);

    std::vector<uint256> hashHeads = view->GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("ReplayBlocks(): unknown inconsistent state");

    uiInterface.ShowProgress(_("Replaying blocks..."), 0, false);
    LogPrintf("Replaying blocks\n");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    if (mapBlockIndex.count(hashHeads[0]) == 0) {
        return error("ReplayBlocks(): reorganization to unknown block requested");
    }
    pindexNew = mapBlockIndex[hashHeads[0]];

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (mapBlockIndex.count(hashHeads[1]) == 0) {
            return error("ReplayBlocks(): reorganization from unknown block requested");
        }
        pindexOld = mapBlockIndex[hashHeads[1]];
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
            CBlock block;
            if (!ReadBlockFromDisk(block, pindexOld, params.GetConsensus())) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            LogPrintf("Rolling back %s (%i)\n", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
        const CBlockIndex* pindex = pindexNew->GetAncestor(nHeight);
        LogPrintf("Rolling forward %s (%i)\n", pindex->GetBlockHash().ToString(), nHeight);
        uiInterface.ShowProgress(_("Replaying blocks..."), (int) ((nHeight - nForkHeight) * 100.0 / (pindexNew->nHeight - nForkHeight)) , false);
        if (!RollforwardBlock(pindex, cache, params)) return false;
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    cache.Flush();
    uiInterface.ShowProgress("", 100, false);
    return true;
}

bool ReplayBlocks(const CChainParams& params, CCoinsView* view) {
    return g_chainstate.ReplayBlocks(params, view);
}

//! Helper for CChainState::RewindBlockIndex
void CChainState::EraseBlockData(CBlockIndex* index)
{
    AssertLockHeld(cs_main);
    assert(!chainActive.Contains(index)); // Make sure this block isn't active

    // Reduce validity
    index->nStatus = std::min<unsigned int>(index->nStatus & BLOCK_VALID_MASK, BLOCK_VALID_TREE) | (index->nStatus & ~BLOCK_VALID_MASK);
    // Remove have-data flags.
    index->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
    // Remove storage location.
    index->nFile = 0;
    index->nDataPos = 0;
    index->nUndoPos = 0;
    // Remove various other things
    index->nTx = 0;
    index->nChainTx = 0;
    index->nSequenceId = 0;
    // Make sure it gets written.
    setDirtyBlockIndex.insert(index);
    // Update indexes
    setBlockIndexCandidates.erase(index);
    std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> ret = mapBlocksUnlinked.equal_range(index->pprev);
    while (ret.first != ret.second) {
        if (ret.first->second == index) {
            mapBlocksUnlinked.erase(ret.first++);
        } else {
            ++ret.first;
        }
    }
    // Mark parent as eligible for main chain again
    if (index->pprev && index->pprev->IsValid(BLOCK_VALID_TRANSACTIONS) && index->pprev->HaveTxsDownloaded()) {
        setBlockIndexCandidates.insert(index->pprev);
    }
}

bool CChainState::RewindBlockIndex(const CChainParams& params)
{
    // Note that during -reindex-chainstate we are called with an empty chainActive!

    // First erase all post-segwit blocks without witness not in the main chain,
    // as this can we done without costly DisconnectTip calls. Active
    // blocks will be dealt with below (releasing cs_main in between).
    {
        LOCK(cs_main);
        for (const auto& entry : mapBlockIndex) {
            if (IsWitnessEnabled(entry.second->pprev, params.GetConsensus()) && !(entry.second->nStatus & BLOCK_OPT_WITNESS) && !chainActive.Contains(entry.second)) {
                EraseBlockData(entry.second);
            }
        }
    }

    // Find what height we need to reorganize to.
    CBlockIndex *tip;
    int nHeight = 1;
    {
        LOCK(cs_main);
        while (nHeight <= chainActive.Height()) {
            // Although SCRIPT_VERIFY_WITNESS is now generally enforced on all
            // blocks in ConnectBlock, we don't need to go back and
            // re-download/re-verify blocks from before segwit actually activated.
            if (IsWitnessEnabled(chainActive[nHeight - 1], params.GetConsensus()) && !(chainActive[nHeight]->nStatus & BLOCK_OPT_WITNESS)) {
                break;
            }
            nHeight++;
        }

        tip = chainActive.Tip();
    }
    // nHeight is now the height of the first insufficiently-validated block, or tipheight + 1

    CValidationState state;
    // Loop until the tip is below nHeight, or we reach a pruned block.
    while (!ShutdownRequested()) {
        {
            LOCK(cs_main);
            // Make sure nothing changed from under us (this won't happen because RewindBlockIndex runs before importing/network are active)
            assert(tip == chainActive.Tip());
            if (tip == nullptr || tip->nHeight < nHeight) break;
            if (fPruneMode && !(tip->nStatus & BLOCK_HAVE_DATA)) {
                // If pruning, don't try rewinding past the HAVE_DATA point;
                // since older blocks can't be served anyway, there's
                // no need to walk further, and trying to DisconnectTip()
                // will fail (and require a needless reindex/redownload
                // of the blockchain).
                break;
            }

            // Disconnect block
            if (!DisconnectTip(state, params, nullptr)) {
                return error("RewindBlockIndex: unable to disconnect block at height %i (%s)", tip->nHeight, FormatStateMessage(state));
            }

            // Reduce validity flag and have-data flags.
            // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
            // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
            // Note: If we encounter an insufficiently validated block that
            // is on chainActive, it must be because we are a pruning node, and
            // this block or some successor doesn't HAVE_DATA, so we were unable to
            // rewind all the way.  Blocks remaining on chainActive at this point
            // must not have their validity reduced.
            EraseBlockData(tip);

            tip = tip->pprev;
        }
        // Make sure the queue of validation callbacks doesn't grow unboundedly.
        LimitValidationInterfaceQueue();

        // Occasionally flush state to disk.
        if (!FlushStateToDisk(params, state, FlushStateMode::PERIODIC)) {
            LogPrintf("RewindBlockIndex: unable to flush state to disk (%s)\n", FormatStateMessage(state));
            return false;
        }
    }

    {
        LOCK(cs_main);
        if (chainActive.Tip() != nullptr) {
            // We can't prune block index candidates based on our tip if we have
            // no tip due to chainActive being empty!
            PruneBlockIndexCandidates();

            CheckBlockIndex(params.GetConsensus());
        }
    }

    return true;
}

bool RewindBlockIndex(const CChainParams& params) {
    if (!g_chainstate.RewindBlockIndex(params)) {
        return false;
    }

    if (chainActive.Tip() != nullptr) {
        // FlushStateToDisk can possibly read chainActive. Be conservative
        // and skip it here, we're about to -reindex-chainstate anyway, so
        // it'll get called a bunch real soon.
        CValidationState state;
        if (!FlushStateToDisk(params, state, FlushStateMode::ALWAYS)) {
            LogPrintf("RewindBlockIndex: unable to flush state to disk (%s)\n", FormatStateMessage(state));
            return false;
        }
    }

    return true;
}

void CChainState::UnloadBlockIndex() {
    nBlockSequenceId = 1;
    m_failed_blocks.clear();
    setBlockIndexCandidates.clear();
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex()
{
    LOCK(cs_main);
    chainActive.SetTip(nullptr);
    pindexBestInvalid = nullptr;
    pindexBestHeader = nullptr;
    mempool.clear();
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }

    for (const BlockMap::value_type& entry : mapBlockIndex) {
        delete entry.second;
    }
    mapBlockIndex.clear();
    fHavePruned = false;

    g_chainstate.UnloadBlockIndex();
}

bool LoadBlockIndex(const CChainParams& chainparams)
{
    // Load block index from databases
    bool needs_init = fReindex;
    if (!fReindex) {
        bool ret = LoadBlockIndexDB(chainparams);
        if (!ret) return false;
        needs_init = mapBlockIndex.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
    }
    return true;
}

bool CChainState::LoadGenesisBlock(const CChainParams& chainparams)
{
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // mapBlockIndex. Note that we can't use chainActive here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (mapBlockIndex.count(chainparams.GenesisBlock().GetHash()))
        return true;

    try {
        const CBlock& block = chainparams.GenesisBlock();
        CDiskBlockPos blockPos = SaveBlockToDisk(block, 0, chainparams, nullptr);
        if (blockPos.IsNull())
            return error("%s: writing genesis block to disk failed", __func__);
        CBlockIndex *pindex = AddToBlockIndex(block);
        ReceivedBlockTransactions(block, pindex, blockPos, chainparams.GetConsensus());
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

bool LoadGenesisBlock(const CChainParams& chainparams)
{
    return g_chainstate.LoadGenesisBlock(chainparams);
}

bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos *dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> buf;
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                uint256 hash = block.GetHash();
                {
                    LOCK(cs_main);
                    // detect out of order blocks, and store them for later
                    if (hash != chainparams.GetConsensus().hashGenesisBlock && !LookupBlockIndex(block.hashPrevBlock)) {
                        LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                                block.hashPrevBlock.ToString());
                        if (dbp)
                            mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                        continue;
                    }

                    // process in case the block isn't known yet
                    CBlockIndex* pindex = LookupBlockIndex(hash);
                    if (!pindex || (pindex->nStatus & BLOCK_HAVE_DATA) == 0) {
                      CValidationState state;
                      if (g_chainstate.AcceptBlock(pblock, state, chainparams, nullptr, true, dbp, nullptr)) {
                          nLoaded++;
                      }
                      if (state.IsError()) {
                          break;
                      }
                    } else if (hash != chainparams.GetConsensus().hashGenesisBlock && pindex->nHeight % 1000 == 0) {
                      LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), pindex->nHeight);
                    }
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == chainparams.GetConsensus().hashGenesisBlock) {
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, chainparams.GetConsensus()))
                        {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            CValidationState dummy;
                            if (g_chainstate.AcceptBlock(pblockrecursive, dummy, chainparams, nullptr, true, &it->second, nullptr))
                            {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void CChainState::CheckBlockIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (chainActive.Height() < 0) {
        assert(mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (const std::pair<const uint256, CBlockIndex*>& entry : mapBlockIndex) {
        forward.insert(std::make_pair(entry.second->pprev, entry.second));
    }

    assert(forward.size() == mapBlockIndex.size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = nullptr; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTransactionsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotChainValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotScriptsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == chainActive.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (!pindex->HaveTxsDownloaded()) assert(pindex->nSequenceId <= 0); // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to HaveTxsDownloaded().
        assert((pindexFirstNeverProcessed == nullptr) == pindex->HaveTxsDownloaded());
        assert((pindexFirstNotTransactionsValid == nullptr) == pindex->HaveTxsDownloaded());
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == nullptr || pindex->nChainWork >= pindex->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr); // All mapBlockIndex entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && pindexFirstNeverProcessed == nullptr) {
            if (pindexFirstInvalid == nullptr) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  chainActive.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == nullptr || pindex == chainActive.Tip()) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != nullptr && pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (pindexFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == nullptr && pindexFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered mapBlocksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between chainActive and the
            //    tip.
            // So if this block is itself better than chainActive.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in mapBlocksUnlinked.
            if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == nullptr) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, FormatISO8601Date(nTimeFirst), FormatISO8601Date(nTimeLast));
}

CBlockFileInfo* GetBlockFileInfo(size_t n)
{
    LOCK(cs_LastBlockFile);

    return &vinfoBlockFile.at(n);
}

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsState(chainActive.Tip(), params, pos, versionbitscache);
}

BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStatistics(chainActive.Tip(), params, pos);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStateSinceHeight(chainActive.Tip(), params, pos, versionbitscache);
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool()
{
    const CChainParams& chainparams = Params();
    int64_t nExpiryTimeout = gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat", "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t expired = 0;
    int64_t failed = 0;
    int64_t already_there = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                mempool.PrioritiseTransaction(tx->GetHash(), amountdelta);
            }
            CValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(chainparams, mempool, state, tx, nullptr /* pfMissingInputs */, nTime,
                                           nullptr /* plTxnReplaced */, false /* bypass_limits */, 0 /* nAbsurdFee */,
                                           false /* test_accept */);
                if (state.IsValid()) {
                    ++count;
                } else {
                    // mempool may contain the transaction already, e.g. from
                    // wallet(s) having loaded it while we were processing
                    // mempool transactions; consider these as valid, instead of
                    // failed, but mark them as 'already there'
                    if (mempool.exists(tx->GetHash())) {
                        ++already_there;
                    } else {
                        ++failed;
                    }
                }
            } else {
                ++expired;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            mempool.PrioritiseTransaction(i.first, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i succeeded, %i failed, %i expired, %i already there\n", count, failed, expired, already_there);
    return true;
}

bool DumpMempool()
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;

    static Mutex dump_mutex;
    LOCK(dump_mutex);

    {
        LOCK(mempool.cs);
        for (const auto &i : mempool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        }
        vinfo = mempool.infoAll();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat.new", "wb");
        if (!filestr) {
            return false;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << (int64_t)i.nTime;
            file << (int64_t)i.nFeeDelta;
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;
        if (!FileCommit(file.Get()))
            throw std::runtime_error("FileCommit failed");
        file.fclose();
        RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat");
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*MICRO, (last-mid)*MICRO);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

//! Guess how far we are in the verification process at the given block index
//! require cs_main if pindex has not been validated yet (because nChainTx might be unset)
double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex *pindex) {
    if (pindex == nullptr)
        return 0.0;

    int64_t nNow = time(nullptr);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return pindex->nChainTx / fTxTotal;
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;
