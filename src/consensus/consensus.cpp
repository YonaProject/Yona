#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <policy/policy.h>
#include <amount.h>

CAmount GetStaticFee(bool nTokenTransaction, int nSpendHeight) {
    // return nTokenTransaction ? 0.005 * COIN : 0.008 * COIN;
    return 0.008 * COIN;
}

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
unsigned int dgpMaxBlockSerSize = 8000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
unsigned int dgpMaxBlockWeight = 8000000;

unsigned int dgpMaxBlockSize = 2000000; // yona

/** The maximum allowed number of signature check operations in a block (network rule) */
int64_t dgpMaxBlockSigOps = 80000;

unsigned int dgpMaxProtoMsgLength = 8000000;

unsigned int dgpMaxTxSigOps = 16000;
