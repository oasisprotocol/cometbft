- `[mempool]` Before updating the mempool, consider it as full if rechecking is still in progress.
  This will stop accepting transactions in the mempool if the node can't keep up with re-CheckTx.
  This improvement is implemented only in the v0 mempool.
  ([\#3314](https://github.com/cometbft/cometbft/pull/3314))
