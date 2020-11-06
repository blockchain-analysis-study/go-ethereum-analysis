// Copyright 2015 The github.com/go-ethereum-analysis Authors
// This file is part of the github.com/go-ethereum-analysis library.
//
// The github.com/go-ethereum-analysis library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The github.com/go-ethereum-analysis library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the github.com/go-ethereum-analysis library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/eth/downloader"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/p2p/discover"
)

const (
	forceSyncCycle      = 10 * time.Second // Time interval to force syncs, even if few peers are available
	minDesiredPeerCount = 5                // Amount of peers desired to start syncing

	// This is the target size for the packs of transactions sent by txsyncLoop.
	// A pack can get larger than this if a single transactions exceeds this size.
	txsyncPackSize = 100 * 1024
)

type txsync struct {
	p   *peer
	txs []*types.Transaction
}

// syncTransactions starts sending all currently pending transactions to the given peer.
func (pm *ProtocolManager) syncTransactions(p *peer) {
	var txs types.Transactions

	// 抓拍 tx_pool 的 pending 中的 tx 快照
	//
	// todo 为什么只用 pengding 不用 queue中的 txs？
	//
	// 	因为 pending是准备好执行的tx, 但是 queue中的tx 很可能会被 替换或者失效掉. 所以 值广播 准备好的
	pending, _ := pm.txpool.Pending()
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	if len(txs) == 0 {
		return
	}
	select {
	case pm.txsyncCh <- &txsync{p, txs}:  // 用来做 广播用
	case <-pm.quitSync:
	}
}

// txsyncLoop takes care of the initial transaction sync for each new
// connection. When a new peer appears, we relay all currently pending
// transactions. In order to minimise egress bandwidth usage, we send
// the transactions in small packs to one peer at a time.
func (pm *ProtocolManager) txsyncLoop() {   // tx 广播
	var (
		// [对端 peer => txs]对
		pending = make(map[discover.NodeID]*txsync)
		sending = false               // whether a send is active
		pack    = new(txsync)         // the pack that is being sent
		done    = make(chan error, 1) // result of the send   全局的 tx 发送槽 (是的 [对端 peer => txs]对 是逐个发送)
	)

	// 发送tx
	// send starts a sending a pack of transactions from the sync.
	send := func(s *txsync) {
		// Fill pack with transactions up to the target size.
		size := common.StorageSize(0)
		pack.p = s.p
		pack.txs = pack.txs[:0]
		for i := 0; i < len(s.txs) && size < txsyncPackSize; i++ {
			pack.txs = append(pack.txs, s.txs[i])
			size += s.txs[i].Size()
		}
		// Remove the transactions that will be sent.
		s.txs = s.txs[:copy(s.txs, s.txs[len(pack.txs):])]
		if len(s.txs) == 0 {
			delete(pending, s.p.ID())
		}
		// Send the pack in the background.
		s.p.Log().Trace("Sending batch of transactions", "count", len(pack.txs), "bytes", size)
		sending = true
		go func() { done <- pack.p.SendTransactions(pack.txs) }()  // done 是 全局的 tx 发送槽 (是的 [对端 peer => txs]对 是逐个发送)
	}

	// 随机选择 一个 [对端 peer => txs]对 用来做发送
	// pick chooses the next pending sync.
	pick := func() *txsync {
		if len(pending) == 0 {
			return nil
		}
		n := rand.Intn(len(pending)) + 1
		for _, s := range pending {
			if n--; n == 0 {
				return s
			}
		}
		return nil
	}

	for {
		select {

		// 收到新交易 直接发
		case s := <-pm.txsyncCh:
			pending[s.p.ID()] = s
			if !sending {
				send(s)
			}

		// 当前 [对端 peer => txs]对 发送失败
		case err := <-done:  // done 是 全局的 tx 发送槽 (是的 [p => txs]对 是逐个发送)
			sending = false
			// Stop tracking peers that cause send failures.
			if err != nil {
				pack.p.Log().Debug("Transaction send failed", "err", err)
				delete(pending, pack.p.ID()) // 移除该 [对端 peer => txs]对
			}
			// Schedule the next send.
			if s := pick(); s != nil {  // 随机选择一个  [对端 peer => txs]对 发送
				send(s)
			}
		case <-pm.quitSync:
			return
		}
	}
}

// syncer is responsible for periodically synchronising with the network, both
// downloading hashes and blocks as well as handling the announcement handler.
func (pm *ProtocolManager) syncer() {   // todo 处理同步逻辑 (关于 Fetcher 和 Downloader 的逻辑起始点)

	// Start and ensure cleanup of sync mechanisms   启动 并确保清除 同步机制
	//
	pm.fetcher.Start()  // todo 启动 fecther

	defer pm.fetcher.Stop()
	defer pm.downloader.Terminate()

	// Wait for different events to fire synchronisation operations
	forceSync := time.NewTicker(forceSyncCycle)  // todo 10s 会去做一次 downloader 尝试同步
	defer forceSync.Stop()

	for {

		// todo 我们可以看到 会存在 当前peer 和 多个 对端peer 的同步作业任务.  但是在 `pm.synchronise()` 中,
		// todo 最终会用 downloader.synchronising == 1 在 当前本地 peer 和某个对端peer 做同步还未完成时, 来阻塞 当前本地 peer 和 当前 对端peer 的同步作业.
		// todo 所以我们可以大胆的认为, downloader 的 同步作业 只能是一个时间中 当前本地 peer 和某个对端peer 做同步作业 ...

		select {

		// todo 只要有 新对端 peer 加入, 我们都启动 downloader 尝试下 同步
		case <-pm.newPeerCh:
			// Make sure we have peers to select from, then sync
			if pm.peers.Len() < minDesiredPeerCount {
				break
			}
			go pm.synchronise(pm.peers.BestPeer())  // 向 td 越大的 对端 peer  发起同步

		// 10s 会去做一次 downloader 尝试同步
		case <-forceSync.C:
			// Force a sync even if not enough peers are present
			go pm.synchronise(pm.peers.BestPeer())  // 向 td 越大的 对端 peer  发起同步

		case <-pm.noMorePeers:
			return
		}
	}
}

// synchronise tries to sync up our local block chain with a remote peer.
//
// 从 一个对端 peer 上同步一些 block 到 本地chain中   todo (downloader 的工作入口点)
//
func (pm *ProtocolManager) synchronise(peer *peer) {
	// Short circuit if no peers are available
	if peer == nil {
		return
	}
	// Make sure the peer's TD is higher than our own
	currentBlock := pm.blockchain.CurrentBlock()								// 本地 chain 的最高块高
	td := pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64())	// 本地最新 难度值 td

	pHead, pTd := peer.Head()	// 对端 peer 目前存在本地 的 td 和 最高块Hash
	if pTd.Cmp(td) <= 0 {       // 如果本地 新的 block 和td 都超过该 对端peer, 那么不处理后续逻辑了
		return
	}
	// Otherwise try to sync with the downloader
	mode := downloader.FullSync  // downloader 默认是 full 模式
	if atomic.LoadUint32(&pm.fastSync) == 1 {
		// Fast sync was explicitly requested, and explicitly granted
		mode = downloader.FastSync
	} else if currentBlock.NumberU64() == 0 && pm.blockchain.CurrentFastBlock().NumberU64() > 0 {   // 上次做 fast 的最高块 (可能上次中断了, 导致 本地最高块 低于上次 fast的目标最高块)
		// The database seems empty as the current block is the genesis. Yet the fast
		// block is ahead, so fast sync was enabled for this node at a certain point.
		// The only scenario where this can happen is if the user manually (or via a
		// bad block) rolled back a fast sync node below the sync point. In this case
		// however it's safe to reenable fast sync.
		atomic.StoreUint32(&pm.fastSync, 1)
		mode = downloader.FastSync
	}

	if mode == downloader.FastSync {
		// Make sure the peer's total difficulty we are synchronizing is higher.
		if pm.blockchain.GetTdByHash(pm.blockchain.CurrentFastBlock().Hash()).Cmp(pTd) >= 0 {  // 在  fast 模式中,  本地的 td 大于 该对端 peer 的td, 则不做后续处理
			return
		}
	}

	// Run the sync cycle, and disable fast sync if we've went past the pivot block
	//
	// 启动 同步for 进程, 如果本地最高块 超过了同步时算的 pivot 块, 那么我们讲 todo 禁用 fast 模式,  后续都是 full 模式
	if err := pm.downloader.Synchronise(peer.id, pHead, pTd, mode); err != nil {  // todo (downloader 的工作入口点)  full 或者 fast 模式
		return
	}
	if atomic.LoadUint32(&pm.fastSync) == 1 {  // fast 模式已完成, 关闭 fast, 启用 full
		log.Info("Fast sync complete, auto disabling")
		atomic.StoreUint32(&pm.fastSync, 0)
	}
	atomic.StoreUint32(&pm.acceptTxs, 1) // Mark initial sync done  将初始同步标记为已完成
	if head := pm.blockchain.CurrentBlock(); head.NumberU64() > 0 {
		// We've completed a sync cycle, notify all peers of new state. This path is
		// essential in star-topology networks where a gateway node needs to notify
		// all its out-of-date peers of the availability of a new block. This failure
		// scenario will most often crop up in private and hackathon networks with
		// degenerate connectivity, but it should be healthy for the mainnet too to
		// more reliably update peers or the local TD state.
		go pm.BroadcastBlock(head, false)   // false: 向其他 对端 peer 宣布   (最终造成影响: 只将 blockHash 和 blockNumber 发布给对端 peer)
	}
}
