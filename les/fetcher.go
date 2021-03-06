// Copyright 2016 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
// This file is part of the github.com/blockchain-analysis-study/go-ethereum-analysis library.
//
// The github.com/blockchain-analysis-study/go-ethereum-analysis library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The github.com/blockchain-analysis-study/go-ethereum-analysis library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the github.com/blockchain-analysis-study/go-ethereum-analysis library. If not, see <http://www.gnu.org/licenses/>.

// Package les implements the Light Ethereum Subprotocol.
package les

import (
	"math/big"
	"sync"
	"time"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/common/mclock"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/consensus"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/rawdb"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/types"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/light"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
)

const (
	blockDelayTimeout = time.Second * 10 // timeout for a peer to announce a head that has already been confirmed by others
	// 每个peer记住的fetcherTreeNode条目的最大数量
	maxNodeCount      = 20               // maximum number of fetcherTreeNode entries remembered for each peer
)

// lightFetcher implements retrieval of newly announced headers. It also provides a peerHasBlock function for the
// ODR system to ensure that we only request data related to a certain block from peers who have already processed
// and announced that block.
//
// peerSetNotify 的一个实现
type lightFetcher struct {
	pm    *ProtocolManager
	odr   *LesOdr
	chain *light.LightChain

	lock            sync.Mutex // lock protects access to the fetcher's internal state variables except sent requests
	maxConfirmedTd  *big.Int

	// 存储 peer指针 与之链接的对端peer
	// 我擦,使用指针来作为map的key??
	peers           map[*peer]*fetcherPeerInfo
	lastUpdateStats *updateStatsEntry
	syncing         bool
	syncDone        chan *peer

	reqMu      sync.RWMutex // reqMu protects access to sent header fetch requests
	requested  map[uint64]fetchRequest

	// todo 处理响应的chan
	deliverChn chan fetchResponse
	timeoutChn chan uint64

	// 结构发起 拉取最新 block header 的hash,num,td等req信号的chan
	// 如果从外部启动则为true
	requestChn chan bool // true if initiated from outside
}

// fetcherPeerInfo holds fetcher-specific information about each active peer
//
/**
fetcherPeerInfo保存有关每个活动peer的特定于访存器的信息
 */
type fetcherPeerInfo struct {
	// root: tree root
	// lastAnnounced: 最后加进来的一个 node !?
	root, lastAnnounced *fetcherTreeNode

	// todo 计数器,表示现在有多少个 checkpoint
	//  和nodeByHash的大小一致
	nodeCnt             int
	confirmedTd         *big.Int
	bestConfirmed       *fetcherTreeNode
	// TODO 这个是干嘛的
	nodeByHash          map[common.Hash]*fetcherTreeNode
	firstUpdateStats    *updateStatsEntry
}

// fetcherTreeNode is a node of a tree that holds information about blocks recently
// announced and confirmed by a certain peer. Each new announce message from a peer
// adds nodes to the tree, based on the previous announced head and the reorg depth.
// There are three possible states for a tree node:
// - announced: not downloaded (known) yet, but we know its head, number and td
// - intermediate: not known, hash and td are empty, they are filled out when it becomes known
// - known: both announced by this peer and downloaded (from any peer).
// This structure makes it possible to always know which peer has a certain block,
// which is necessary for selecting a suitable peer for ODR requests and also for
// canonizing new heads. It also helps to always download the minimum necessary
// amount of headers with a single request.
/**
fetcherTreeNode是树的节点，
其中保存有关某个 peer 最近`宣布`和`确认`的 block的信息。
来自peer的每个新的`公告消息`(announce message)都基于先前的`公告头`和`重组深度` 将节点添加到 tree 中。
树节点有三种可能的状态：
-`宣布`：尚未下载（已知），但我们知道其标题，编号和td
-`中间级`：未知，hash和td为空，在已知时将填写它们
-`已知`：此对等方宣布并下载（从任何对等方下载）。
todo 这种结构使得始终可以知道哪个peer具有特定的块，
这对于为ODR <可按需检索的> 请求选择合适的peer以及对新的header进行标准化来说是必需的。
它还有助于始终通过单个请求下载最小数量的header。

todo 这是一个梳妆的结构
 */
type fetcherTreeNode struct {
	// 对应这个tree 上节点的  hash 和 number
	hash             common.Hash
	number           uint64
	td               *big.Int
	known, requested bool
	parent           *fetcherTreeNode
	children         []*fetcherTreeNode
}

// fetchRequest represents a header download request
type fetchRequest struct {
	hash    common.Hash
	amount  uint64
	peer    *peer
	sent    mclock.AbsTime
	timeout bool
}

// fetchResponse represents a header download response
type fetchResponse struct {
	reqID   uint64
	headers []*types.Header
	peer    *peer
}

// newLightFetcher creates a new light fetcher
func newLightFetcher(pm *ProtocolManager) *lightFetcher {
	// peerSetNotify 的一个实现
	f := &lightFetcher{
		pm:             pm,
		chain:          pm.blockchain.(*light.LightChain),
		odr:            pm.odr,
		peers:          make(map[*peer]*fetcherPeerInfo),
		deliverChn:     make(chan fetchResponse, 100),
		requested:      make(map[uint64]fetchRequest),
		timeoutChn:     make(chan uint64),
		requestChn:     make(chan bool, 100),
		syncDone:       make(chan *peer),
		maxConfirmedTd: big.NewInt(0),
	}
	// 这里和 请求分发器一样 (主要是将 peerSet中的p注册到f中)
	pm.peers.notify(f)

	f.pm.wg.Add(1)

	// TODO  处理 f 的逻辑, 超级重要
	go f.syncLoop()
	return f
}

// syncLoop is the main event loop of the light fetcher
//
// syncLoop: 是 light fetcher 的主事件循环
func (f *lightFetcher) syncLoop() {

	// 是否正在和对端节点做 fecher 连接中?
	requesting := false
	defer f.pm.wg.Done()
	for {
		select {
		case <-f.pm.quitSync:
			return
		// when a new announce is received, request loop keeps running until
		// no further requests are necessary or possible
		//
		// todo 当收到新的通知时，请求循环将继续运行，直到不再需要或可能没有其他请求为止
		//
		case newAnnounce := <-f.requestChn:
			f.lock.Lock()
			s := requesting
			requesting = false
			var (
				rq    *distReq
				reqID uint64
			)

			// 如果不是同步中,且收到的 announceMsg  为false <不需要拉取最新的 head 信息>, 且 没有和对端peer做同步
			if !f.syncing && !(newAnnounce && s) {

				// 获取下一个请求,及随机生成的reqId
				// TODO 这个 贼鸡 重要
				// 在这里面返回 distReq 实体啊
				// distReq 最终会追加到 请求分发器中的啊
				//  最终在,请求分发器的 loop中会调用 distReq的 request 函数, 里头会有去 GetBlockHeaders 的func
				rq, reqID = f.nextRequest()
			}

			// 获取 同步标识位
			syncing := f.syncing
			f.lock.Unlock()

			if rq != nil {
				requesting = true
				// 根据 f.pm.reqDist.queue() 返回的chan中获取 响应的值
				// 注意 reqDist 是那个 `请求分发器` 的引用
				// 所以这里返回的chan 中的响应由 分发器的方法中回填信号
				_, ok := <-f.pm.reqDist.queue(rq)
				if !ok {
					f.requestChn <- false
				}


				// 如果不同步
				if !syncing {
					go func() {
						time.Sleep(softRequestTimeout)
						f.reqMu.Lock()
						req, ok := f.requested[reqID]
						if ok {
							req.timeout = true
							f.requested[reqID] = req
						}
						f.reqMu.Unlock()
						// keep starting new requests while possible
						f.requestChn <- false
					}()
				}
			}
		// 处理 超时请求
		case reqID := <-f.timeoutChn:
			f.reqMu.Lock()
			req, ok := f.requested[reqID]
			if ok {
				delete(f.requested, reqID)
			}
			f.reqMu.Unlock()
			if ok {
				// 调整响应时间
				f.pm.serverPool.adjustResponseTime(req.peer.poolEntry, time.Duration(mclock.Now()-req.sent), true)
				req.peer.Log().Debug("Fetching data timed out hard")
				// 从pm中移除超时的 对端peer
				go f.pm.removePeer(req.peer.id)
			}

		// todo 处理响应
		case resp := <-f.deliverChn:
			f.reqMu.Lock()
			req, ok := f.requested[resp.reqID]
			if ok && req.peer != resp.peer {
				ok = false
			}
			if ok {
				delete(f.requested, resp.reqID)
			}
			f.reqMu.Unlock()
			if ok {
				f.pm.serverPool.adjustResponseTime(req.peer.poolEntry, time.Duration(mclock.Now()-req.sent), req.timeout)
			}
			f.lock.Lock()
			if !ok || !(f.syncing || f.processResponse(req, resp)) {
				resp.peer.Log().Debug("Failed processing response")
				go f.pm.removePeer(resp.peer.id)
			}
			f.lock.Unlock()
		// 处理 同步结束信号
		case p := <-f.syncDone:
			f.lock.Lock()
			p.Log().Debug("Done synchronising with peer")
			f.checkSyncedHeaders(p)
			f.syncing = false
			f.lock.Unlock()
		}
	}
}

// registerPeer adds a new peer to the fetcher's peer set
func (f *lightFetcher) registerPeer(p *peer) {
	p.lock.Lock()
	p.hasBlock = func(hash common.Hash, number uint64) bool {
		return f.peerHasBlock(p, hash, number)
	}
	p.lock.Unlock()

	f.lock.Lock()
	defer f.lock.Unlock()

	f.peers[p] = &fetcherPeerInfo{nodeByHash: make(map[common.Hash]*fetcherTreeNode)}
}

// unregisterPeer removes a new peer from the fetcher's peer set
func (f *lightFetcher) unregisterPeer(p *peer) {
	p.lock.Lock()
	p.hasBlock = nil
	p.lock.Unlock()

	f.lock.Lock()
	defer f.lock.Unlock()

	// check for potential timed out block delay statistics
	f.checkUpdateStats(p, nil)
	delete(f.peers, p)
}

// announce processes a new announcement message received from a peer, adding new
// nodes to the peer's block tree and removing old nodes if necessary
//
/**
announce: 处理从peer收到的新公告消息，将新节点添加到 peer 的block tree，并在必要时删除旧节点
 */
func (f *lightFetcher) announce(p *peer, head *announceData) {
	f.lock.Lock()
	defer f.lock.Unlock()
	p.Log().Debug("Received new announcement", "number", head.Number, "hash", head.Hash, "reorg", head.ReorgDepth)

	/**
	todo 获取,每个活动peer的特定于访存器的信息
	todo 这里有 odr tree
	 */
	fp := f.peers[p]
	if fp == nil {
		p.Log().Debug("Announcement from unknown peer")
		return
	}

	// 当现在见进来的header 的TD 小于上次加进来的header相关的TD小时, (有问题)
	if fp.lastAnnounced != nil && head.Td.Cmp(fp.lastAnnounced.td) <= 0 {
		// announced tds should be strictly monotonic
		//
		// 公布的tds应该 `严格单调`
		// 即 TD 应该单调递增, 如果不是,则该远端 peer 的数据有问题,需要从本地的peerSet中移除
		p.Log().Debug("Received non-monotonic td", "current", head.Td, "previous", fp.lastAnnounced.td)
		go f.pm.removePeer(p.id)
		return
	}

	// todo 先拿到最后一个 block做成的 node
	n := fp.lastAnnounced

	// 根据 重组深度,遍历一直往 tree root 遍历
	// todo 说白了就是需要查找公共祖先   入参的head 和 fp的最后一个 block的node
	for i := uint64(0); i < head.ReorgDepth; i++ {
		if n == nil {
			break
		}

		// todo 使用上一级 node
		n = n.parent
	}


	// n is now the reorg common ancestor, add a new branch of nodes
	//
	// todo `n` 现在是reorg的共同祖先，添加一个新的节点分支
	if n != nil && (head.Number >= n.number+maxNodeCount || head.Number <= n.number) {
		// if announced head block height is lower or same as n or too far from it to add
		// intermediate nodes then discard previous announcement info and trigger a resync
		//
		/**
		todo
			如果已声明的 head块高度小于或等于n或相距太远而无法添加中间节点，则丢弃先前的声明信息并触发重新同步
		 */
		n = nil // 将指针引用置为 nil
		fp.nodeCnt = 0  // 清空checkpoint计数
		// 清空 checkpoint tree
		fp.nodeByHash = make(map[common.Hash]*fetcherTreeNode)
	}


	/**
	TODO 来啦来啦 皮卡丘

	todo 如果 入参的head 和之前fp中最后一个 block 的node 的 公共祖先存在 且 合法
	 */
	if n != nil {
		// check if the node count is too high to add new nodes, discard oldest ones if necessary
		//
		// 检查节点数是否太高而无法添加新节点，必要时丢弃最旧的节点
		locked := false // 表示 是否 lock chain
		for uint64(fp.nodeCnt)+head.Number-n.number > maxNodeCount && fp.root != nil {

			/**
			先将 chain 锁住,然后再操作
			 */
			if !locked {
				f.chain.LockChain()
				defer f.chain.UnlockChain()
				locked = true
			}


			/**
			下面就是调整 tree
			因为 可能之前的tree 数据过久,则之前可能是 子节点的可能现在是 规范节点(规范节点需要用力啊做成根部)了
			 */

			// if one of root's children is canonical, keep it, delete other branches and root itself
			//
			// 如果根的子代之一是规范的，则保留该子代，删除其他分支和根自己
			// todo 定义新的 root
			var newRoot *fetcherTreeNode

			// 遍历root 的所有 children
			for i, nn := range fp.root.children {
				// 判断该block是否是规范块
				if rawdb.ReadCanonicalHash(f.pm.chainDb, nn.number) == nn.hash {

					// 如果是 规范块,从tree中清除掉该block
					fp.root.children = append(fp.root.children[:i], fp.root.children[i+1:]...)

					// 将 该规范块 作为一颗新tree 的root
					nn.parent = nil
					newRoot = nn
					break
				}
			}

			// 从peer的fetcherPeerInfo 中删除节点及其子树
			//  todo 从 fp中清掉root 对应的 tree
			fp.deleteNode(fp.root)

			// todo 使用新的 root
			if n == fp.root {
				n = newRoot
			}
			fp.root = newRoot


			// checkKnownNode: 检查是否知道（下载并验证了）block tree node, 从之前的light chain中校验
			// 省去做重复查询了
			if newRoot == nil || !f.checkKnownNode(p, newRoot) {
				fp.bestConfirmed = nil
				fp.confirmedTd = nil
			}

			if n == nil {
				break
			}
		}

		// todo 来,如果新的 祖先不为 nil
		if n != nil {

			// n 是当前入参的 head 的祖先
			for n.number < head.Number {

				// 一直去构造 head 的祖先块
				nn := &fetcherTreeNode{number: n.number + 1, parent: n}
				n.children = append(n.children, nn)
				n = nn
				fp.nodeCnt++
			}
			n.hash = head.Hash
			n.td = head.Td

			// 将新的checkpoint 加入 map中
			fp.nodeByHash[n.hash] = n
		}
	}



	/**
	todo  如果找不到 共同祖先
	 */
	if n == nil {
		// could not find reorg common ancestor or had to delete entire tree, a new root and a resync is needed
		// todo 找不到重新组织的共同祖先，或不得不删除整个树，需要新的根并需要重新同步
		// 则, 清掉整颗tree
		if fp.root != nil {
			fp.deleteNode(fp.root)
		}

		// 以 入参的head作为root 构建新的树
		n = &fetcherTreeNode{hash: head.Hash, number: head.Number, td: head.Td}
		fp.root = n
		fp.nodeCnt++
		fp.nodeByHash[n.hash] = n
		fp.bestConfirmed = nil
		fp.confirmedTd = nil
	}

	f.checkKnownNode(p, n)
	p.lock.Lock()
	p.headInfo = head
	fp.lastAnnounced = n
	p.lock.Unlock()
	f.checkUpdateStats(p, nil)

	// todo 通知 light fetcher 获取新的拉取req
	//  最终在,请求分发器的 loop中会调用 distReq的 request 函数, 里头会有去 GetBlockHeaders 的func
	f.requestChn <- true
}

// peerHasBlock returns true if we can assume the peer knows the given block
// based on its announcements
func (f *lightFetcher) peerHasBlock(p *peer, hash common.Hash, number uint64) bool {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.syncing {
		// always return true when syncing
		// false positives are acceptable, a more sophisticated condition can be implemented later
		return true
	}

	fp := f.peers[p]
	if fp == nil || fp.root == nil {
		return false
	}

	if number >= fp.root.number {
		// it is recent enough that if it is known, is should be in the peer's block tree
		return fp.nodeByHash[hash] != nil
	}
	f.chain.LockChain()
	defer f.chain.UnlockChain()
	// if it's older than the peer's block tree root but it's in the same canonical chain
	// as the root, we can still be sure the peer knows it
	//
	// when syncing, just check if it is part of the known chain, there is nothing better we
	// can do since we do not know the most recent block hash yet
	return rawdb.ReadCanonicalHash(f.pm.chainDb, fp.root.number) == fp.root.hash && rawdb.ReadCanonicalHash(f.pm.chainDb, number) == hash
}

// requestAmount calculates the amount of headers to be downloaded starting
// from a certain head backwards
//
// requestAmount计算从特定header开始向后下载的header的数量
func (f *lightFetcher) requestAmount(p *peer, n *fetcherTreeNode) uint64 {
	amount := uint64(0)
	nn := n
	for nn != nil && !f.checkKnownNode(p, nn) {
		nn = nn.parent
		amount++
	}
	if nn == nil {
		amount = n.number
	}
	return amount
}

// requestedID tells if a certain reqID has been requested by the fetcher
func (f *lightFetcher) requestedID(reqID uint64) bool {
	f.reqMu.RLock()
	_, ok := f.requested[reqID]
	f.reqMu.RUnlock()
	return ok
}

// nextRequest selects the peer and announced head to be requested next, amount
// to be downloaded starting from the head backwards is also returned
//
// nextRequest选择 对端peer 并宣布下一步要请求的head，还返回从head开始向后下载的数量
//
func (f *lightFetcher) nextRequest() (*distReq, uint64) {
	var (
		bestHash   common.Hash
		bestAmount uint64
	)

	bestTd := f.maxConfirmedTd  // 初始化难度值
	bestSyncing := false		// 初始化 同步标识位

	// 逐个获取peer 和 fecherPeerInfo
	// fecherPeerInfo中存在一个trie
	// fetcherPeerInfo保存有关每个活动peer的特定于访存器的信息
	for p, fp := range f.peers {
		// 遍历该peer的所有 访存器
		for hash, n := range fp.nodeByHash {

			// 逐个教研检查,逐个对比td
			if !f.checkKnownNode(p, n) && !n.requested && (bestTd == nil || n.td.Cmp(bestTd) >= 0) {
				// 计算从特定header开始向后下载的header的数量
				amount := f.requestAmount(p, n)
				if bestTd == nil || n.td.Cmp(bestTd) > 0 || amount < bestAmount {
					bestHash = hash
					bestAmount = amount
					bestTd = n.td
					bestSyncing = fp.bestConfirmed == nil || fp.root == nil || !f.checkKnownNode(p, fp.root)
				}
			}
		}
	}
	if bestTd == f.maxConfirmedTd {
		return nil, 0
	}


	//
	f.syncing = bestSyncing

	var rq *distReq
	// 随机生成一个 请求Id
	reqID := genReqID()

	// 如果是同步中的话
	if f.syncing {

		/**
		组装 req 实体
		 */
		rq = &distReq{
			getCost: func(dp distPeer) uint64 {
				return 0
			},
			canSend: func(dp distPeer) bool {
				p := dp.(*peer)
				f.lock.Lock()
				defer f.lock.Unlock()

				fp := f.peers[p]
				return fp != nil && fp.nodeByHash[bestHash] != nil
			},
			request: func(dp distPeer) func() {
				go func() {
					p := dp.(*peer)
					p.Log().Debug("Synchronisation started")

					/**
					TODO 超级重要
					TODO 这里是 light 同步的开始,
					TODO 同步的流程最终会流转到 downloader 那边
					 */
					f.pm.synchronise(p)
					f.syncDone <- p
				}()
				return nil
			},
		}
	} else {

		/**
		组装 req 实体
		 */
		rq = &distReq{
			getCost: func(dp distPeer) uint64 {
				p := dp.(*peer)
				return p.GetRequestCost(GetBlockHeadersMsg, int(bestAmount))
			},
			canSend: func(dp distPeer) bool {
				p := dp.(*peer)
				f.lock.Lock()
				defer f.lock.Unlock()

				fp := f.peers[p]
				if fp == nil {
					return false
				}
				n := fp.nodeByHash[bestHash]
				return n != nil && !n.requested
			},

			// 重要
			request: func(dp distPeer) func() {
				p := dp.(*peer)
				f.lock.Lock()
				fp := f.peers[p]
				if fp != nil {
					n := fp.nodeByHash[bestHash]
					if n != nil {
						n.requested = true
					}
				}
				f.lock.Unlock()

				cost := p.GetRequestCost(GetBlockHeadersMsg, int(bestAmount))
				p.fcServer.QueueRequest(reqID, cost)
				f.reqMu.Lock()
				f.requested[reqID] = fetchRequest{hash: bestHash, amount: bestAmount, peer: p, sent: mclock.Now()}
				f.reqMu.Unlock()
				go func() {
					time.Sleep(hardRequestTimeout)
					f.timeoutChn <- reqID
				}()

				// // // // // // // //
				// // // // // // // //
				// todo 超级重要
				// todo 超级重要
				// todo 其实 这个就是 发起拉取  header 的请求
				// // // // // // // //
				// // // // // // // //
				return func() {
					// todo 根据Hash 去拿 header
					p.RequestHeadersByHash(reqID, cost, bestHash, int(bestAmount), 0, true)
				}
			},
		}
	}

	// 返回 组装好的 req, 和对应的随机生成的 reqId
	return rq, reqID
}

// deliverHeaders delivers header download request responses for processing
func (f *lightFetcher) deliverHeaders(peer *peer, reqID uint64, headers []*types.Header) {
	f.deliverChn <- fetchResponse{reqID: reqID, headers: headers, peer: peer}
}

// processResponse processes header download request responses, returns true if successful
func (f *lightFetcher) processResponse(req fetchRequest, resp fetchResponse) bool {
	if uint64(len(resp.headers)) != req.amount || resp.headers[0].Hash() != req.hash {
		req.peer.Log().Debug("Response content mismatch", "requested", len(resp.headers), "reqfrom", resp.headers[0], "delivered", req.amount, "delfrom", req.hash)
		return false
	}
	headers := make([]*types.Header, req.amount)
	for i, header := range resp.headers {
		headers[int(req.amount)-1-i] = header
	}
	if _, err := f.chain.InsertHeaderChain(headers, 1); err != nil {
		if err == consensus.ErrFutureBlock {
			return true
		}
		log.Debug("Failed to insert header chain", "err", err)
		return false
	}
	tds := make([]*big.Int, len(headers))
	for i, header := range headers {
		td := f.chain.GetTd(header.Hash(), header.Number.Uint64())
		if td == nil {
			log.Debug("Total difficulty not found for header", "index", i+1, "number", header.Number, "hash", header.Hash())
			return false
		}
		tds[i] = td
	}
	f.newHeaders(headers, tds)
	return true
}

// newHeaders updates the block trees of all active peers according to a newly
// downloaded and validated batch or headers
func (f *lightFetcher) newHeaders(headers []*types.Header, tds []*big.Int) {
	var maxTd *big.Int
	for p, fp := range f.peers {
		if !f.checkAnnouncedHeaders(fp, headers, tds) {
			p.Log().Debug("Inconsistent announcement")
			go f.pm.removePeer(p.id)
		}
		if fp.confirmedTd != nil && (maxTd == nil || maxTd.Cmp(fp.confirmedTd) > 0) {
			maxTd = fp.confirmedTd
		}
	}
	if maxTd != nil {
		f.updateMaxConfirmedTd(maxTd)
	}
}

// checkAnnouncedHeaders updates peer's block tree if necessary after validating
// a batch of headers. It searches for the latest header in the batch that has a
// matching tree node (if any), and if it has not been marked as known already,
// sets it and its parents to known (even those which are older than the currently
// validated ones). Return value shows if all hashes, numbers and Tds matched
// correctly to the announced values (otherwise the peer should be dropped).
func (f *lightFetcher) checkAnnouncedHeaders(fp *fetcherPeerInfo, headers []*types.Header, tds []*big.Int) bool {
	var (
		n      *fetcherTreeNode
		header *types.Header
		td     *big.Int
	)

	for i := len(headers) - 1; ; i-- {
		if i < 0 {
			if n == nil {
				// no more headers and nothing to match
				return true
			}
			// we ran out of recently delivered headers but have not reached a node known by this peer yet, continue matching
			hash, number := header.ParentHash, header.Number.Uint64()-1
			td = f.chain.GetTd(hash, number)
			header = f.chain.GetHeader(hash, number)
			if header == nil || td == nil {
				log.Error("Missing parent of validated header", "hash", hash, "number", number)
				return false
			}
		} else {
			header = headers[i]
			td = tds[i]
		}
		hash := header.Hash()
		number := header.Number.Uint64()
		if n == nil {
			n = fp.nodeByHash[hash]
		}
		if n != nil {
			if n.td == nil {
				// node was unannounced
				if nn := fp.nodeByHash[hash]; nn != nil {
					// if there was already a node with the same hash, continue there and drop this one
					nn.children = append(nn.children, n.children...)
					n.children = nil
					fp.deleteNode(n)
					n = nn
				} else {
					n.hash = hash
					n.td = td
					fp.nodeByHash[hash] = n
				}
			}
			// check if it matches the header
			if n.hash != hash || n.number != number || n.td.Cmp(td) != 0 {
				// peer has previously made an invalid announcement
				return false
			}
			if n.known {
				// we reached a known node that matched our expectations, return with success
				return true
			}
			n.known = true
			if fp.confirmedTd == nil || td.Cmp(fp.confirmedTd) > 0 {
				fp.confirmedTd = td
				fp.bestConfirmed = n
			}
			n = n.parent
			if n == nil {
				return true
			}
		}
	}
}

// checkSyncedHeaders updates peer's block tree after synchronisation by marking
// downloaded headers as known. If none of the announced headers are found after
// syncing, the peer is dropped.
func (f *lightFetcher) checkSyncedHeaders(p *peer) {
	fp := f.peers[p]
	if fp == nil {
		p.Log().Debug("Unknown peer to check sync headers")
		return
	}
	n := fp.lastAnnounced
	var td *big.Int
	for n != nil {
		if td = f.chain.GetTd(n.hash, n.number); td != nil {
			break
		}
		n = n.parent
	}
	// now n is the latest downloaded header after syncing
	if n == nil {
		p.Log().Debug("Synchronisation failed")
		go f.pm.removePeer(p.id)
	} else {
		header := f.chain.GetHeader(n.hash, n.number)
		f.newHeaders([]*types.Header{header}, []*big.Int{td})
	}
}

// checkKnownNode checks if a block tree node is known (downloaded and validated)
// If it was not known previously but found in the database, sets its known flag
//
// checkKnownNode: 检查是否知道（下载并验证了）block tree node。如果以前未知但在数据库中找到它，则设置其已知标志
//
func (f *lightFetcher) checkKnownNode(p *peer, n *fetcherTreeNode) bool {
	if n.known {
		return true
	}
	td := f.chain.GetTd(n.hash, n.number)
	if td == nil {
		return false
	}
	header := f.chain.GetHeader(n.hash, n.number)
	// check the availability of both header and td because reads are not protected by chain db mutex
	// Note: returning false is always safe here
	if header == nil {
		return false
	}

	fp := f.peers[p]
	if fp == nil {
		p.Log().Debug("Unknown peer to check known nodes")
		return false
	}
	if !f.checkAnnouncedHeaders(fp, []*types.Header{header}, []*big.Int{td}) {
		p.Log().Debug("Inconsistent announcement")
		go f.pm.removePeer(p.id)
	}
	if fp.confirmedTd != nil {
		f.updateMaxConfirmedTd(fp.confirmedTd)
	}
	return n.known
}

// deleteNode deletes a node and its child subtrees from a peer's block tree
//
// deleteNode: 从peer的fetcherPeerInfo 中删除节点及其子树
func (fp *fetcherPeerInfo) deleteNode(n *fetcherTreeNode) {
	if n.parent != nil {

		// 先整理下 tree, 如果自己的子节点就包含了自己
		// 则,先清掉
		for i, nn := range n.parent.children {
			if nn == n {
				n.parent.children = append(n.parent.children[:i], n.parent.children[i+1:]...)
				break
			}
		}
	}


	for {
		if n.td != nil {

			// 删掉 对应的root
			delete(fp.nodeByHash, n.hash)
		}

		// checkpoint 计数 减一
		fp.nodeCnt--
		if len(n.children) == 0 {
			return
		}

		// 继续清理掉 新的root及下属子节点
		for i, nn := range n.children {
			if i == 0 {
				n = nn
			} else {
				fp.deleteNode(nn)
			}
		}
	}
}

// updateStatsEntry items form a linked list that is expanded with a new item every time a new head with a higher Td
// than the previous one has been downloaded and validated. The list contains a series of maximum confirmed Td values
// and the time these values have been confirmed, both increasing monotonically. A maximum confirmed Td is calculated
// both globally for all peers and also for each individual peer (meaning that the given peer has announced the head
// and it has also been downloaded from any peer, either before or after the given announcement).
// The linked list has a global tail where new confirmed Td entries are added and a separate head for each peer,
// pointing to the next Td entry that is higher than the peer's max confirmed Td (nil if it has already confirmed
// the current global head).
type updateStatsEntry struct {
	time mclock.AbsTime
	td   *big.Int
	next *updateStatsEntry
}

// updateMaxConfirmedTd updates the block delay statistics of active peers. Whenever a new highest Td is confirmed,
// adds it to the end of a linked list together with the time it has been confirmed. Then checks which peers have
// already confirmed a head with the same or higher Td (which counts as zero block delay) and updates their statistics.
// Those who have not confirmed such a head by now will be updated by a subsequent checkUpdateStats call with a
// positive block delay value.
func (f *lightFetcher) updateMaxConfirmedTd(td *big.Int) {
	if f.maxConfirmedTd == nil || td.Cmp(f.maxConfirmedTd) > 0 {
		f.maxConfirmedTd = td
		newEntry := &updateStatsEntry{
			time: mclock.Now(),
			td:   td,
		}
		if f.lastUpdateStats != nil {
			f.lastUpdateStats.next = newEntry
		}
		f.lastUpdateStats = newEntry
		for p := range f.peers {
			f.checkUpdateStats(p, newEntry)
		}
	}
}

// checkUpdateStats checks those peers who have not confirmed a certain highest Td (or a larger one) by the time it
// has been confirmed by another peer. If they have confirmed such a head by now, their stats are updated with the
// block delay which is (this peer's confirmation time)-(first confirmation time). After blockDelayTimeout has passed,
// the stats are updated with blockDelayTimeout value. In either case, the confirmed or timed out updateStatsEntry
// items are removed from the head of the linked list.
// If a new entry has been added to the global tail, it is passed as a parameter here even though this function
// assumes that it has already been added, so that if the peer's list is empty (all heads confirmed, head is nil),
// it can set the new head to newEntry.
func (f *lightFetcher) checkUpdateStats(p *peer, newEntry *updateStatsEntry) {
	now := mclock.Now()
	fp := f.peers[p]
	if fp == nil {
		p.Log().Debug("Unknown peer to check update stats")
		return
	}
	if newEntry != nil && fp.firstUpdateStats == nil {
		fp.firstUpdateStats = newEntry
	}
	for fp.firstUpdateStats != nil && fp.firstUpdateStats.time <= now-mclock.AbsTime(blockDelayTimeout) {
		f.pm.serverPool.adjustBlockDelay(p.poolEntry, blockDelayTimeout)
		fp.firstUpdateStats = fp.firstUpdateStats.next
	}
	if fp.confirmedTd != nil {
		for fp.firstUpdateStats != nil && fp.firstUpdateStats.td.Cmp(fp.confirmedTd) <= 0 {
			f.pm.serverPool.adjustBlockDelay(p.poolEntry, time.Duration(now-fp.firstUpdateStats.time))
			fp.firstUpdateStats = fp.firstUpdateStats.next
		}
	}
}
