// Copyright 2015 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package eth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/consensus"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/consensus/misc"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/types"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/eth/downloader"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/eth/fetcher"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/ethdb"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/event"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/p2p"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/p2p/discover"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/params"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rlp"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096
)

var (
	daoChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

// errIncompatibleConfig is returned if the requested protocols and configs are
// not compatible (low protocol version restrictions and high requirements).
var errIncompatibleConfig = errors.New("incompatible configuration")

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type ProtocolManager struct {
	networkID uint64

	fastSync  uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)     快速同步开关 0：关闭, 1: 开启
	acceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)		(看了代码目前只会是 1 这个值) 是否允许同步 txs 的开关  0: 关闭,  1: 允许   todo 只有 block 同步已完成才开启  tx同步标识

	// tx_pool 引用
	txpool      txPool
	// chain 引用
	blockchain  *core.BlockChain
	// 链配置 信息
	chainconfig *params.ChainConfig

	// 本地节点做大允许连接的远端节点数目
	maxPeers    int

	// downloader  和 fetcher 都是在 ProtocolManager 中 NewProtocolManager() 实例化的
	downloader *downloader.Downloader
	fetcher    *fetcher.Fetcher
	peers      *peerSet	 // 这个也是 NewProtocolManager() 中实例化

	SubProtocols []p2p.Protocol  // 这些最终就是  p2p.peer.Run() 拉

	eventMux      *event.TypeMux
	txsCh         chan core.NewTxsEvent
	txsSub        event.Subscription
	minedBlockSub *event.TypeMuxSubscription

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup
}

// NewProtocolManager returns a new Ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the Ethereum network.
//
// NewProtocolManager返回一个新的以太坊子协议管理器。 以太坊子协议管理具有以太坊网络功能的peers。
func NewProtocolManager(config *params.ChainConfig, mode downloader.SyncMode, networkID uint64, mux *event.TypeMux, txpool txPool, engine consensus.Engine, blockchain *core.BlockChain, chaindb ethdb.Database) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	//
	// 创建 协议管理器及其一些基础字段
	manager := &ProtocolManager{
		networkID:   networkID,
		eventMux:    mux,
		txpool:      txpool,
		blockchain:  blockchain,
		chainconfig: config,
		peers:       newPeerSet(),
		newPeerCh:   make(chan *peer),
		noMorePeers: make(chan struct{}),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
	}
	// Figure out whether to allow fast sync or not
	// 找出是否允许快速同步
	if mode == downloader.FastSync && blockchain.CurrentBlock().NumberU64() > 0 {
		log.Warn("Blockchain not empty, fast sync disabled")
		mode = downloader.FullSync
	}
	if mode == downloader.FastSync {
		manager.fastSync = uint32(1)
	}
	// Initiate a sub-protocol for every implemented version we can handle
	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		// Skip protocol version if incompatible with the mode of operation
		// 从eth63开始不支持快速同步？
		if mode == downloader.FastSync && version < eth63 {
			continue
		}
		// Compatible; initialise the sub-protocol
		version := version // Closure for the run

		/**
		这里添加了几个回调 函数

		将 node 相关操作 对应的封装到 protocol 实例中
		 */
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],

			// todo 回调函数 (生成一个 protocalManager管理的 p2p node 实例,  用来做 广播 tx  和 block 用)
			//
			// todo 这个回调 最终会在 p2p\peer.go 的 startProtocols() 中被调用
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {

				peer := manager.newPeer(int(version), p, rw)   // todo 将 p2p.peer 封装成一个 ProtocalManager 管理的 eth.peer 实例

				select {
				// 每一个 peer.run 的时候
				case manager.newPeerCh <- peer:  // 这里发信号, 主要影响到  触发 downloader 去尝试做 同步
					manager.wg.Add(1)
					defer manager.wg.Done()

					return manager.handle(peer) // todo 处理 各类消息
				case <-manager.quitSync:
					return p2p.DiscQuitting
				}
			},

			// 我是 回调函数 (返回 node 的某些信息)
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},

			// 我是 回调函数 (返回 node 的真实链接实例)
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}
	if len(manager.SubProtocols) == 0 {
		return nil, errIncompatibleConfig
	}

	/**
	todo  初始化一个 downloader 实例
	 */
	// Construct the different synchronisation mechanisms
	manager.downloader = downloader.New(mode, chaindb, manager.eventMux, blockchain, nil, manager.removePeer)


	// 一个 校验器函数
	validator := func(header *types.Header) error {
		return engine.VerifyHeader(blockchain, header, true)
	}

	// 一个返回链上最高块 函数
	heighter := func() uint64 {
		return blockchain.CurrentBlock().NumberU64()
	}

	// 一个往链上插入新区块的函数
	inserter := func(blocks types.Blocks) (int, error) {
		// If fast sync is running, deny importing weird blocks
		if atomic.LoadUint32(&manager.fastSync) == 1 {
			log.Warn("Discarded bad propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash())
			return 0, nil
		}
		atomic.StoreUint32(&manager.acceptTxs, 1) // Mark initial sync done on any fetcher import   将任何 fecther 标记为已完成初始同步
		return manager.blockchain.InsertChain(blocks)
	}

	/**
	todo 初始化一个 fetcher 实例
	 */
	manager.fetcher = fetcher.New(blockchain.GetBlockByHash, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer)

	return manager, nil
}

// 将该对端peer 从本地ProtocolManager.peerSet中移除
// 将该对端peer 从本地 Downloader.peerSet中移除
// 断开和对端peer 的p2p连接
func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	log.Debug("Removing Ethereum peer", "peer", id)

	// Unregister the peer from the downloader and Ethereum peer set
	pm.downloader.UnregisterPeer(id)					// 将该对端peer 从本地 Downloader.peerSet中移除
	if err := pm.peers.Unregister(id); err != nil {  	// 将该对端peer 从本地ProtocolManager.peerSet中移除
		log.Error("Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer) // 断开和对端peer 的p2p连接
	}
}

/**
todo 启动 全节点的 pm

maxPeers: 在外面我们取的是 (p2p 服务的 最大允许 peer 连接数)
 */
func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers

	// broadcast transactions
	pm.txsCh = make(chan core.NewTxsEvent, txChanSize)
	pm.txsSub = pm.txpool.SubscribeNewTxsEvent(pm.txsCh)  // todo 监听 当前本地 tx_pool 中的 新 txs
	go pm.txBroadcastLoop()  		// todo 处理 新 tx 广播

	// broadcast mined blocks
	pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})  // todo 监听 当前本地 node 的  miner 挖出的 新 block 事件
	go pm.minedBroadcastLoop()		 // todo 处理 block 广播和 hash、Number 等发布  <最终由对端 peer 的 Fecther 来处理>

	// start sync handlers
	go pm.syncer()					// todo downloader 和 fetcher 相关
	go pm.txsyncLoop()				// todo 处理 tx_pool.pending 的 txs 发送  (选择 [对端peer => txs] 对来操作)
}

func (pm *ProtocolManager) Stop() {
	log.Info("Stopping Ethereum protocol")

	pm.txsSub.Unsubscribe()        // quits txBroadcastLoop
	pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	log.Info("Ethereum protocol stopped")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
/**
handle是用于管理eth对等方 (远端peer) 生命周期的回调。 此功能终止时，对等方(当前本地节点和远点节点)断开连接。

todo 入参数一个远点peer 的封装
 */
func (pm *ProtocolManager) handle(p *peer) error {
	// Ignore maxPeers if this is a trusted peer
	// 如果该远端节点是一个可信任的节点的话，则忽略掉pm的set中的大小
	if pm.peers.Len() >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
		// 否则，表示发现了太多的节点了
		return p2p.DiscTooManyPeers
	}
	p.Log().Debug("Ethereum peer connected", "name", p.Name())

	// Execute the Ethereum handshake
	var (
		genesis = pm.blockchain.Genesis()			// 创世块
		head    = pm.blockchain.CurrentHeader()		// 当前链上最高块header
		hash    = head.Hash()						// 当前最高块的Hash
		number  = head.Number.Uint64()				// 当前最高块的Number
		td      = pm.blockchain.GetTd(hash, number) // 当前链上的最新难度值
	)

	if err := p.Handshake(pm.networkID, td, hash, genesis.Hash()); err != nil {  // todo 处理当前 本地节点 和 该远点节点 p的 p2p消息
		p.Log().Debug("Ethereum handshake failed", "err", err)
		return err
	}
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	// Register the peer locally
	if err := pm.peers.Register(p); err != nil {   // todo 将远端 peer 的信息, 加到本地 pm.peerSet 中  (用来广播 tx  和 block 用)
		p.Log().Error("Ethereum peer registration failed", "err", err)
		return err
	}
	defer pm.removePeer(p.id)

	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := pm.downloader.RegisterPeer(p.id, p.version, p); err != nil {  // todo 将远端 peer 的信息, 加到本地 downloader.peerSet 中  (用来 同步数据用)
		return err
	}
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	pm.syncTransactions(p)  // todo 往对端 peer 尝试做一次 tx 广播  (只用 pending 中的txs)

	// If we're DAO hard-fork aware, validate any remote peer with regard to the hard-fork
	if daoBlock := pm.chainconfig.DAOForkBlock; daoBlock != nil {
		// Request the peer's DAO fork header for extra-data validation
		if err := p.RequestHeadersByNumber(daoBlock.Uint64(), 1, 0, false); err != nil {
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		p.forkDrop = time.AfterFunc(daoChallengeTimeout, func() {
			p.Log().Debug("Timed out DAO fork-check, dropping")
			pm.removePeer(p.id)
		})
		// Make sure it's cleaned up if the peer dies off
		defer func() {
			if p.forkDrop != nil {
				p.forkDrop.Stop()
				p.forkDrop = nil
			}
		}()
	}
	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil { // todo 这里处理 各类  tx  和 block 消息
			p.Log().Debug("Ethereum message handling failed", "err", err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
/**
TODO 超级重要的一个方法
每当从远程peer收到入站消息时，都会调用handleMsg。 返回任何错误后，远程连接将被断开。
 */
func (pm *ProtocolManager) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	defer msg.Discard()

	// Handle the message depending on its contents
	switch {
	case msg.Code == StatusMsg:
		// Status messages should never arrive after the handshake   握手后 StatusMsg 永远不会到达  (那在这之前的)
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")

	// Block header query, collect the requested headers and reply
	case msg.Code == GetBlockHeadersMsg:
		// Decode the complex header query
		var query getBlockHeadersData
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		hashMode := query.Origin.Hash != (common.Hash{})
		first := true
		maxNonCanonical := uint64(100)

		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Header
			unknown bool
		)
		for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit && len(headers) < downloader.MaxHeaderFetch {
			// Retrieve the next header satisfying the query
			var origin *types.Header
			if hashMode {
				if first {
					first = false
					origin = pm.blockchain.GetHeaderByHash(query.Origin.Hash)
					if origin != nil {
						query.Origin.Number = origin.Number.Uint64()
					}
				} else {
					origin = pm.blockchain.GetHeader(query.Origin.Hash, query.Origin.Number)
				}
			} else {
				origin = pm.blockchain.GetHeaderByNumber(query.Origin.Number)
			}
			if origin == nil {
				break
			}
			headers = append(headers, origin)
			bytes += estHeaderRlpSize

			// Advance to the next header of the query
			switch {
			case hashMode && query.Reverse:
				// Hash based traversal towards the genesis block
				ancestor := query.Skip + 1
				if ancestor == 0 {
					unknown = true
				} else {
					query.Origin.Hash, query.Origin.Number = pm.blockchain.GetAncestor(query.Origin.Hash, query.Origin.Number, ancestor, &maxNonCanonical)
					unknown = (query.Origin.Hash == common.Hash{})
				}
			case hashMode && !query.Reverse:
				// Hash based traversal towards the leaf block
				var (
					current = origin.Number.Uint64()
					next    = current + query.Skip + 1
				)
				if next <= current {
					infos, _ := json.MarshalIndent(p.Peer.Info(), "", "  ")
					p.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
					unknown = true
				} else {
					if header := pm.blockchain.GetHeaderByNumber(next); header != nil {
						nextHash := header.Hash()
						expOldHash, _ := pm.blockchain.GetAncestor(nextHash, next, query.Skip+1, &maxNonCanonical)
						if expOldHash == query.Origin.Hash {
							query.Origin.Hash, query.Origin.Number = nextHash, next
						} else {
							unknown = true
						}
					} else {
						unknown = true
					}
				}
			case query.Reverse:
				// Number based traversal towards the genesis block
				if query.Origin.Number >= query.Skip+1 {
					query.Origin.Number -= query.Skip + 1
				} else {
					unknown = true
				}

			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += query.Skip + 1
			}
		}
		return p.SendBlockHeaders(headers)

	case msg.Code == BlockHeadersMsg:
		// A batch of headers arrived to one of our previous requests
		var headers []*types.Header
		if err := msg.Decode(&headers); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// If no headers were received, but we're expending a DAO fork check, maybe it's that
		if len(headers) == 0 && p.forkDrop != nil {
			// Possibly an empty reply to the fork header checks, sanity check TDs
			verifyDAO := true

			// If we already have a DAO header, we can check the peer's TD against it. If
			// the peer's ahead of this, it too must have a reply to the DAO check
			if daoHeader := pm.blockchain.GetHeaderByNumber(pm.chainconfig.DAOForkBlock.Uint64()); daoHeader != nil {
				if _, td := p.Head(); td.Cmp(pm.blockchain.GetTd(daoHeader.Hash(), daoHeader.Number.Uint64())) >= 0 {
					verifyDAO = false
				}
			}
			// If we're seemingly on the same chain, disable the drop timer
			if verifyDAO {
				p.Log().Debug("Seems to be on the same side of the DAO fork")
				p.forkDrop.Stop()
				p.forkDrop = nil
				return nil
			}
		}
		// Filter out any explicitly requested headers, deliver the rest to the downloader   过滤掉任何显式请求的 header，其余的传递给下载器
		//
		// todo 【注意】 只有 收到的 header 是一个header时, 才继续处理
		filter := len(headers) == 1
		if filter {
			// If it's a potential DAO fork check, validate against the rules
			if p.forkDrop != nil && pm.chainconfig.DAOForkBlock.Cmp(headers[0].Number) == 0 {
				// Disable the fork drop timer
				p.forkDrop.Stop()
				p.forkDrop = nil

				// Validate the header and either drop the peer or continue
				if err := misc.VerifyDAOHeaderExtraData(pm.chainconfig, headers[0]); err != nil {
					p.Log().Debug("Verified to be on the other side of the DAO fork, dropping")
					return err
				}
				p.Log().Debug("Verified to be on the same side of the DAO fork")
				return nil
			}
			// Irrelevant of the fork checks, send the header to the fetcher just in case  与fork检查无关，以防万一，将 header 发送到 fecther
			//
			// 将 接收到 对端peer 发来的 一串 headers 交由 做过滤,  并可能返回一串 【未知hash 的header】
			headers = pm.fetcher.FilterHeaders(p.id, headers, time.Now())
		}

		// todo 否则, 全部交给 downloader 去做一大段 block 的下载
		if len(headers) > 0 || !filter {
			err := pm.downloader.DeliverHeaders(p.id, headers)
			if err != nil {
				log.Debug("Failed to deliver headers", "err", err)
			}
		}

	case msg.Code == GetBlockBodiesMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			hash   common.Hash
			bytes  int
			bodies []rlp.RawValue
		)
		for bytes < softResponseLimit && len(bodies) < downloader.MaxBlockFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block body, stopping if enough was found
			if data := pm.blockchain.GetBodyRLP(hash); len(data) != 0 {
				bodies = append(bodies, data)
				bytes += len(data)
			}
		}
		return p.SendBlockBodiesRLP(bodies)

	case msg.Code == BlockBodiesMsg:
		// A batch of block bodies arrived to one of our previous requests
		var request blockBodiesData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver them all to the downloader for queuing
		transactions := make([][]*types.Transaction, len(request))
		uncles := make([][]*types.Header, len(request))

		for i, body := range request {
			transactions[i] = body.Transactions
			uncles[i] = body.Uncles
		}
		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		//
		// 过滤 body
		filter := len(transactions) > 0 || len(uncles) > 0
		if filter {
			transactions, uncles = pm.fetcher.FilterBodies(p.id, transactions, uncles, time.Now())
		}

		// 如果 还有剩余的 body 需要过滤,  或者 之前不需要过滤 body 的话, 我们全部交给 downloader 解决
		if len(transactions) > 0 || len(uncles) > 0 || !filter {
			err := pm.downloader.DeliverBodies(p.id, transactions, uncles)
			if err != nil {
				log.Debug("Failed to deliver bodies", "err", err)
			}
		}

	case p.version >= eth63 && msg.Code == GetNodeDataMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash  common.Hash
			bytes int
			data  [][]byte
		)
		for bytes < softResponseLimit && len(data) < downloader.MaxStateFetch {
			// Retrieve the hash of the next state entry
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested state entry, stopping if enough was found
			if entry, err := pm.blockchain.TrieNode(hash); err == nil {
				data = append(data, entry)
				bytes += len(entry)
			}
		}
		return p.SendNodeData(data)

	case p.version >= eth63 && msg.Code == NodeDataMsg:
		// A batch of node state data arrived to one of our previous requests
		var data [][]byte
		if err := msg.Decode(&data); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverNodeData(p.id, data); err != nil {
			log.Debug("Failed to deliver node state data", "err", err)
		}

	case p.version >= eth63 && msg.Code == GetReceiptsMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash     common.Hash
			bytes    int
			receipts []rlp.RawValue
		)
		for bytes < softResponseLimit && len(receipts) < downloader.MaxReceiptFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block's receipts, skipping if unknown to us
			results := pm.blockchain.GetReceiptsByHash(hash)
			if results == nil {
				if header := pm.blockchain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
					continue
				}
			}
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(results); err != nil {
				log.Error("Failed to encode receipt", "err", err)
			} else {
				receipts = append(receipts, encoded)
				bytes += len(encoded)
			}
		}
		return p.SendReceiptsRLP(receipts)

	case p.version >= eth63 && msg.Code == ReceiptsMsg:
		// A batch of receipts arrived to one of our previous requests
		var receipts [][]*types.Receipt
		if err := msg.Decode(&receipts); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverReceipts(p.id, receipts); err != nil {
			log.Debug("Failed to deliver receipts", "err", err)
		}


	/**
	这里接受与一个 新的blocks的Hash消息
	多个block的Hash 哦
	远端的该peer 发过来的 一些列BlockHash
	 */
	case msg.Code == NewBlockHashesMsg:

		// 这个是封装了多个Hash 和number 的结构
		var announces newBlockHashesData

		// 从接收到的消息体中解析出多个 Hash 和number
		if err := msg.Decode(&announces); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		// Mark the hashes as present at the remote node
		//
		// 标识 这些从当前远端节点发过来的 Hash
		for _, block := range announces {

			// 在该远端节点实例的相关容器中 记录标识 下这些block的Hash (为了去重用)
			p.MarkBlock(block.Hash)
		}
		// Schedule all the unknown hashes for retrieval
		unknown := make(newBlockHashesData, 0, len(announces))   // todo 用来收集 存在于 对端peer 但是不存在当前本地 peer 的chain 中的block
		for _, block := range announces {
			if !pm.blockchain.HasBlock(block.Hash, block.Number) {
				unknown = append(unknown, block)
			}
		}

		// 逐个 处理 不存在 于 当前本地 peer 的chain 中的 block
		for _, block := range unknown {
			// p 这里是对端 peer
			pm.fetcher.Notify(p.id, block.Hash, block.Number, time.Now(), p.RequestOneHeader, p.RequestBodies)
		}

	case msg.Code == NewBlockMsg:
		// Retrieve and decode the propagated block
		var request newBlockData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		request.Block.ReceivedAt = msg.ReceivedAt
		request.Block.ReceivedFrom = p

		// Mark the peer as owning the block and schedule it for import
		p.MarkBlock(request.Block.Hash())
		pm.fetcher.Enqueue(p.id, request.Block)

		// Assuming the block is importable by the peer, but possibly not yet done so,
		// calculate the head hash and TD that the peer truly must have.
		var (
			trueHead = request.Block.ParentHash()
			trueTD   = new(big.Int).Sub(request.TD, request.Block.Difficulty())
		)
		// Update the peers total difficulty if better than the previous
		if _, td := p.Head(); trueTD.Cmp(td) > 0 {
			p.SetHead(trueHead, trueTD)   // 没收到一个 对端 peer 发来的 block 时, 更新在本地 peerSet 中的对端 peer 快照的  td 和 header

			// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
			// a singe block (as the true TD is below the propagated block), however this
			// scenario should easily be covered by the fetcher.
			currentBlock := pm.blockchain.CurrentBlock()
			if trueTD.Cmp(pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64())) > 0 {
				go pm.synchronise(p)  // 向 td 越大的 对端peer 发起同步作业
			}
		}

	case msg.Code == TxMsg:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if atomic.LoadUint32(&pm.acceptTxs) == 0 {
			break
		}
		// Transactions can be processed, parse all of them and deliver to the pool
		var txs []*types.Transaction
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		for i, tx := range txs {
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			p.MarkTransaction(tx.Hash())
		}
		pm.txpool.AddRemotes(txs)

	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
//
// 给所有的的 对端 peer 广播 blockHash 和 部分对端 peer广播 block
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)  // 获取所有 对该 blockHash 还未知的 peers

	// If propagation is requested, send to a subset of the peer   如果请求“传播”，则发送给 一部分 对端 peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := pm.blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), pm.blockchain.GetTd(block.ParentHash(), block.NumberU64()-1))
		} else {
			log.Error("Propagating dangling block", "number", block.Number(), "hash", hash)
			return
		}
		// Send the block to a subset of our peers    todo 这里取到 [0, 开平方 len)
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]

		// 将当前 block 逐个往 还未知道该 blockHash 的 对端 peer 上发送   (这里还没发送 只往通道里面写 block 和 td) (到时候用来 发送整个  block 和 td 的)
		for _, peer := range transfer {
			peer.AsyncSendNewBlock(block, td)
		}
		log.Trace("Propagated block", "hash", hash, "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// Otherwise if the block is indeed in out own chain, announce it
	//
	// 否则，如果该区块确实在自己的链中，则宣布它的存在   (这里还没发送 只往通道里面写 block )  (到时候用来 发布 block的 Hash 和 number 的)
	if pm.blockchain.HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			peer.AsyncSendNewBlockHash(block)
		}
		log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}

// BroadcastTxs will propagate a batch of transactions to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTxs(txs types.Transactions) {
	var txset = make(map[*peer]types.Transactions)

	// Broadcast transactions to a batch of peers not knowing about it
	for _, tx := range txs {
		peers := pm.peers.PeersWithoutTx(tx.Hash())  // 准备逐个往 未知当前 txHash 的 peer 上发送 该 tx
		for _, peer := range peers {
			txset[peer] = append(txset[peer], tx)
		}
		log.Trace("Broadcast transaction", "hash", tx.Hash(), "recipients", len(peers))
	}
	// FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for peer, txs := range txset {
		peer.AsyncSendTransactions(txs)  // 逐个往 未知 txHash 的 peer 上发送 txs  (这里还未真的 发送,  只往通道里发消息)
	}
}

// Mined broadcast loop
func (pm *ProtocolManager) minedBroadcastLoop() {  // 处理 block 广播和 hash、Number 等发布
	// automatically stops if unsubscribe
	for obj := range pm.minedBlockSub.Chan() {  // todo 读取出 当前本地 node 的 miner 挖出来的 新block 的 event
		if ev, ok := obj.Data.(core.NewMinedBlockEvent); ok {

			// todo 下面这两个 广播信息, 会被 对端 peer 的 Fecther 模块处理

			// 首先将块传播到同级  (最终造成影响:  将block 和 td发给 一部分对端 peer 且 blockHash 和 blockNumber 发布给 全部对端 peer)  todo 这里的对端peer 都是对 该block 未知的
			pm.BroadcastBlock(ev.Block, true)  // First propagate block to peers
			// 然后向其他人宣布   (最终造成影响: 只将 blockHash 和 blockNumber 发布给对端 peer) todo 这里的对端peer 都是对 该block 未知的
			pm.BroadcastBlock(ev.Block, false) // Only then announce to the rest
		}
	}
}

func (pm *ProtocolManager) txBroadcastLoop() {  // 处理 tx 广播
	for {
		select {
		case event := <-pm.txsCh:
			pm.BroadcastTxs(event.Txs)  // 里面最终做到： 逐个往 未知 txHash 的 peer 上发送 txs  (这里还未真的 发送,  只往通道里发消息)

		// Err() channel will be closed when unsubscribing.
		case <-pm.txsSub.Err():
			return
		}
	}
}

// NodeInfo represents a short summary of the Ethereum sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Network    uint64              `json:"network"`    // Ethereum network ID (1=Frontier, 2=Morden, Ropsten=3, Rinkeby=4)
	Difficulty *big.Int            `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis    common.Hash         `json:"genesis"`    // SHA3 hash of the host's genesis block
	Config     *params.ChainConfig `json:"config"`     // Chain configuration for the fork rules
	Head       common.Hash         `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (pm *ProtocolManager) NodeInfo() *NodeInfo {
	currentBlock := pm.blockchain.CurrentBlock()
	return &NodeInfo{
		Network:    pm.networkID,
		Difficulty: pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64()),
		Genesis:    pm.blockchain.Genesis().Hash(),
		Config:     pm.blockchain.Config(),
		Head:       currentBlock.Hash(),
	}
}
