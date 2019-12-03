// Copyright 2016 The github.com/go-ethereum-analysis Authors
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

// Package les implements the Light Ethereum Subprotocol.
package les

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/common/mclock"
	"github.com/go-ethereum-analysis/consensus"
	"github.com/go-ethereum-analysis/core"
	"github.com/go-ethereum-analysis/core/rawdb"
	"github.com/go-ethereum-analysis/core/state"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/eth/downloader"
	"github.com/go-ethereum-analysis/ethdb"
	"github.com/go-ethereum-analysis/event"
	"github.com/go-ethereum-analysis/light"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/p2p"
	"github.com/go-ethereum-analysis/p2p/discv5"
	"github.com/go-ethereum-analysis/params"
	"github.com/go-ethereum-analysis/rlp"
	"github.com/go-ethereum-analysis/trie"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	ethVersion = 63 // equivalent eth version for the downloader

	MaxHeaderFetch           = 192 // Amount of block headers to be fetched per retrieval request
	MaxBodyFetch             = 32  // Amount of block bodies to be fetched per retrieval request
	MaxReceiptFetch          = 128 // Amount of transaction receipts to allow fetching per request
	MaxCodeFetch             = 64  // Amount of contract codes to allow fetching per request
	// 每个检索请求将获取的Merkle证明数量
	MaxProofsFetch           = 64  // Amount of merkle proofs to be fetched per retrieval request
	MaxHelperTrieProofsFetch = 64  // Amount of merkle proofs to be fetched per retrieval request
	MaxTxSend                = 64  // Amount of transactions to be send per request
	MaxTxStatus              = 256 // Amount of transactions to queried per request

	disableClientRemovePeer = false
)

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type BlockChain interface {
	Config() *params.ChainConfig
	HasHeader(hash common.Hash, number uint64) bool
	GetHeader(hash common.Hash, number uint64) *types.Header
	GetHeaderByHash(hash common.Hash) *types.Header
	CurrentHeader() *types.Header
	GetTd(hash common.Hash, number uint64) *big.Int
	State() (*state.StateDB, error)
	InsertHeaderChain(chain []*types.Header, checkFreq int) (int, error)
	Rollback(chain []common.Hash)
	GetHeaderByNumber(number uint64) *types.Header
	GetAncestor(hash common.Hash, number, ancestor uint64, maxNonCanonical *uint64) (common.Hash, uint64)
	Genesis() *types.Block
	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
}

type txPool interface {
	AddRemotes(txs []*types.Transaction) []error
	Status(hashes []common.Hash) []core.TxStatus
}

type ProtocolManager struct {
	// 是否是 轻节点
	lightSync   bool // Client: true,  Server: false
	txpool      txPool
	txrelay     *LesTxRelay
	networkId   uint64
	chainConfig *params.ChainConfig
	blockchain  BlockChain
	chainDb     ethdb.Database
	odr         *LesOdr
	// todo  只有是开启了支持轻节点连接 Server 端的全节点，才会对 pm.server 赋值
	server      *LesServer

	// todo  如果当前节点是轻节点Client 则,该值就有
	// todo 里头记录的是和当前 client链接的 server 端 (与当前client链接的server全节点)
	serverPool  *serverPool
	clientPool  *freeClientPool
	lesTopic    discv5.Topic
	// 请求分发器
	reqDist     *requestDistributor
	// 猎犬(请求分发器的更上一层)
	retriever   *retrieveManager

	// downloader 的引用
	downloader *downloader.Downloader
	// lightfetcher的引用
	fetcher    *lightFetcher
	peers      *peerSet

	// 限制当前 节点 最多可连接多少个对端peer
	maxPeers   int

	eventMux *event.TypeMux

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg *sync.WaitGroup
}

// NewProtocolManager returns a new ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the ethereum network.
func NewProtocolManager(chainConfig *params.ChainConfig, lightSync bool, networkId uint64, mux *event.TypeMux, engine consensus.Engine, peers *peerSet, blockchain BlockChain, txpool txPool, chainDb ethdb.Database, odr *LesOdr, txrelay *LesTxRelay, serverPool *serverPool, quitSync chan struct{}, wg *sync.WaitGroup) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{

		// 在当前 pm 中赋值当前节点是否为 light 节点
		lightSync:   lightSync, // todo 注意: server 端这个值 为 false
		eventMux:    mux,
		blockchain:  blockchain,
		chainConfig: chainConfig,
		chainDb:     chainDb,
		odr:         odr,
		networkId:   networkId,
		txpool:      txpool,
		txrelay:     txrelay,

		// todo 这个,如果是 轻节点的client端 (真的轻节点) 的话,才会有
		// TODO 如果是 轻节点的server端 (一个全节点) 的话,则没有
		// todo 里头记录的是和当前 client链接的 server 端
		serverPool:  serverPool,
		peers:       peers,
		newPeerCh:   make(chan *peer),
		quitSync:    quitSync,
		wg:          wg,
		noMorePeers: make(chan struct{}),
	}
	if odr != nil {
		manager.retriever = odr.retriever    // 请求分发器
		manager.reqDist = odr.retriever.dist // 猎犬 (请求分发器更上一层)
	}

	// 获取 removePeerFunc 的指针
	removePeer := manager.removePeer
	if disableClientRemovePeer {
		removePeer = func(id string) {}
	}

	if lightSync {
		/** TODO 大头 light 模式的 download 相关*/
		manager.downloader = downloader.New(downloader.LightSync, chainDb, manager.eventMux, nil, blockchain, removePeer)
		manager.peers.notify((*downloaderPeerNotify)(manager))
		manager.fetcher = newLightFetcher(manager)
	}

	return manager, nil
}

// removePeer initiates disconnection from a peer by removing it from the peer set
func (pm *ProtocolManager) removePeer(id string) {
	pm.peers.Unregister(id)
}


/**
TODO 启动 轻节点的 pm (Server/Client)
 */
func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers


	// todo 当前是Client端的话
	if pm.lightSync {
		go pm.syncer()
	} else {

		// todo 如果当前是 Server端的话
		pm.clientPool = newFreeClientPool(pm.chainDb, maxPeers, 10000, mclock.System{})
		go func() {
			for range pm.newPeerCh {
			}
		}()
	}
}

func (pm *ProtocolManager) Stop() {
	// Showing a log message. During download / process this could actually
	// take between 5 to 10 seconds and therefor feedback is required.
	log.Info("Stopping light Ethereum protocol")

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	close(pm.quitSync) // quits syncer, fetcher
	if pm.clientPool != nil {
		pm.clientPool.stop()
	}

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for any process action
	pm.wg.Wait()

	log.Info("Light Ethereum protocol stopped")
}

// runPeer is the p2p protocol run function for the given version.
//
// todo  runPeer: 是给定版本的p2p协议运行功能
func (pm *ProtocolManager) runPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter) error {
	var entry *poolEntry

	// 根据真实的 p2p 实例和 读写流等相关信息
	// 封装一个 对端peer实例
	peer := pm.newPeer(int(version), pm.networkId, p, rw)

	// todo  如果当前节点是轻节点Client 则,该值就有
	// todo 里头记录的是和当前 client链接的 server 端 (与当前client链接的server全节点)
	if pm.serverPool != nil {
		addr := p.RemoteAddr().(*net.TCPAddr)
		// todo 将当前 client 和远端的 server 建立TCP连接, 当前节点主动发起
		// 其实我耶不清楚,为毛这里还要去做 p2p? 传进来的p2p.Peer 不已经是具备了 TCP 的了么
		entry = pm.serverPool.connect(peer, addr.IP, uint16(addr.Port))
	}

	// poolEntry: 代表 服务器节点 <light的server端> 并存储其当前状态和统计信息
	peer.poolEntry = entry
	select {
	// 来一波新节点加入的通知
	case pm.newPeerCh <- peer:
		pm.wg.Add(1)
		defer pm.wg.Done()

		/**
		todo 处理轻节点 握手
		 */
		err := pm.handle(peer)

		// 最后断开? 看不懂哦
		if entry != nil {
			pm.serverPool.disconnect(entry)
		}
		return err

	// 如果退出 同步
	case <-pm.quitSync:
		if entry != nil {
			pm.serverPool.disconnect(entry)
		}
		return p2p.DiscQuitting
	}
}

func (pm *ProtocolManager) newPeer(pv int, nv uint64, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, nv, p, newMeteredMsgWriter(rw))
}

// handle is the callback invoked to manage the life cycle of a les peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer) error {
	// Ignore maxPeers if this is a trusted peer
	// In server mode we try to check into the client pool after handshake
	//
	/**
	如果是 client端 且 和对端的链接数越界 且对端不是可信任节点的话，
	则，直接返回错误
	 */
	if pm.lightSync && pm.peers.Len() >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
		return p2p.DiscTooManyPeers
	}

	p.Log().Debug("Light Ethereum peer connected", "name", p.Name())

	// Execute the LES handshake
	var (
		// 创世块
		genesis = pm.blockchain.Genesis()
		// 链上最高快 header
		head    = pm.blockchain.CurrentHeader()
		// 链上最高块对应的Hash
		hash    = head.Hash()
		// 链上最高快对应的Hash
		number  = head.Number.Uint64()
		// 当前链上的td
		td      = pm.blockchain.GetTd(hash, number)
	)


	/**
	TODO 处理 轻节点和全节点 握手 (即 tcp 的校验性链接)
	todo 只是简单的发起 握手,并没有处理 TCP 连接之后的各种消息
	todo 在 `pm.handleMsg` 这里才是真正的处理 TCP msg
	 */
	if err := p.Handshake(td, hash, number, genesis.Hash(), pm.server); err != nil {
		p.Log().Debug("Light Ethereum handshake failed", "err", err)
		return err
	}



	/**
	在 握手完了之后

	如果当前 节点 是 server 端
	且对端节点不可信,则将本地 peerSet 中的对端p移除

	 */
	if !pm.lightSync && !p.Peer.Info().Network.Trusted {
		addr, ok := p.RemoteAddr().(*net.TCPAddr)
		// test peer address is not a tcp address, don't use client pool if can not typecast
		//
		// 测试 peer 的地址不是TCP地址，如果无法进行类型转换，请不要使用客户端池
		if ok {
			id := addr.IP.String()
			if !pm.clientPool.connect(id, func() { go pm.removePeer(p.id) }) {
				return p2p.DiscTooManyPeers
			}
			defer pm.clientPool.disconnect(id)
		}
	}

	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	// Register the peer locally
	/**
	TODO 握手成功则，在当前节点的 peerSet 中注册一个对端节点的实例
	 */
	if err := pm.peers.Register(p); err != nil {
		p.Log().Error("Light Ethereum peer registration failed", "err", err)
		return err
	}
	defer func() {

		//  todo 如果是 light 的server 端(全节点) 且 client的管理相关 不为空 且 对端peer 的client字段不为空
		if pm.server != nil && pm.server.fcManager != nil && p.fcClient != nil {

			// 从fcManager中移除 对端peer的fcClient
			p.fcClient.Remove(pm.server.fcManager)
		}
		// 从pm的peerSet中移除 对端peer
		pm.removePeer(p.id)
	}()
	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	//
	// 在 downloader中注册 该对端peer。
	// 如果downloader认为它被禁止，我们将断开连接
	if pm.lightSync {
		p.lock.Lock()

		// 获取该对端 peer缓存信息中的 (可能的) headerInfo
		head := p.headInfo
		p.lock.Unlock()
		if pm.fetcher != nil {

			// todo 根据可能的 header 去在本地的 `对端peer的缓存信息` 上拉取最高块的 header 的 hash, num, td 等等 announce msg
			pm.fetcher.announce(p, head)
		}

		if p.poolEntry != nil {
			pm.serverPool.registered(p.poolEntry)
		}
	}

	stop := make(chan struct{})
	defer close(stop)

	/**
	todo 超级重要这个携程
	 */
	go func() {
		// new block announce loop
		/**
		todo 新块 广播循环
		 */
		for {
			select {
			/**
			todo 这里才是真正的
			 */
			case announce := <-p.announceChn:

				// 发送新block header 通知
				// todo 消息在 `pm.handleMsg(p)` 中被处理
				p.SendAnnounce(announce)
			case <-stop:
				return
			}
		}
	}()

	// main loop. handle incoming messages.
	for {

		/**
		TODO 这个是处理 TCP 数据消息交换
		 */
		if err := pm.handleMsg(p); err != nil {
			p.Log().Debug("Light Ethereum message handling failed", "err", err)
			return err
		}
	}
}

// TODO 轻节点的请求 集
var reqList = []uint64{GetBlockHeadersMsg, GetBlockBodiesMsg, GetCodeMsg, GetReceiptsMsg, GetProofsV1Msg, SendTxMsg, SendTxV2Msg, GetTxStatusMsg, GetHeaderProofsMsg, GetProofsV2Msg, GetHelperTrieProofsMsg}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	//
	// 读取来自 对端 peer 的下一条消息，并确保已将其完全读完
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	p.Log().Trace("Light Ethereum message arrived", "code", msg.Code, "bytes", msg.Size)


	// 根据不同的 msg.Code 获取
	costs := p.fcCosts[msg.Code]

	// reject: 拒绝
	//
	// reqCnt: req的checkpoint <这里的checkpoint 指的是, req数据的数量级, 且没特指是哪种数据>
	// maxCnt: max的checkpoint
	reject := func(reqCnt, maxCnt uint64) bool {

		// 如果该 peer 是 light 的server 端,
		// 或者 req的checkpoint > max的checkpoint
		if p.fcClient == nil || reqCnt > maxCnt {
			return true
		}

		/**
		轻节点 client 接收req !?
		 */
		// 返回peer 被允许的缓存数量大小
		// todo fcClient: 流量控制Client
		bufValue, _ := p.fcClient.AcceptRequest()

		// 计算(资源)消耗的值
		cost := costs.baseCost + reqCnt*costs.reqCost
		if cost > pm.server.defParams.BufLimit {
			cost = pm.server.defParams.BufLimit
		}

		// 如果计算出的预计消耗 令牌 > 剩余可消耗令牌
		if cost > bufValue {
			recharge := time.Duration((cost - bufValue) * 1000000 / pm.server.defParams.MinRecharge)
			p.Log().Error("Request came too early", "recharge", common.PrettyDuration(recharge))
			return true
		}
		return false
	}


	// 校验msg的大小
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}

	// TODO Discard: 会将所有剩余的有效负载数据读入黑洞
	defer msg.Discard()


	/**
	todo 交付的消息
	 */
	var deliverMsg *Msg

	// Handle the message depending on its contents
	//
	// 根据消息内容处理消息
	switch msg.Code {

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	todo 这里是接收到 握手时发起的状态查询msg

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case StatusMsg:
		p.Log().Trace("Received status message")
		// Status messages should never arrive after the handshake
		/**
		todo 握手后状态消息永远不会到达
		 */
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")

	// Block header query, collect the requested headers and reply
	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	block header 的查询，收集请求的headers并回复

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case AnnounceMsg:
		p.Log().Trace("Received announce message")
		if p.requestAnnounceType == announceTypeNone { // 这种, 基本上不会遇上,遇上的话就是异常
			return errResp(ErrUnexpectedResponse, "")
		}

		var req announceData
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}

		if p.requestAnnounceType == announceTypeSigned { // 这个也是, 因为目前没看到对这个 p.requestAnnounceType 赋值 这个的地方啊
			if err := req.checkSignature(p.pubKey); err != nil {
				p.Log().Trace("Invalid announcement signature", "err", err)
				return err
			}
			p.Log().Trace("Valid announcement signature")
		}

		p.Log().Trace("Announce message content", "number", req.Number, "hash", req.Hash, "td", req.Td, "reorg", req.ReorgDepth)

		/**
		todo 这个才是正常处理 msg
		todo 即,处理类型为 `announceTypeSimple` 的
		 */
		if pm.fetcher != nil {

			// todo fetcher 去处理 这个 对端peer过来的 新header 的广播通知msg
			// todo 将新的 header 的 hash, number 等相关的 信息追加到 odr tree 中
			pm.fetcher.announce(p, &req)
		}

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	获取 header 的req
	这个是 server 才会收到的

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case GetBlockHeadersMsg:
		p.Log().Trace("Received block header request")
		// Decode the complex header query
		var req struct {
			ReqID uint64
			Query getBlockHeadersData
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}

		query := req.Query
		if reject(query.Amount, MaxHeaderFetch) {
			return errResp(ErrRequestRejected, "")
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
		for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit {
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


		// 计算对端client 在当前节点剩余的 资源 BV
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + query.Amount*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, query.Amount, rcost)

		// reqId, BV, headers
		return p.SendBlockHeaders(req.ReqID, bv, headers)

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	接收 header 的resp
	这个是client 端接收到的

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case BlockHeadersMsg:
		if pm.downloader == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received block header response message")
		// A batch of headers arrived to one of our previous requests
		var resp struct {
			ReqID, BV uint64   // BV: Buffer Value
			Headers   []*types.Header
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		// 根据对端节点的 server 调整消耗
		p.fcServer.GotReply(resp.ReqID, resp.BV)


		// 将resp 回来的header做交付, 可能是将 header 入链
		if pm.fetcher != nil && pm.fetcher.requestedID(resp.ReqID) {
			pm.fetcher.deliverHeaders(p, resp.ReqID, resp.Headers)
		} else {

			// todo 这里交付给 downloader 去插 header了
			err := pm.downloader.DeliverHeaders(p.id, resp.Headers)
			if err != nil {
				log.Debug(fmt.Sprint(err))
			}
		}

	/**
	server 端
	les 也会去拉取 bodies
	 */
	case GetBlockBodiesMsg:
		p.Log().Trace("Received block bodies request")
		// Decode the retrieval message
		var req struct {
			ReqID  uint64
			Hashes []common.Hash
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			bytes  int
			bodies []rlp.RawValue
		)
		reqCnt := len(req.Hashes)
		if reject(uint64(reqCnt), MaxBodyFetch) {
			return errResp(ErrRequestRejected, "")
		}
		for _, hash := range req.Hashes {
			if bytes >= softResponseLimit {
				break
			}
			// Retrieve the requested block body, stopping if enough was found
			if number := rawdb.ReadHeaderNumber(pm.chainDb, hash); number != nil {
				if data := rawdb.ReadBodyRLP(pm.chainDb, hash, *number); len(data) != 0 {
					bodies = append(bodies, data)
					bytes += len(data)
				}
			}
		}
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)
		return p.SendBlockBodiesRLP(req.ReqID, bv, bodies)


	/**
	client端接收到 bodies
	 */
	case BlockBodiesMsg:
		if pm.odr == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received block bodies response")
		// A batch of block bodies arrived to one of our previous requests
		var resp struct {
			ReqID, BV uint64 // BV: Buffer Value
			Data      []*types.Body
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		// 调节 Server 资源
		p.fcServer.GotReply(resp.ReqID, resp.BV)

		/**
		交付类型
		 */
		deliverMsg = &Msg{
			MsgType: MsgBlockBodies,
			ReqID:   resp.ReqID,
			Obj:     resp.Data,
		}


	/**
	处理拉取 Code 的req
	 */
	case GetCodeMsg:
		p.Log().Trace("Received code request")
		// Decode the retrieval message
		var req struct {
			ReqID uint64
			Reqs  []CodeReq
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			bytes int
			data  [][]byte
		)
		reqCnt := len(req.Reqs)
		if reject(uint64(reqCnt), MaxCodeFetch) {
			return errResp(ErrRequestRejected, "")
		}
		for _, req := range req.Reqs {
			// Retrieve the requested state entry, stopping if enough was found
			if number := rawdb.ReadHeaderNumber(pm.chainDb, req.BHash); number != nil {
				if header := rawdb.ReadHeader(pm.chainDb, req.BHash, *number); header != nil {
					statedb, err := pm.blockchain.State()
					if err != nil {
						continue
					}
					account, err := pm.getAccount(statedb, header.Root, common.BytesToHash(req.AccKey))
					if err != nil {
						continue
					}
					code, _ := statedb.Database().TrieDB().Node(common.BytesToHash(account.CodeHash))

					data = append(data, code)
					if bytes += len(code); bytes >= softResponseLimit {
						break
					}
				}
			}
		}
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)
		return p.SendCode(req.ReqID, bv, data)

	/**
	处理拉取 code 的resp
	 */
	case CodeMsg:
		if pm.odr == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received code response")
		// A batch of node state data arrived to one of our previous requests
		var resp struct {
			ReqID, BV uint64 // BV: Buffer Value
			Data      [][]byte
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		p.fcServer.GotReply(resp.ReqID, resp.BV)
		deliverMsg = &Msg{
			MsgType: MsgCode,
			ReqID:   resp.ReqID,
			Obj:     resp.Data,
		}

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	获取 rceipt 的req

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case GetReceiptsMsg:
		p.Log().Trace("Received receipts request")
		// Decode the retrieval message
		var req struct {
			ReqID  uint64
			Hashes []common.Hash
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			bytes    int
			receipts []rlp.RawValue
		)
		reqCnt := len(req.Hashes)
		if reject(uint64(reqCnt), MaxReceiptFetch) {
			return errResp(ErrRequestRejected, "")
		}
		for _, hash := range req.Hashes {
			if bytes >= softResponseLimit {
				break
			}
			// Retrieve the requested block's receipts, skipping if unknown to us
			var results types.Receipts
			if number := rawdb.ReadHeaderNumber(pm.chainDb, hash); number != nil {
				results = rawdb.ReadReceipts(pm.chainDb, hash, *number)
			}
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
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)
		return p.SendReceiptsRLP(req.ReqID, bv, receipts)

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	处理 receipt 的resp

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case ReceiptsMsg:
		if pm.odr == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received receipts response")
		// A batch of receipts arrived to one of our previous requests
		var resp struct {
			ReqID, BV uint64 // BV: Buffer Value
			Receipts  []types.Receipts
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		p.fcServer.GotReply(resp.ReqID, resp.BV)
		deliverMsg = &Msg{
			MsgType: MsgReceipts,
			ReqID:   resp.ReqID,
			Obj:     resp.Receipts,
		}

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	todo 应该是 (odr *LesOdr) Retrieve 调用过来的
	获取 state 的proof

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	TODO 已经弃用 LPV2 用 ``
	 */
	case GetProofsV1Msg:
		p.Log().Trace("Received proofs request")
		// Decode the retrieval message
		var req struct {
			ReqID uint64
			Reqs  []ProofReq
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			bytes  int
			proofs proofsData
		)
		reqCnt := len(req.Reqs)

		// 资源不够,被拒绝请求
		if reject(uint64(reqCnt), MaxProofsFetch) {
			return errResp(ErrRequestRejected, "")
		}

		// TODO  遍历所有 proof req
		for _, req := range req.Reqs {
			// Retrieve the requested state entry, stopping if enough was found
			//
			// 如果已经拉取足够的 state 的条目了,则停止拉取
			if number := rawdb.ReadHeaderNumber(pm.chainDb, req.BHash); number != nil {
				if header := rawdb.ReadHeader(pm.chainDb, req.BHash, *number); header != nil {
					statedb, err := pm.blockchain.State()
					if err != nil {
						continue
					}

					// 构造一个 stateTrie
					var trie state.Trie

					// 查询账户信息
					if len(req.AccKey) > 0 {
						// 根据对应的该 state的root以及 accountKey 去查选账户
						account, err := pm.getAccount(statedb, header.Root, common.BytesToHash(req.AccKey))
						if err != nil {
							continue
						}

						// 再根据 账户去StorageTrie 上查会账户的整棵 StorageTrie
						trie, _ = statedb.Database().OpenStorageTrie(common.BytesToHash(req.AccKey), account.Root)
					} else {
						// 如果没有没有制定AccKey,则只表示拉回该block中的StateTrie
						trie, _ = statedb.Database().OpenTrie(header.Root)
					}


					if trie != nil {

						// TODO 这里开始构造证明
						var proof light.NodeList



						// todo 来来来,这个贼重要
						// trie的类型根据实际而定,
						// todo State中的 trie是 cachedTrie
						// todo Storage中的 trie是 SecureTrie
						//
						// todo 但是看了实现,最终的Prove 都是调用了 `SecureTrie.Prove`
						trie.Prove(req.Key, 0, &proof)


						// 追加取回来的proof (其实是各种node的rlp和sha3之后的hash值)
						proofs = append(proofs, proof)

						// 每次最多只取回 2097152
						if bytes += proof.DataSize(); bytes >= softResponseLimit {
							break
						}
					}
				}
			}
		}

		// 调整当前Server节点中对端p的client 令牌桶
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)

		// todo 将本节点组装好的proof发回client
		return p.SendProofs(req.ReqID, bv, proofs)

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	LPV2
	TODO 理论上基本都是走LPV2的了
	从远程peer获取一批Merkle证明

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case GetProofsV2Msg:
		p.Log().Trace("Received les/2 proofs request")
		// Decode the retrieval message
		var req struct {
			ReqID uint64
			Reqs  []ProofReq
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			lastBHash common.Hash
			statedb   *state.StateDB
			root      common.Hash
		)

		// 请求 checkpoint 的长度 !?
		reqCnt := len(req.Reqs)

		// 判断流量(令牌桶)控制
		if reject(uint64(reqCnt), MaxProofsFetch) {
			return errResp(ErrRequestRejected, "")
		}

		// 构建一个node的Set
		nodes := light.NewNodeSet()

		// TODO  遍历所有 proof req
		for _, req := range req.Reqs {
			// Look up the state belonging to the request
			//
			// 查找属于 req的 state
			if statedb == nil || req.BHash != lastBHash {
				statedb, root, lastBHash = nil, common.Hash{}, req.BHash

				// 如果已经拉取足够的 state 的条目了,则停止拉取
				if number := rawdb.ReadHeaderNumber(pm.chainDb, req.BHash); number != nil {
					if header := rawdb.ReadHeader(pm.chainDb, req.BHash, *number); header != nil {
						statedb, _ = pm.blockchain.State()
						root = header.Root
					}
				}
			}
			if statedb == nil {
				continue
			}
			// Pull the account or storage trie of the request
			//
			// 提取请求的帐户或存储 trie
			var trie state.Trie
			if len(req.AccKey) > 0 {
				account, err := pm.getAccount(statedb, root, common.BytesToHash(req.AccKey))
				if err != nil {
					continue
				}
				trie, _ = statedb.Database().OpenStorageTrie(common.BytesToHash(req.AccKey), account.Root)
			} else {
				trie, _ = statedb.Database().OpenTrie(root)
			}
			if trie == nil {
				continue
			}
			// Prove the user's request from the account or stroage trie
			// 填充 nodes

			// todo 来来来,这个贼重要
			// trie的类型根据实际而定,
			// todo State中的 trie是 cachedTrie
			// todo Storage中的 trie是 SecureTrie
			//
			// todo 但是看了实现,最终的Prove 都是调用了 `SecureTrie.Prove`

			// todo fromLevel大于零，则可以从证明中省略最接近根的给定数量的trie节点
			trie.Prove(req.Key, req.FromLevel, nodes)
			if nodes.DataSize() >= softResponseLimit {
				break
			}
		}
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)
		// nodes.NodeList(): 将 nodes 转化成 nodeList
		return p.SendProofsV2(req.ReqID, bv, nodes.NodeList())

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	todo client处理 LPV1 的 merkle proof 响应

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case ProofsV1Msg:
		if pm.odr == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received proofs response")
		// A batch of merkle proofs arrived to one of our previous requests
		var resp struct {
			ReqID, BV uint64 // BV: Buffer Value
			Data      []light.NodeList
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		// TODO 根据最新请求回复中包含的值来调整估计的缓冲区值
		p.fcServer.GotReply(resp.ReqID, resp.BV)

		/**
		需要被处理的交付信息
		 */
		deliverMsg = &Msg{
			MsgType: MsgProofsV1,
			ReqID:   resp.ReqID,
			Obj:     resp.Data,
		}

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	todo client处理 LPV2 的 merkle proof 响应

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case ProofsV2Msg:
		if pm.odr == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received les/2 proofs response")
		// A batch of merkle proofs arrived to one of our previous requests
		var resp struct {
			ReqID, BV uint64 // BV: Buffer Value
			Data      light.NodeList
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		// TODO 根据最新请求回复中包含的值来调整估计的缓冲区值
		p.fcServer.GotReply(resp.ReqID, resp.BV)

		/**
		需要被处理的交付信息
		*/
		deliverMsg = &Msg{
			MsgType: MsgProofsV2,
			ReqID:   resp.ReqID,
			Obj:     resp.Data,
		}


	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	Server 处理 header的proof   LPV1

	todo
		ChtRequest 和 BloomRequest 都会发起这个req

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	TODO 这个已经弃用, LPV2 用 `GetHelperTrieProofs`




	todo  CHT (0)：从Canonical Hash Trie请求密钥。如果auxReq为2，则所属标头返回为auxData。
			key是编码为8字节大字节序的块号。请注意，CHT的节大小已提高到32k，而不是4k块.

	todo  BloomBits (1)：从BloomBits Trie请求密钥。在这个Trie key中，它的长度为10个字节，
			它由将bloom bit index 编码为2字节的大字节序组成，然后是将 section index编码为8字节的大字节序。
			返回的值是相应的压缩bloom bit vector.

	 */
	case GetHeaderProofsMsg:
		p.Log().Trace("Received headers proof request")
		// Decode the retrieval message
		var req struct {
			ReqID uint64
			Reqs  []ChtReq
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			bytes  int
			proofs []ChtResp
		)
		reqCnt := len(req.Reqs)
		if reject(uint64(reqCnt), MaxHelperTrieProofsFetch) {
			return errResp(ErrRequestRejected, "")
		}
		trieDb := trie.NewDatabase(ethdb.NewTable(pm.chainDb, light.ChtTablePrefix))


		// 遍历 reqs
		for _, req := range req.Reqs {

			// 从当前 blockchain 中 <当前肯定是 全节点> 拉取 header
			if header := pm.blockchain.GetHeaderByNumber(req.BlockNum); header != nil {

				// todo 注意, server 端也是提供 CanonicalHash 的
				//
				// 读取本地db中存储的 `CanonicalHash` server 这边每隔 `4096` 去拿
				sectionHead := rawdb.ReadCanonicalHash(pm.chainDb, req.ChtNum*light.CHTFrequencyServer-1)
				// 根据Hash拉取 CHTRoot (之所以 req.ChtNum-1是因为 section的索引从0开始)
				if root := light.GetChtRoot(pm.chainDb, req.ChtNum-1, sectionHead); root != (common.Hash{}) {

					// 拉取 db 中的 Cht trie
					trie, err := trie.New(root, trieDb)
					if err != nil {
						continue
					}
					var encNumber [8]byte
					binary.BigEndian.PutUint64(encNumber[:], req.BlockNum)

					var proof light.NodeList

					// todo 填充数的 proof 路径
					trie.Prove(encNumber[:], 0, &proof)

					proofs = append(proofs, ChtResp{Header: header, Proof: proof})
					if bytes += proof.DataSize() + estHeaderRlpSize; bytes >= softResponseLimit {
						break
					}
				}
			}
		}
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)
		return p.SendHeaderProofs(req.ReqID, bv, proofs)

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	Server 处理 header的proof   LPV2


	TODO 对于 CHT
	LES服务器为每32768个块生成CHT，CHT[i]其中包含block 的数据0..i * 32768-1。
	如果客户端知道的根哈希，CHT[i]并希望获取标头号N（其中N < i * 32768），
	则可以通过GetHelperTrieProofs请求获取标头和CHT的相应Merkle证明.

	TODO 对于 BloomBit
	为了使此数据结构可按需从轻客户端获取，我们将生成的向量放在trie中。可以使用GetHelperTrieProofs消息检索此部分的部分

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case GetHelperTrieProofsMsg:
		p.Log().Trace("Received helper trie proof request")
		// Decode the retrieval message
		var req struct {
			ReqID uint64
			Reqs  []HelperTrieReq
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Gather state data until the fetch or network limits is reached
		var (
			auxBytes int
			auxData  [][]byte
		)
		reqCnt := len(req.Reqs)
		if reject(uint64(reqCnt), MaxHelperTrieProofsFetch) {
			return errResp(ErrRequestRejected, "")
		}

		var (
			lastIdx  uint64
			lastType uint
			root     common.Hash
			auxTrie  *trie.Trie
		)
		nodes := light.NewNodeSet()

		// 遍历 所有 reqs
		for _, req := range req.Reqs {
			if auxTrie == nil || req.Type != lastType || req.TrieIdx != lastIdx {
				auxTrie, lastType, lastIdx = nil, req.Type, req.TrieIdx

				var prefix string
				// 根据type 和 TrieIdx 获取
				// todo req.Type 只会有两种
				//      htBloomBits
				// 		htCanonical

				// 这里根据  num -> CanonicalHash -> CHTRoot 或者 BloomTrieRoot
				if root, prefix = pm.getHelperTrie(req.Type, req.TrieIdx); root != (common.Hash{}) {
					auxTrie, _ = trie.New(root, trie.NewDatabase(ethdb.NewTable(pm.chainDb, prefix)))
				}
			}

			/**
			todo req.AuxReq 只有两种 type
				auxRoot
				auxHeader

				这里很奇妙, 如果你拉的不是 root 那么就一定是拉 header
			 */
			if req.AuxReq == auxRoot {
				var data []byte
				if root != (common.Hash{}) {
					data = root[:]
				}
				auxData = append(auxData, data)
				auxBytes += len(data)
			} else {
				if auxTrie != nil {
					auxTrie.Prove(req.Key, req.FromLevel, nodes)
				}
				if req.AuxReq != 0 {

					// 这里 根据 num -> CanonicalHash -> header
					data := pm.getHelperTrieAuxData(req)
					auxData = append(auxData, data)
					auxBytes += len(data)
				}
			}
			if nodes.DataSize()+auxBytes >= softResponseLimit {
				break
			}
		}
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)
		return p.SendHelperTrieProofs(req.ReqID, bv, HelperTrieResps{Proofs: nodes.NodeList(), AuxData: auxData})


	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	LPV1
	Client 处理 headerProof 的resp


	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case HeaderProofsMsg:
		if pm.odr == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received headers proof response")
		var resp struct {
			ReqID, BV uint64 // BV: Buffer Value
			Data      []ChtResp
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		// 调节 server 的资源
		p.fcServer.GotReply(resp.ReqID, resp.BV)

		/**
		交付类型
		 */
		deliverMsg = &Msg{
			MsgType: MsgHeaderProofs,
			ReqID:   resp.ReqID,
			Obj:     resp.Data,
		}

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	LPV2
	Client 处理 headerProof 的resp

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	todo  auxData在GetHelperTrieProofs中返回一个 proof 集和一组 req。
			auxData列表的长度等于非零的请求数auxReq.
	 */
	case HelperTrieProofsMsg:
		if pm.odr == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received helper trie proof response")
		var resp struct {
			ReqID, BV uint64 // BV: Buffer Value
			Data      HelperTrieResps
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		/**
		调节 server 的资源
		 */
		p.fcServer.GotReply(resp.ReqID, resp.BV)

		/**
		交付类型
		 */
		deliverMsg = &Msg{
			MsgType: MsgHelperTrieProofs,
			ReqID:   resp.ReqID,
			Obj:     resp.Data,
		}

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	LPV1
	Server 接收到 client 的txs 转发

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case SendTxMsg:
		if pm.txpool == nil {
			return errResp(ErrRequestRejected, "")
		}
		// Transactions arrived, parse all of them and deliver to the pool
		var txs []*types.Transaction
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		reqCnt := len(txs)
		if reject(uint64(reqCnt), MaxTxSend) {
			return errResp(ErrRequestRejected, "")
		}

		// 将新的 txs 追加到 txpool remote 中
		pm.txpool.AddRemotes(txs)

		_, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	LPV2
	Server 接收到 Client 的 txs req 转发

	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	 */
	case SendTxV2Msg:
		if pm.txpool == nil {
			return errResp(ErrRequestRejected, "")
		}
		// Transactions arrived, parse all of them and deliver to the pool
		var req struct {
			ReqID uint64
			Txs   []*types.Transaction
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		reqCnt := len(req.Txs)
		if reject(uint64(reqCnt), MaxTxSend) {
			return errResp(ErrRequestRejected, "")
		}

		// 获取所有tx的Hash
		hashes := make([]common.Hash, len(req.Txs))
		for i, tx := range req.Txs {
			hashes[i] = tx.Hash()
		}

		// 获取所有的 tx db的索引
		stats := pm.txStatus(hashes)
		for i, stat := range stats {
			if stat.Status == core.TxStatusUnknown {

				// 如果某些 tx 确实是 pool 和 db 都 unknown的
				// 则,追加到 txpool中, 以 remote tx 的方式
				if errs := pm.txpool.AddRemotes([]*types.Transaction{req.Txs[i]}); errs[0] != nil {
					stats[i].Error = errs[0].Error()
					continue
				}
				stats[i] = pm.txStatus([]common.Hash{hashes[i]})[0]
			}
		}

		// 调节 各种资源
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)
		// TODO 将 tx的状态发送回去
		// todo 下面的 `TxStatusMsg` 有用
		return p.SendTxStatus(req.ReqID, bv, stats)

	/**
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	LPV2
	Server 收到 校验tx status 的req


	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################
	todo #################################

	要求 对端peer 返回包含所引用 tx status 的TxStatus消息。
	该消息旨在查询客户过去发送的txs。 请注意，不需要服务器使每个tx无限期可用.
	 */
	case GetTxStatusMsg:
		if pm.txpool == nil {
			return errResp(ErrUnexpectedResponse, "")
		}
		// Transactions arrived, parse all of them and deliver to the pool
		var req struct {
			ReqID  uint64
			Hashes []common.Hash
		}
		if err := msg.Decode(&req); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		reqCnt := len(req.Hashes)
		if reject(uint64(reqCnt), MaxTxStatus) {
			return errResp(ErrRequestRejected, "")
		}
		bv, rcost := p.fcClient.RequestProcessed(costs.baseCost + uint64(reqCnt)*costs.reqCost)
		pm.server.fcCostStats.update(msg.Code, uint64(reqCnt), rcost)

		// 回应 tx Status
		// todo 下面的 `TxStatusMsg` 有用
		return p.SendTxStatus(req.ReqID, bv, pm.txStatus(req.Hashes))

	/**
	LPV2
	Client 处理 jiaoyan tx status 的 resp

	TODO  貌似没鸡吊 用
	 */
	case TxStatusMsg:
		if pm.odr == nil {
			return errResp(ErrUnexpectedResponse, "")
		}

		p.Log().Trace("Received tx status response")
		var resp struct {
			ReqID, BV uint64 // BV: Buffer Value
			Status    []txStatus
		}
		if err := msg.Decode(&resp); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		// 调整 server 的资源
		p.fcServer.GotReply(resp.ReqID, resp.BV)

	default:
		p.Log().Trace("Received unknown message", "code", msg.Code)
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}



	/**
	todo 这里是 将被需要交付的 data做处理
	 */
	if deliverMsg != nil {
		err := pm.retriever.deliver(p, deliverMsg)
		if err != nil {
			p.responseErrors++
			// 为毛大于 50 个resp err时,返回最后一个 err !?
			if p.responseErrors > maxResponseErrors {
				return err
			}
		}
	}
	return nil
}

// getAccount retrieves an account from the state based at root.
func (pm *ProtocolManager) getAccount(statedb *state.StateDB, root, hash common.Hash) (state.Account, error) {
	trie, err := trie.New(root, statedb.Database().TrieDB())
	if err != nil {
		return state.Account{}, err
	}
	blob, err := trie.TryGet(hash[:])
	if err != nil {
		return state.Account{}, err
	}
	var account state.Account
	if err = rlp.DecodeBytes(blob, &account); err != nil {
		return state.Account{}, err
	}
	return account, nil
}

// getHelperTrie returns the post-processed trie root for the given trie ID and section index
func (pm *ProtocolManager) getHelperTrie(id uint, idx uint64) (common.Hash, string) {
	switch id {
	case htCanonical:
		sectionHead := rawdb.ReadCanonicalHash(pm.chainDb, (idx+1)*light.CHTFrequencyClient-1)
		return light.GetChtV2Root(pm.chainDb, idx, sectionHead), light.ChtTablePrefix
	case htBloomBits:
		sectionHead := rawdb.ReadCanonicalHash(pm.chainDb, (idx+1)*light.BloomTrieFrequency-1)
		return light.GetBloomTrieRoot(pm.chainDb, idx, sectionHead), light.BloomTrieTablePrefix
	}
	return common.Hash{}, ""
}

// getHelperTrieAuxData returns requested auxiliary data for the given HelperTrie request
//
// getHelperTrieAuxData:
// 返回给定HelperTrie请求的请求辅助数据
func (pm *ProtocolManager) getHelperTrieAuxData(req HelperTrieReq) []byte {
	if req.Type == htCanonical && req.AuxReq == auxHeader && len(req.Key) == 8 {
		blockNum := binary.BigEndian.Uint64(req.Key)
		hash := rawdb.ReadCanonicalHash(pm.chainDb, blockNum)
		return rawdb.ReadHeaderRLP(pm.chainDb, hash, blockNum)
	}
	return nil
}

func (pm *ProtocolManager) txStatus(hashes []common.Hash) []txStatus {
	stats := make([]txStatus, len(hashes))
	for i, stat := range pm.txpool.Status(hashes) {
		// Save the status we've got from the transaction pool
		stats[i].Status = stat

		// If the transaction is unknown to the pool, try looking it up locally
		//
		// 如果该交易在txpool中没找到,则尝试去db查找
		if stat == core.TxStatusUnknown {
			// 如果db可以找到得到
			if block, number, index := rawdb.ReadTxLookupEntry(pm.chainDb, hashes[i]); block != (common.Hash{}) {

				// 将status 标识为 Included, 已经包含在db中
				stats[i].Status = core.TxStatusIncluded
				stats[i].Lookup = &rawdb.TxLookupEntry{BlockHash: block, BlockIndex: number, Index: index}
			}
		}
	}
	return stats
}

// downloaderPeerNotify implements peerSetNotify
// peerSetNotify 的一个实现
type downloaderPeerNotify ProtocolManager

type peerConnection struct {
	manager *ProtocolManager
	peer    *peer
}

func (pc *peerConnection) Head() (common.Hash, *big.Int) {
	return pc.peer.HeadAndTd()
}

func (pc *peerConnection) RequestHeadersByHash(origin common.Hash, amount int, skip int, reverse bool) error {
	reqID := genReqID()
	rq := &distReq{
		getCost: func(dp distPeer) uint64 {
			peer := dp.(*peer)
			return peer.GetRequestCost(GetBlockHeadersMsg, amount)
		},
		canSend: func(dp distPeer) bool {
			return dp.(*peer) == pc.peer
		},
		request: func(dp distPeer) func() {
			peer := dp.(*peer)
			cost := peer.GetRequestCost(GetBlockHeadersMsg, amount)
			peer.fcServer.QueueRequest(reqID, cost)
			return func() { peer.RequestHeadersByHash(reqID, cost, origin, amount, skip, reverse) }
		},
	}
	_, ok := <-pc.manager.reqDist.queue(rq)
	if !ok {
		return light.ErrNoPeers
	}
	return nil
}

func (pc *peerConnection) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool) error {
	reqID := genReqID()
	rq := &distReq{
		getCost: func(dp distPeer) uint64 {
			peer := dp.(*peer)
			return peer.GetRequestCost(GetBlockHeadersMsg, amount)
		},
		canSend: func(dp distPeer) bool {
			return dp.(*peer) == pc.peer
		},
		request: func(dp distPeer) func() {
			peer := dp.(*peer)
			cost := peer.GetRequestCost(GetBlockHeadersMsg, amount)
			peer.fcServer.QueueRequest(reqID, cost)
			return func() { peer.RequestHeadersByNumber(reqID, cost, origin, amount, skip, reverse) }
		},
	}
	_, ok := <-pc.manager.reqDist.queue(rq)
	if !ok {
		return light.ErrNoPeers
	}
	return nil
}

func (d *downloaderPeerNotify) registerPeer(p *peer) {
	pm := (*ProtocolManager)(d)
	pc := &peerConnection{
		manager: pm,
		peer:    p,
	}
	pm.downloader.RegisterLightPeer(p.id, ethVersion, pc)
}

func (d *downloaderPeerNotify) unregisterPeer(p *peer) {
	pm := (*ProtocolManager)(d)
	pm.downloader.UnregisterPeer(p.id)
}
