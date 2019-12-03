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
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/eth"
	"github.com/go-ethereum-analysis/les/flowcontrol"
	"github.com/go-ethereum-analysis/light"
	"github.com/go-ethereum-analysis/p2p"
	"github.com/go-ethereum-analysis/rlp"
)

var (
	errClosed            = errors.New("peer set is closed")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
)

const maxResponseErrors = 50 // number of invalid responses tolerated (makes the protocol less brittle but still avoids spam)

const (
	announceTypeNone = iota
	announceTypeSimple  // 默认的 响应 通知类型, 请求 通知类型
	announceTypeSigned
)

// light 模式下的节点实例
type peer struct {
	*p2p.Peer
	pubKey *ecdsa.PublicKey

	rw p2p.MsgReadWriter

	version int    // Protocol version negotiated
	network uint64 // Network ID being on

	// 响应 通知类型, 请求 通知类型
	// todo announceType: 如果是 轻节点的server 端,则默认是: announceTypeSimple
	// todo requestAnnounceType: 默认也是这模式
	announceType, requestAnnounceType uint64

	id string

	// 设置当前 peer 的通知类型?
	// 就是当前节点的 td / currentHead Hash/ currentHead num
	headInfo *announceData
	lock     sync.RWMutex

	announceChn chan announceData

	// 一个 func 队列
	sendQueue   *execQueue

	// poolEntry: 代表 服务器节点 <light的server端> 并存储其当前状态和统计信息
	poolEntry      *poolEntry
	hasBlock       func(common.Hash, uint64) bool
	responseErrors int

	// 如果peer 是server的话,则该值为nil
	// todo fcClient: 流量控制Client
	fcClient       *flowcontrol.ClientNode // nil if the peer is server only
	// 如果peer 是client的话,则该值为nil
	// todo fcServer: 流量控制Server
	fcServer       *flowcontrol.ServerNode // nil if the peer is client only

	// todo 流量控制的Server参数
	fcServerParams *flowcontrol.ServerParams

	// todo 记录req的消耗表
	fcCosts        requestCostTable
}

func newPeer(version int, network uint64, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	id := p.ID()
	pubKey, _ := id.Pubkey()

	return &peer{
		Peer:        p,
		pubKey:      pubKey,
		rw:          rw,
		version:     version,
		network:     network,
		id:          fmt.Sprintf("%x", id[:8]),
		announceChn: make(chan announceData, 20),
	}
}

func (p *peer) canQueue() bool {
	return p.sendQueue.canQueue()
}

func (p *peer) queueSend(f func()) {
	p.sendQueue.queue(f)
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *peer) Info() *eth.PeerInfo {
	return &eth.PeerInfo{
		Version:    p.version,
		Difficulty: p.Td(),
		Head:       fmt.Sprintf("%x", p.Head()),
	}
}

// Head retrieves a copy of the current head (most recent) hash of the peer.
func (p *peer) Head() (hash common.Hash) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	copy(hash[:], p.headInfo.Hash[:])
	return hash
}

func (p *peer) HeadAndTd() (hash common.Hash, td *big.Int) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	copy(hash[:], p.headInfo.Hash[:])
	return hash, p.headInfo.Td
}

func (p *peer) headBlockInfo() blockInfo {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return blockInfo{Hash: p.headInfo.Hash, Number: p.headInfo.Number, Td: p.headInfo.Td}
}

// Td retrieves the current total difficulty of a peer.
func (p *peer) Td() *big.Int {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return new(big.Int).Set(p.headInfo.Td)
}

// waitBefore implements distPeer interface
func (p *peer) waitBefore(maxCost uint64) (time.Duration, float64) {
	return p.fcServer.CanSend(maxCost)
}

func sendRequest(w p2p.MsgWriter, msgcode, reqID, cost uint64, data interface{}) error {
	type req struct {
		ReqID uint64
		Data  interface{}
	}
	return p2p.Send(w, msgcode, req{reqID, data})
}

func sendResponse(w p2p.MsgWriter, msgcode, reqID, bv uint64, data interface{}) error {
	type resp struct {
		ReqID, BV uint64 // BV: Buffer Value
		Data      interface{}
	}
	return p2p.Send(w, msgcode, resp{reqID, bv, data})
}

func (p *peer) GetRequestCost(msgcode uint64, amount int) uint64 {
	p.lock.RLock()
	defer p.lock.RUnlock()

	cost := p.fcCosts[msgcode].baseCost + p.fcCosts[msgcode].reqCost*uint64(amount)
	if cost > p.fcServerParams.BufLimit {
		cost = p.fcServerParams.BufLimit
	}
	return cost
}

// HasBlock checks if the peer has a given block
func (p *peer) HasBlock(hash common.Hash, number uint64) bool {
	p.lock.RLock()
	hasBlock := p.hasBlock
	p.lock.RUnlock()
	return hasBlock != nil && hasBlock(hash, number)
}

// SendAnnounce announces the availability of a number of blocks through
// a hash notification.
// todo 发送新block header 通知
func (p *peer) SendAnnounce(request announceData) error {
	return p2p.Send(p.rw, AnnounceMsg, request)
}

// SendBlockHeaders sends a batch of block headers to the remote peer.
func (p *peer) SendBlockHeaders(reqID, bv uint64, headers []*types.Header) error {
	return sendResponse(p.rw, BlockHeadersMsg, reqID, bv, headers)
}

// SendBlockBodiesRLP sends a batch of block contents to the remote peer from
// an already RLP encoded format.
func (p *peer) SendBlockBodiesRLP(reqID, bv uint64, bodies []rlp.RawValue) error {
	return sendResponse(p.rw, BlockBodiesMsg, reqID, bv, bodies)
}

// SendCodeRLP sends a batch of arbitrary internal data, corresponding to the
// hashes requested.
func (p *peer) SendCode(reqID, bv uint64, data [][]byte) error {
	return sendResponse(p.rw, CodeMsg, reqID, bv, data)
}

// SendReceiptsRLP sends a batch of transaction receipts, corresponding to the
// ones requested from an already RLP encoded format.
func (p *peer) SendReceiptsRLP(reqID, bv uint64, receipts []rlp.RawValue) error {
	return sendResponse(p.rw, ReceiptsMsg, reqID, bv, receipts)
}

// SendProofs sends a batch of legacy LES/1 merkle proofs, corresponding to the ones requested.
func (p *peer) SendProofs(reqID, bv uint64, proofs proofsData) error {
	return sendResponse(p.rw, ProofsV1Msg, reqID, bv, proofs)
}

// SendProofsV2 sends a batch of merkle proofs, corresponding to the ones requested.
func (p *peer) SendProofsV2(reqID, bv uint64, proofs light.NodeList) error {
	return sendResponse(p.rw, ProofsV2Msg, reqID, bv, proofs)
}

// SendHeaderProofs sends a batch of legacy LES/1 header proofs, corresponding to the ones requested.
func (p *peer) SendHeaderProofs(reqID, bv uint64, proofs []ChtResp) error {
	return sendResponse(p.rw, HeaderProofsMsg, reqID, bv, proofs)
}

// SendHelperTrieProofs sends a batch of HelperTrie proofs, corresponding to the ones requested.
func (p *peer) SendHelperTrieProofs(reqID, bv uint64, resp HelperTrieResps) error {
	return sendResponse(p.rw, HelperTrieProofsMsg, reqID, bv, resp)
}

// SendTxStatus sends a batch of transaction status records, corresponding to the ones requested.
func (p *peer) SendTxStatus(reqID, bv uint64, stats []txStatus) error {
	return sendResponse(p.rw, TxStatusMsg, reqID, bv, stats)
}

// RequestHeadersByHash fetches a batch of blocks' headers corresponding to the
// specified header query, based on the hash of an origin block.
//
// 根据Hash 去拿 header
func (p *peer) RequestHeadersByHash(reqID, cost uint64, origin common.Hash, amount int, skip int, reverse bool) error {
	p.Log().Debug("Fetching batch of headers", "count", amount, "fromhash", origin, "skip", skip, "reverse", reverse)
	return sendRequest(p.rw, GetBlockHeadersMsg, reqID, cost, &getBlockHeadersData{Origin: hashOrNumber{Hash: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse})
}

// RequestHeadersByNumber fetches a batch of blocks' headers corresponding to the
// specified header query, based on the number of an origin block.
func (p *peer) RequestHeadersByNumber(reqID, cost, origin uint64, amount int, skip int, reverse bool) error {
	p.Log().Debug("Fetching batch of headers", "count", amount, "fromnum", origin, "skip", skip, "reverse", reverse)
	return sendRequest(p.rw, GetBlockHeadersMsg, reqID, cost, &getBlockHeadersData{Origin: hashOrNumber{Number: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse})
}

// RequestBodies fetches a batch of blocks' bodies corresponding to the hashes
// specified.
func (p *peer) RequestBodies(reqID, cost uint64, hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of block bodies", "count", len(hashes))
	return sendRequest(p.rw, GetBlockBodiesMsg, reqID, cost, hashes)
}

// RequestCode fetches a batch of arbitrary data from a node's known state
// data, corresponding to the specified hashes.
func (p *peer) RequestCode(reqID, cost uint64, reqs []CodeReq) error {
	p.Log().Debug("Fetching batch of codes", "count", len(reqs))
	return sendRequest(p.rw, GetCodeMsg, reqID, cost, reqs)
}

// RequestReceipts fetches a batch of transaction receipts from a remote node.
func (p *peer) RequestReceipts(reqID, cost uint64, hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of receipts", "count", len(hashes))
	return sendRequest(p.rw, GetReceiptsMsg, reqID, cost, hashes)
}

// RequestProofs fetches a batch of merkle proofs from a remote node.
//
/**
RequestProofs: 从远程peer获取一批Merkle证明
 */
func (p *peer) RequestProofs(reqID, cost uint64, reqs []ProofReq) error {
	p.Log().Debug("Fetching batch of proofs", "count", len(reqs))
	switch p.version {
	case lpv1:
		return sendRequest(p.rw, GetProofsV1Msg, reqID, cost, reqs)
	case lpv2:
		return sendRequest(p.rw, GetProofsV2Msg, reqID, cost, reqs)
	default:
		panic(nil)
	}
}

// RequestHelperTrieProofs fetches a batch of HelperTrie merkle proofs from a remote node.
//
/**
RequestHelperTrieProofs: 从远程节点获取一批HelperTrie merkle证明.

todo 不管是 ChtIndexer的`ChtRequest` 或者是 BloomTrieIndexer的`BloomRequest` 都走这个
 */
func (p *peer) RequestHelperTrieProofs(reqID, cost uint64, reqs []HelperTrieReq) error {
	p.Log().Debug("Fetching batch of HelperTrie proofs", "count", len(reqs))

	// 查看对端peer协议版本
	switch p.version {
	case lpv1:
		reqsV1 := make([]ChtReq, len(reqs))
		for i, req := range reqs {
			if req.Type != htCanonical || req.AuxReq != auxHeader || len(req.Key) != 8 {
				return fmt.Errorf("Request invalid in LES/1 mode")
			}
			blockNum := binary.BigEndian.Uint64(req.Key)
			// convert HelperTrie request to old CHT request
			//
			// 将HelperTrie请求转换为旧的CHT请求
			reqsV1[i] = ChtReq{ChtNum: (req.TrieIdx + 1) * (light.CHTFrequencyClient / light.CHTFrequencyServer), BlockNum: blockNum, FromLevel: req.FromLevel}
		}
		return sendRequest(p.rw, GetHeaderProofsMsg, reqID, cost, reqsV1)
	case lpv2:
		return sendRequest(p.rw, GetHelperTrieProofsMsg, reqID, cost, reqs)
	default:
		panic(nil)
	}
}

// RequestTxStatus fetches a batch of transaction status records from a remote node.
//
/**
 todo RequestTxStatus:
		从远程 peer 获取一批 txs 状态记录  (貌似没人调用)
 */
func (p *peer) RequestTxStatus(reqID, cost uint64, txHashes []common.Hash) error {
	p.Log().Debug("Requesting transaction status", "count", len(txHashes))
	return sendRequest(p.rw, GetTxStatusMsg, reqID, cost, txHashes)
}

// SendTxStatus sends a batch of transactions to be added to the remote transaction pool.
//
/**
todo
	SendTxStatus发送一批要添加到远程 peer的 txpool中的 txs
 */
func (p *peer) SendTxs(reqID, cost uint64, txs types.Transactions) error {
	p.Log().Debug("Fetching batch of transactions", "count", len(txs))
	switch p.version {
	case lpv1:

		// 旧 msg 格式不包含reqID
		return p2p.Send(p.rw, SendTxMsg, txs) // old message format does not include reqID
	case lpv2:

		// todo 后面以太坊都用这个
		return sendRequest(p.rw, SendTxV2Msg, reqID, cost, txs)
	default:
		panic(nil)
	}
}

type keyValueEntry struct {
	Key   string
	Value rlp.RawValue
}
type keyValueList []keyValueEntry
type keyValueMap map[string]rlp.RawValue

func (l keyValueList) add(key string, val interface{}) keyValueList {
	var entry keyValueEntry
	entry.Key = key
	if val == nil {
		val = uint64(0)
	}
	enc, err := rlp.EncodeToBytes(val)
	if err == nil {
		entry.Value = enc
	}
	return append(l, entry)
}

func (l keyValueList) decode() keyValueMap {
	m := make(keyValueMap)
	for _, entry := range l {
		m[entry.Key] = entry.Value
	}
	return m
}

func (m keyValueMap) get(key string, val interface{}) error {
	enc, ok := m[key]
	if !ok {
		return errResp(ErrMissingKey, "%s", key)
	}
	if val == nil {
		return nil
	}
	return rlp.DecodeBytes(enc, val)
}


// 处理 P2P 的 Send和Receive 列表
func (p *peer) sendReceiveHandshake(sendList keyValueList) (keyValueList, error) {
	// Send out own handshake in a new thread
	// 在新线程中发送自己的握手
	errc := make(chan error, 1)
	go func() {

		/**
		发送 Status
		 */
		errc <- p2p.Send(p.rw, StatusMsg, sendList)
	}()
	// In the mean time retrieve the remote status message
	// 同时 拉取 远程状态消息
	// 即: 接收响应的详细
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return nil, err
	}

	if msg.Code != StatusMsg {
		return nil, errResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}
	if msg.Size > ProtocolMaxMsgSize {
		return nil, errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}


	// Decode the handshake
	//
	// 解码握手
	var recvList keyValueList
	if err := msg.Decode(&recvList); err != nil {
		return nil, errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	return recvList, nil
}

// Handshake executes the les protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
/**
握手执行les协议握手，协议版本号，网络ID，困难，头部和创世块块。
 */
func (p *peer) Handshake(td *big.Int, head common.Hash, headNum uint64, genesis common.Hash, server *LesServer) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	// TODO 握手时声明的3个参数为：
	//
	// todo 在server(全节点)对client(轻节点)提供服务，
	// todo 在双方建立连接握手时，server会声名 [3个流量控制参数]，
	// todo 如果在服务过程中，client不遵守协议，client将会被终止服务。
	//
	// Buffer Limit
	// Maximum Request Cost table
	// Minimum Rate of Recharge
	//
	// MaxCostTablle，client在本地同样维护令牌桶，然后去判断本地令牌里面有没有这么多令牌让它发送请求，如果没有的话就不应该向server发送这个请求.
	//
	// 在server端显得更为复杂，因为server给client都是最低配置参数 ，比如最慢恢复速度。
	// server处理请求有较为精确的计算公式，我们保证公式结果不会大于查询得到的结果。此外，
	// 当server发现它的资源被闲置时会给client更快令牌速度，所以server端同时维护两个令牌桶.


	// 收集 各种握手时的参数
	var send keyValueList
	send = send.add("protocolVersion", uint64(p.version))   // 协议的版本
	send = send.add("networkId", p.network)		// 网络Id
	send = send.add("headTd", td)			// 最佳chain head的总难度
	send = send.add("headHash", head)   // 最佳的 head 的 hash
	send = send.add("headNum", headNum) // 最佳的 head 的 num
	send = send.add("genesisHash", genesis) // genesisHash
	if server != nil {
		send = send.add("serveHeaders", nil) // （空值）：如果 对端peer 可以提供标题链下载，则显示
		send = send.add("serveChainSince", uint64(0)) // 存在，如果 对端peer 可以从给定的 block num 开始服务于 header / receipt 的ODR请求
		send = send.add("serveStateSince", uint64(0)) // 存在，如果 对端peer 可以从给定的 block num 开始服务于 proof / code 的ODR请求
		send = send.add("txRelay", nil)  // （无值）：如果 对端peer 可以将交易中继到ETH网络，则显示
		send = send.add("flowControl/BL", server.defParams.BufLimit)    // TODO 握手的 Buffer Limit   缓冲区限制
		send = send.add("flowControl/MRR", server.defParams.MinRecharge)// TODO 握手时 Minimum Rate of Recharge   最小充电率
		list := server.fcCostStats.getCurrentList()
		// todo 此参数的值是一个表，该表为LES协议中的每个按需检索消息分配成本值。该表被编码为整数三元组的列表：[[MsgCode, BaseCost, ReqCost], ...]
		send = send.add("flowControl/MRC", list)   // TODO 握手时的 Maximum Request Cost table    最大请求费用表

		/**
		todo Server:
			当客户端连接时，服务器将客户端的初始Buffer Value（BV）设置为BL, BL在Status中进行声明。
			从客户端收到请求后， server会根据自己的估算值计算成本
			（但不高于MaxCost，等于  BaseCost + ReqCost * N ，其中N是请求中所请求的单个元素的数量），
			然后从中扣除BV。
			如果结果为BV负，则丢弃对等方，否则开始处理请求。
			回复消息中包含一个BV值，该值是先前计算的值BV加上在服务时间中所充值的金额。
			请注意，由于 Server 始终可以确定请求的最大费用（不超过MaxCost）（并且客户端不应承担其他费用）.
			如果在BV <MaxCost时收到消息，Server可以拒绝一条消息而不对其进行处理，因为这已经是流控制违规.



		todo Client:
				Client始终对其当前BV具有最低的估计值，称为BLE
					1) 将BLE设置为Status中收到的BL
					2) BLE <MaxCost时，不向服务器发送任何请求
					3) MaxCost在发送请求时推断
					4) 小于BL时以MRR速率对BLE充电
				当收到具有新的BV值的回复消息, 它将BLE设置为BV-Sum（MaxCost），对属于此回复的请求之后发送的请求的MaxCost值求和
		 */


		p.fcCosts = list.decode()
	} else {

		// 设置为默认，直到实现“非常轻巧”客户端模式
		p.requestAnnounceType = announceTypeSimple // set to default until "very light" client mode is implemented
		send = send.add("announceType", p.requestAnnounceType)
	}

	/**
	TODO 这里处理 p2p 的 send/receive
	 */
	recvList, err := p.sendReceiveHandshake(send)
	if err != nil {
		return err
	}

	// 将 slice 转成 map
	recv := recvList.decode()

	// 读取对端peer的 resp 中的gensis 和 链上最高块的Hash
	var rGenesis, rHash common.Hash
	// 读取对端peer 的p2p version 和 networkId 和链上最高块的num
	var rVersion, rNetwork, rNum uint64
	var rTd *big.Int

	// 获取必须的对端响应回来的p2p信息
	if err := recv.get("protocolVersion", &rVersion); err != nil {
		return err
	}
	if err := recv.get("networkId", &rNetwork); err != nil {
		return err
	}
	if err := recv.get("headTd", &rTd); err != nil {
		return err
	}
	if err := recv.get("headHash", &rHash); err != nil {
		return err
	}
	if err := recv.get("headNum", &rNum); err != nil {
		return err
	}
	if err := recv.get("genesisHash", &rGenesis); err != nil {
		return err
	}

	// 做一下必须的几个参数的合法性校验
	if rGenesis != genesis {
		return errResp(ErrGenesisBlockMismatch, "%x (!= %x)", rGenesis[:8], genesis[:8])
	}
	if rNetwork != p.network {
		return errResp(ErrNetworkIdMismatch, "%d (!= %d)", rNetwork, p.network)
	}
	if int(rVersion) != p.version {
		return errResp(ErrProtocolVersionMismatch, "%d (!= %d)", rVersion, p.version)
	}


	// 根据条件 选择性的获取 参数
	// todo 如果 `当前` 本地节点是 server (即: 全节点)
	if server != nil {
		// until we have a proper peer connectivity API, allow LES connection to other servers
		/*if recv.get("serveStateSince", nil) == nil {
			return errResp(ErrUselessPeer, "wanted client, got server")
		}*/
		if recv.get("announceType", &p.announceType) != nil {

			// todo 如果是 轻节点的server 端,则默认是: announceTypeSimple
			p.announceType = announceTypeSimple
		}
		// todo 则，确认 `对端节点实例 p` 是 client
		p.fcClient = flowcontrol.NewClientNode(server.fcManager, server.defParams)
	} else {

		// todo 如果当前节点是 client的话
		if recv.get("serveChainSince", nil) != nil {
			return errResp(ErrUselessPeer, "peer cannot serve chain")
		}
		if recv.get("serveStateSince", nil) != nil {
			return errResp(ErrUselessPeer, "peer cannot serve state")
		}
		if recv.get("txRelay", nil) != nil {
			return errResp(ErrUselessPeer, "peer cannot relay transactions")
		}
		params := &flowcontrol.ServerParams{}
		if err := recv.get("flowControl/BL", &params.BufLimit); err != nil { // 轻节点握手中重要参数之一
			return err
		}
		if err := recv.get("flowControl/MRR", &params.MinRecharge); err != nil { // 轻节点握手中重要参数之二
			return err
		}
		var MRC RequestCostList
		if err := recv.get("flowControl/MRC", &MRC); err != nil { // 轻节点握手中重要参数之三
			return err
		}
		p.fcServerParams = params
		// todo 否则，确认 `对端节点实例 p` 是 server
		p.fcServer = flowcontrol.NewServerNode(params)
		p.fcCosts = MRC.decode()
	}

	// 组装对端节点的 block的当前 head信息
	p.headInfo = &announceData{Td: rTd, Hash: rHash, Number: rNum}
	return nil
}

// String implements fmt.Stringer.
func (p *peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("les/%d", p.version),
	)
}

// peerSetNotify is a callback interface to notify services about added or
// removed peers
/**
peerSetNotify是一个回调接口，用于通知服务有关已添加或已删除的peer

目前有四种实现

LesTxRelay
downloaderPeerNotify (真实类型是: ProtocolManager)
requestDistributor
lightFetcher

 */
type peerSetNotify interface {
	registerPeer(*peer)
	unregisterPeer(*peer)
}

// peerSet represents the collection of active peers currently participating in
// the Light Ethereum sub-protocol.
type peerSet struct {
	peers      map[string]*peer
	lock       sync.RWMutex
	// 记录所有发过 notify 通知给 peerSet中的peer 的 notify实例
	notifyList []peerSetNotify
	closed     bool
}

// newPeerSet creates a new peer set to track the active participants.
func newPeerSet() *peerSet {
	return &peerSet{
		peers: make(map[string]*peer),
	}
}

// notify adds a service to be notified about added or removed peers
/**
notify
添加一项服务，以通知有关已添加或已删除的peer
 */
func (ps *peerSet) notify(n peerSetNotify) {
	ps.lock.Lock()
	ps.notifyList = append(ps.notifyList, n)

	// 初始化一个 peer 的切片， 长度等于 peerSet的长度
	peers := make([]*peer, 0, len(ps.peers))

	// 逐个将peerSet中的peer添加到 该切片中，以便下面 for 调用
	// 为什么需要先加到 切片中再for 切片，而不是直接for peerSet ？
	// 因为 peerSet 无时不刻都可能有新的peer加进来，而n.registerPeer的调用时间可能很久，
	// 逐个调用的话还需要在 lock 中做，就会导致这个lock 会很长
	// 但是在lock中直接做 append 耗时很快
	// todo 还有一种好的写法是，在lock中启用 goroutine 调用 n.registerPeer
	// (相当于取了个 peerSet 的快照)
	for _, p := range ps.peers {
		peers = append(peers, p)
	}
	ps.lock.Unlock()

	for _, p := range peers {
		// 调用 Notify实例 逐个注册 peerSet中的 peer
		n.registerPeer(p)
	}
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known.
/**
Register: 将一个新的 peer 注入工作集中 (peerSet)，或者如果已知该 peer，则返回错误
 */
func (ps *peerSet) Register(p *peer) error {
	ps.lock.Lock()
	if ps.closed {
		ps.lock.Unlock()
		return errClosed
	}
	if _, ok := ps.peers[p.id]; ok {
		ps.lock.Unlock()
		return errAlreadyRegistered
	}

	// 如果 peer 还未存在,则加入 peerSet中
	ps.peers[p.id] = p

	// 创建一个 func 队列实例
	// 该队列在创建的同时就已经进入 监听阶段了
	p.sendQueue = newExecQueue(100)
	peers := make([]peerSetNotify, len(ps.notifyList))
	copy(peers, ps.notifyList)
	ps.lock.Unlock()

	// 每一次有新的peer注册到pm的时候,都需要将peer 逐个注册到 对应改的 notify 实现上
	for _, n := range peers {
		n.registerPeer(p)
	}
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity. It also initiates disconnection at the networking layer.
func (ps *peerSet) Unregister(id string) error {
	ps.lock.Lock()
	if p, ok := ps.peers[id]; !ok {
		ps.lock.Unlock()
		return errNotRegistered
	} else {

		// 先从pm的peerSet中删除对应pid的peer
		delete(ps.peers, id)
		peers := make([]peerSetNotify, len(ps.notifyList))
		copy(peers, ps.notifyList)
		ps.lock.Unlock()

		// 每一次有peer被移除时,都需要逐个到对应的 notify 上面去移除掉
		for _, n := range peers {
			n.unregisterPeer(p)
		}
		// 将该peer 的func 执行队列关闭
		p.sendQueue.quit()
		// 断开对端peer 的链接
		p.Peer.Disconnect(p2p.DiscUselessPeer)
		return nil
	}
}

// AllPeerIDs returns a list of all registered peer IDs
func (ps *peerSet) AllPeerIDs() []string {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	res := make([]string, len(ps.peers))
	idx := 0
	for id := range ps.peers {
		res[idx] = id
		idx++
	}
	return res
}

// Peer retrieves the registered peer with the given id.
func (ps *peerSet) Peer(id string) *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.peers[id]
}

// Len returns if the current number of peers in the set.
func (ps *peerSet) Len() int {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return len(ps.peers)
}

// BestPeer retrieves the known peer with the currently highest total difficulty.
func (ps *peerSet) BestPeer() *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	var (
		bestPeer *peer
		bestTd   *big.Int
	)
	for _, p := range ps.peers {
		if td := p.Td(); bestPeer == nil || td.Cmp(bestTd) > 0 {
			bestPeer, bestTd = p, td
		}
	}
	return bestPeer
}

// AllPeers returns all peers in a list
func (ps *peerSet) AllPeers() []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, len(ps.peers))
	i := 0
	for _, peer := range ps.peers {
		list[i] = peer
		i++
	}
	return list
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (ps *peerSet) Close() {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	for _, p := range ps.peers {
		p.Disconnect(p2p.DiscQuitting)
	}
	ps.closed = true
}
