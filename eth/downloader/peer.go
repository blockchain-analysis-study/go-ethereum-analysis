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

// Contains the active peer-set of the downloader, maintaining both failures
// as well as reputation metrics to prioritize the block retrievals.

package downloader

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/event"
	"github.com/go-ethereum-analysis/log"
)

const (
	maxLackingHashes  = 4096 // Maximum number of entries allowed on the list or lacking items
	measurementImpact = 0.1  // The impact a single measurement has on a peer's final throughput value.
)

var (
	errAlreadyFetching   = errors.New("already fetching blocks from peer")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
)

// peerConnection represents an active peer from which hashes and blocks are retrieved.
//
/**
peerConnection表示一个活动peer，可从中检索 Hash和 Block。
 */
type peerConnection struct {
	id string // Unique identifier of the peer

	// 对端peer的当前 header的活动状态
	headerIdle  int32 // Current header activity state of the peer (idle = 0, active = 1)
	// 对端peer的当前block的活动状态
	blockIdle   int32 // Current block activity state of the peer (idle = 0, active = 1)
	// 对端peer的当前 receipt的活动状态
	receiptIdle int32 // Current receipt activity state of the peer (idle = 0, active = 1)
	// 对端peer的当前 state trie node的数据活动状态
	stateIdle   int32 // Current node data activity state of the peer (idle = 0, active = 1)


	// 每秒可检索的标头数量
	headerThroughput  float64 // Number of headers measured to be retrievable per second
	// 每秒可检索的块（实体）数
	blockThroughput   float64 // Number of blocks (bodies) measured to be retrievable per second
	// 每秒测量为可检索的收据数量
	receiptThroughput float64 // Number of receipts measured to be retrievable per second
	// 每秒测量为可检索的 state trie node 数据片数
	stateThroughput   float64 // Number of node data pieces measured to be retrievable per second

	// 请求往返时间, 用来跟踪响应
	rtt time.Duration // Request round trip time to track responsiveness (QoS)

	// 开始获取最后一个 header 的时间
	headerStarted  time.Time // Time instance when the last header fetch was started
	// 开始获取最后一个 block（ body ）的时间
	blockStarted   time.Time // Time instance when the last block (body) fetch was started
	// 开始获取最后一次 receipt 的时间
	receiptStarted time.Time // Time instance when the last receipt fetch was started
	// 开始获取最后一个 state trie node数据的时间
	stateStarted   time.Time // Time instance when the last node data fetch was started

	// 不需要请求的哈希集（以前没有） 什么 Hash 值? state trie Hash集
	lacking map[common.Hash]struct{} // Set of hashes not to request (didn't have previously)

	peer Peer  // 被封装的 peer 实例

	// ETH协议版本号切换策略
	version int        // Eth protocol version number to switch strategies
	log     log.Logger // Contextual logger to add extra infos to peer logs
	lock    sync.RWMutex
}

// LightPeer encapsulates the methods required to synchronise with a remote light peer.
type LightPeer interface {
	Head() (common.Hash, *big.Int)
	RequestHeadersByHash(common.Hash, int, int, bool) error
	RequestHeadersByNumber(uint64, int, int, bool) error
}

// Peer encapsulates the methods required to synchronise with a remote full peer.
type Peer interface {
	LightPeer
	RequestBodies([]common.Hash) error
	RequestReceipts([]common.Hash) error
	RequestNodeData([]common.Hash) error
}

// lightPeerWrapper wraps a LightPeer struct, stubbing out the Peer-only methods.
type lightPeerWrapper struct {
	peer LightPeer
}

func (w *lightPeerWrapper) Head() (common.Hash, *big.Int) { return w.peer.Head() }

// light 支持同步 headeR by hash
func (w *lightPeerWrapper) RequestHeadersByHash(h common.Hash, amount int, skip int, reverse bool) error {
	return w.peer.RequestHeadersByHash(h, amount, skip, reverse)
}

// light 支持同步 headeR by number
func (w *lightPeerWrapper) RequestHeadersByNumber(i uint64, amount int, skip int, reverse bool) error {
	return w.peer.RequestHeadersByNumber(i, amount, skip, reverse)
}

// light 模式,不支持 同步 bodies
func (w *lightPeerWrapper) RequestBodies([]common.Hash) error {
	panic("RequestBodies not supported in light client mode sync")
}
// light 模式,不支持 同步 receipt
func (w *lightPeerWrapper) RequestReceipts([]common.Hash) error {
	panic("RequestReceipts not supported in light client mode sync")
}

// light 模式,不支持 同步 state trie node
func (w *lightPeerWrapper) RequestNodeData([]common.Hash) error {
	panic("RequestNodeData not supported in light client mode sync")
}

// newPeerConnection creates a new downloader peer.
func newPeerConnection(id string, version int, peer Peer, logger log.Logger) *peerConnection {
	return &peerConnection{
		id:      id,
		lacking: make(map[common.Hash]struct{}),

		peer: peer,

		version: version,
		log:     logger,
	}
}

// Reset clears the internal state of a peer entity.
func (p *peerConnection) Reset() {
	p.lock.Lock()
	defer p.lock.Unlock()

	atomic.StoreInt32(&p.headerIdle, 0)
	atomic.StoreInt32(&p.blockIdle, 0)
	atomic.StoreInt32(&p.receiptIdle, 0)
	atomic.StoreInt32(&p.stateIdle, 0)

	p.headerThroughput = 0
	p.blockThroughput = 0
	p.receiptThroughput = 0
	p.stateThroughput = 0

	p.lacking = make(map[common.Hash]struct{})
}

// FetchHeaders sends a header retrieval request to the remote peer.
//
/**
FetchHeaders:
发送header 拉取 req到远程 peer
 */
func (p *peerConnection) FetchHeaders(from uint64, count int) error {
	// Sanity check the protocol version
	if p.version < 62 {
		panic(fmt.Sprintf("header fetch [eth/62+] requested on eth/%d", p.version))
	}
	// Short circuit if the peer is already fetching
	if !atomic.CompareAndSwapInt32(&p.headerIdle, 0, 1) {
		return errAlreadyFetching
	}
	p.headerStarted = time.Now()

	// Issue the header retrieval request (absolut upwards without gaps)
	// todo 这里才是主体
	go p.peer.RequestHeadersByNumber(from, count, 0, false)

	return nil
}

// FetchBodies sends a block body retrieval request to the remote peer.
func (p *peerConnection) FetchBodies(request *fetchRequest) error {
	// Sanity check the protocol version
	if p.version < 62 {
		panic(fmt.Sprintf("body fetch [eth/62+] requested on eth/%d", p.version))
	}
	// Short circuit if the peer is already fetching
	if !atomic.CompareAndSwapInt32(&p.blockIdle, 0, 1) {
		return errAlreadyFetching
	}
	p.blockStarted = time.Now()

	// Convert the header set to a retrievable slice
	hashes := make([]common.Hash, 0, len(request.Headers))
	for _, header := range request.Headers {
		hashes = append(hashes, header.Hash())
	}
	go p.peer.RequestBodies(hashes)

	return nil
}

// FetchReceipts sends a receipt retrieval request to the remote peer.
func (p *peerConnection) FetchReceipts(request *fetchRequest) error {
	// Sanity check the protocol version
	if p.version < 63 {
		panic(fmt.Sprintf("body fetch [eth/63+] requested on eth/%d", p.version))
	}
	// Short circuit if the peer is already fetching
	if !atomic.CompareAndSwapInt32(&p.receiptIdle, 0, 1) {
		return errAlreadyFetching
	}
	p.receiptStarted = time.Now()

	// Convert the header set to a retrievable slice
	hashes := make([]common.Hash, 0, len(request.Headers))
	for _, header := range request.Headers {
		hashes = append(hashes, header.Hash())
	}
	go p.peer.RequestReceipts(hashes)

	return nil
}

// FetchNodeData sends a node state data retrieval request to the remote peer.
//
/**
FetchNodeData:
向远程peer发送节点 state trie node 数据拉取请求
 */
func (p *peerConnection) FetchNodeData(hashes []common.Hash) error {
	// Sanity check the protocol version
	if p.version < 63 {
		panic(fmt.Sprintf("node data fetch [eth/63+] requested on eth/%d", p.version))
	}
	// Short circuit if the peer is already fetching
	// 修改state空闲标识位为  active: 1, 修改成功则成功,否则直接返回
	if !atomic.CompareAndSwapInt32(&p.stateIdle, 0, 1) {
		return errAlreadyFetching
	}

	// 记录 开始拉取 state 数据的时间
	p.stateStarted = time.Now()

	/** todo 真正启动拉取state 数据 */
	// TODO 注意: 只有 fast 模式才会最终走到这里来
	// TODO 查看  eth/downloader.syncWithPeer() 自明
	go p.peer.RequestNodeData(hashes)

	return nil
}

// SetHeadersIdle sets the peer to idle, allowing it to execute new header retrieval
// requests. Its estimated header retrieval throughput is updated with that measured
// just now.
//
/**
SetHeadersIdle:
将peer设置为空闲，从而允许其执行新的header拉取req。 其估计的 header 拉取吞吐量已更新为刚刚测量的
 */
func (p *peerConnection) SetHeadersIdle(delivered int) {
	p.setIdle(p.headerStarted, delivered, &p.headerThroughput, &p.headerIdle)
}

// SetBlocksIdle sets the peer to idle, allowing it to execute new block retrieval
// requests. Its estimated block retrieval throughput is updated with that measured
// just now.
func (p *peerConnection) SetBlocksIdle(delivered int) {
	p.setIdle(p.blockStarted, delivered, &p.blockThroughput, &p.blockIdle)
}

// SetBodiesIdle sets the peer to idle, allowing it to execute block body retrieval
// requests. Its estimated body retrieval throughput is updated with that measured
// just now.
func (p *peerConnection) SetBodiesIdle(delivered int) {
	p.setIdle(p.blockStarted, delivered, &p.blockThroughput, &p.blockIdle)
}

// SetReceiptsIdle sets the peer to idle, allowing it to execute new receipt
// retrieval requests. Its estimated receipt retrieval throughput is updated
// with that measured just now.
func (p *peerConnection) SetReceiptsIdle(delivered int) {
	p.setIdle(p.receiptStarted, delivered, &p.receiptThroughput, &p.receiptIdle)
}

// SetNodeDataIdle sets the peer to idle, allowing it to execute new state trie
// data retrieval requests. Its estimated state retrieval throughput is updated
// with that measured just now.
//
/**
SetNodeDataIdle
将 peer 设置为空闲，从而允许其执行新的state Trie数据 拉取请求。
其估计的 state 拉取吞吐量已更新为现在测量的状态。
 */
func (p *peerConnection) SetNodeDataIdle(delivered int) {
	p.setIdle(p.stateStarted, delivered, &p.stateThroughput, &p.stateIdle)
}

// setIdle sets the peer to idle, allowing it to execute new retrieval requests.
// Its estimated retrieval throughput is updated with that measured just now.
func (p *peerConnection) setIdle(started time.Time, delivered int, throughput *float64, idle *int32) {
	// Irrelevant of the scaling, make sure the peer ends up idle
	defer atomic.StoreInt32(idle, 0)

	p.lock.Lock()
	defer p.lock.Unlock()

	// If nothing was delivered (hard timeout / unavailable data), reduce throughput to minimum
	if delivered == 0 {
		*throughput = 0
		return
	}
	// Otherwise update the throughput with a new measurement
	elapsed := time.Since(started) + 1 // +1 (ns) to ensure non-zero divisor
	measured := float64(delivered) / (float64(elapsed) / float64(time.Second))

	*throughput = (1-measurementImpact)*(*throughput) + measurementImpact*measured
	p.rtt = time.Duration((1-measurementImpact)*float64(p.rtt) + measurementImpact*float64(elapsed))

	p.log.Trace("Peer throughput measurements updated",
		"hps", p.headerThroughput, "bps", p.blockThroughput,
		"rps", p.receiptThroughput, "sps", p.stateThroughput,
		"miss", len(p.lacking), "rtt", p.rtt)
}

// HeaderCapacity retrieves the peers header download allowance based on its
// previously discovered throughput.
//
/**
HeaderCapacity:
根据其先前发现的吞吐量拉取peer 的header 下载配额
 */
func (p *peerConnection) HeaderCapacity(targetRTT time.Duration) int {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return int(math.Min(1+math.Max(1, p.headerThroughput*float64(targetRTT)/float64(time.Second)), float64(MaxHeaderFetch)))
}

// BlockCapacity retrieves the peers block download allowance based on its
// previously discovered throughput.
func (p *peerConnection) BlockCapacity(targetRTT time.Duration) int {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return int(math.Min(1+math.Max(1, p.blockThroughput*float64(targetRTT)/float64(time.Second)), float64(MaxBlockFetch)))
}

// ReceiptCapacity retrieves the peers receipt download allowance based on its
// previously discovered throughput.
func (p *peerConnection) ReceiptCapacity(targetRTT time.Duration) int {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return int(math.Min(1+math.Max(1, p.receiptThroughput*float64(targetRTT)/float64(time.Second)), float64(MaxReceiptFetch)))
}

// NodeDataCapacity retrieves the peers state download allowance based on its
// previously discovered throughput.
//
// NodeDataCapacity: 根据先前发现的吞吐量拉取 peers 的 state下载配额
func (p *peerConnection) NodeDataCapacity(targetRTT time.Duration) int {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return int(math.Min(1+math.Max(1, p.stateThroughput*float64(targetRTT)/float64(time.Second)), float64(MaxStateFetch)))
}

// MarkLacking appends a new entity to the set of items (blocks, receipts, states)
// that a peer is known not to have (i.e. have been requested before). If the
// set reaches its maximum allowed capacity, items are randomly dropped off.
func (p *peerConnection) MarkLacking(hash common.Hash) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for len(p.lacking) >= maxLackingHashes {
		for drop := range p.lacking {
			delete(p.lacking, drop)
			break
		}
	}
	p.lacking[hash] = struct{}{}
}

// Lacks retrieves whether the hash of a blockchain item is on the peers lacking
// list (i.e. whether we know that the peer does not have it).
func (p *peerConnection) Lacks(hash common.Hash) bool {
	p.lock.RLock()
	defer p.lock.RUnlock()

	_, ok := p.lacking[hash]
	return ok
}

// peerSet represents the collection of active peer participating in the chain
// download procedure.
type peerSet struct {
	peers        map[string]*peerConnection
	newPeerFeed  event.Feed
	peerDropFeed event.Feed
	lock         sync.RWMutex
}

// newPeerSet creates a new peer set top track the active download sources.
func newPeerSet() *peerSet {
	return &peerSet{
		peers: make(map[string]*peerConnection),
	}
}

// SubscribeNewPeers subscribes to peer arrival events.
func (ps *peerSet) SubscribeNewPeers(ch chan<- *peerConnection) event.Subscription {
	return ps.newPeerFeed.Subscribe(ch)
}

// SubscribePeerDrops subscribes to peer departure events.
func (ps *peerSet) SubscribePeerDrops(ch chan<- *peerConnection) event.Subscription {
	return ps.peerDropFeed.Subscribe(ch)
}

// Reset iterates over the current peer set, and resets each of the known peers
// to prepare for a next batch of block retrieval.
func (ps *peerSet) Reset() {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	for _, peer := range ps.peers {
		peer.Reset()
	}
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known.
//
// The method also sets the starting throughput values of the new peer to the
// average of all existing peers, to give it a realistic chance of being used
// for data retrievals.
func (ps *peerSet) Register(p *peerConnection) error {
	// Retrieve the current median RTT as a sane default
	p.rtt = ps.medianRTT()

	// Register the new peer with some meaningful defaults
	ps.lock.Lock()
	if _, ok := ps.peers[p.id]; ok {
		ps.lock.Unlock()
		return errAlreadyRegistered
	}
	if len(ps.peers) > 0 {
		p.headerThroughput, p.blockThroughput, p.receiptThroughput, p.stateThroughput = 0, 0, 0, 0


		/* 累加各个 peer 中记录的 同步各种数据的 吞吐量 */
		for _, peer := range ps.peers {
			peer.lock.RLock()
			p.headerThroughput += peer.headerThroughput
			p.blockThroughput += peer.blockThroughput
			p.receiptThroughput += peer.receiptThroughput
			p.stateThroughput += peer.stateThroughput
			peer.lock.RUnlock()
		}

		/** 这里是将总的 吞吐量 除以 peer的个数, 得到个平均值 */
		p.headerThroughput /= float64(len(ps.peers))
		p.blockThroughput /= float64(len(ps.peers))
		p.receiptThroughput /= float64(len(ps.peers))
		p.stateThroughput /= float64(len(ps.peers))
	}


	ps.peers[p.id] = p
	ps.lock.Unlock()

	ps.newPeerFeed.Send(p)
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (ps *peerSet) Unregister(id string) error {
	ps.lock.Lock()
	p, ok := ps.peers[id]
	if !ok {
		defer ps.lock.Unlock()
		return errNotRegistered
	}
	delete(ps.peers, id)
	ps.lock.Unlock()

	ps.peerDropFeed.Send(p)
	return nil
}

// Peer retrieves the registered peer with the given id.
func (ps *peerSet) Peer(id string) *peerConnection {
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

// AllPeers retrieves a flat list of all the peers within the set.
func (ps *peerSet) AllPeers() []*peerConnection {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peerConnection, 0, len(ps.peers))
	for _, p := range ps.peers {
		list = append(list, p)
	}
	return list
}

// HeaderIdlePeers retrieves a flat list of all the currently header-idle peers
// within the active peer set, ordered by their reputation.
func (ps *peerSet) HeaderIdlePeers() ([]*peerConnection, int) {
	idle := func(p *peerConnection) bool {
		return atomic.LoadInt32(&p.headerIdle) == 0
	}
	throughput := func(p *peerConnection) float64 {
		p.lock.RLock()
		defer p.lock.RUnlock()
		return p.headerThroughput
	}
	return ps.idlePeers(62, 64, idle, throughput)
}

// BodyIdlePeers retrieves a flat list of all the currently body-idle peers within
// the active peer set, ordered by their reputation.
func (ps *peerSet) BodyIdlePeers() ([]*peerConnection, int) {
	idle := func(p *peerConnection) bool {
		return atomic.LoadInt32(&p.blockIdle) == 0
	}
	throughput := func(p *peerConnection) float64 {
		p.lock.RLock()
		defer p.lock.RUnlock()
		return p.blockThroughput
	}
	return ps.idlePeers(62, 64, idle, throughput)
}

// ReceiptIdlePeers retrieves a flat list of all the currently receipt-idle peers
// within the active peer set, ordered by their reputation.
func (ps *peerSet) ReceiptIdlePeers() ([]*peerConnection, int) {
	idle := func(p *peerConnection) bool {
		return atomic.LoadInt32(&p.receiptIdle) == 0
	}
	throughput := func(p *peerConnection) float64 {
		p.lock.RLock()
		defer p.lock.RUnlock()
		return p.receiptThroughput
	}
	return ps.idlePeers(63, 64, idle, throughput)
}

// NodeDataIdlePeers retrieves a flat list of all the currently node-data-idle
// peers within the active peer set, ordered by their reputation.
//
// NodeDataIdlePeers检索活动 peerSet中所有当前节点数据空闲 peer 的平面列表，并按其[信誉]排序。
// NOTE: 这里的 信誉 指的是和 Downloader 中的 d.rttConfidence 对估算的RTT的置信度  是否一个意思!?
func (ps *peerSet) NodeDataIdlePeers() ([]*peerConnection, int) {

	// 回调函数, 返回节点是否具备 state 空闲
	idle := func(p *peerConnection) bool {
		return atomic.LoadInt32(&p.stateIdle) == 0
	}

	//
	throughput := func(p *peerConnection) float64 {
		p.lock.RLock()
		defer p.lock.RUnlock()
		return p.stateThroughput
	}

	// 获取空闲的 peers
	return ps.idlePeers(63, 64, idle, throughput)
}

// idlePeers retrieves a flat list of all currently idle peers satisfying the
// protocol version constraints, using the provided function to check idleness.
// The resulting set of peers are sorted by their measure throughput.
func (ps *peerSet) idlePeers(minProtocol, maxProtocol int, idleCheck func(*peerConnection) bool, throughput func(*peerConnection) float64) ([]*peerConnection, int) {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	idle, total := make([]*peerConnection, 0, len(ps.peers)), 0
	for _, p := range ps.peers {
		if p.version >= minProtocol && p.version <= maxProtocol {
			if idleCheck(p) {
				idle = append(idle, p)
			}
			total++
		}
	}
	for i := 0; i < len(idle); i++ {
		for j := i + 1; j < len(idle); j++ {
			if throughput(idle[i]) < throughput(idle[j]) {
				idle[i], idle[j] = idle[j], idle[i]
			}
		}
	}
	return idle, total
}

// medianRTT returns the median RTT of the peerset, considering only the tuning
// peers if there are more peers available.
func (ps *peerSet) medianRTT() time.Duration {
	// Gather all the currently measured round trip times
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	rtts := make([]float64, 0, len(ps.peers))
	for _, p := range ps.peers {
		p.lock.RLock()
		rtts = append(rtts, float64(p.rtt))
		p.lock.RUnlock()
	}
	sort.Float64s(rtts)

	median := rttMaxEstimate
	if qosTuningPeers <= len(rtts) {
		median = time.Duration(rtts[qosTuningPeers/2]) // Median of our tuning peers
	} else if len(rtts) > 0 {
		median = time.Duration(rtts[len(rtts)/2]) // Median of our connected peers (maintain even like this some baseline qos)
	}
	// Restrict the RTT into some QoS defaults, irrelevant of true RTT
	if median < rttMinEstimate {
		median = rttMinEstimate
	}
	if median > rttMaxEstimate {
		median = rttMaxEstimate
	}
	return median
}
