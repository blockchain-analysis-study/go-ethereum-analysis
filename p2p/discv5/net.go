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

package discv5

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/common/mclock"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto/sha3"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/p2p/netutil"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rlp"
)

var (
	errInvalidEvent = errors.New("invalid in current state")
	errNoQuery      = errors.New("no pending query")
)

const (
	autoRefreshInterval   = 1 * time.Hour       // 每小时 刷新
	bucketRefreshInterval = 1 * time.Minute
	seedCount             = 30
	seedMaxAge            = 5 * 24 * time.Hour
	lowPort               = 1024
)

const testTopic = "foo"

const (
	printTestImgLogs = false
)

// Network manages the table and all protocol interaction.
type Network struct {
	db          *nodeDB // database of known nodes
	conn        transport
	netrestrict *netutil.Netlist

	closed           chan struct{}          // closed when loop is done
	closeReq         chan struct{}          // 'request to close'
	refreshReq       chan []*Node           // lookups ask for refresh on this channel
	refreshResp      chan (<-chan struct{}) // ...and get the channel to block on from this one
	read             chan ingressPacket     // ingress packets arrive here
	timeout          chan timeoutEvent
	queryReq         chan *findnodeQuery // lookups submit findnode queries on this channel
	tableOpReq       chan func()
	tableOpResp      chan struct{}

	// todo les server 使用
	topicRegisterReq chan topicRegisterReq

	// todo les client 使用
	topicSearchReq   chan topicSearchReq

	// State of the main loop.
	tab           *Table
	topictab      *topicTable
	ticketStore   *ticketStore
	nursery       []*Node

	// 记录 追踪 状态为【活动】的节点
	nodes         map[NodeID]*Node // tracks active nodes with state != known   跟踪状态为==的活动节点
	timeoutTimers map[timeoutEvent]*time.Timer

	// Revalidation queues.
	// Nodes put on these queues will be pinged eventually.
	slowRevalidateQueue []*Node
	fastRevalidateQueue []*Node

	// Buffers for state transition.
	sendBuf []*ingressPacket
}

// transport is implemented by the UDP transport.
// it is an interface so we can test without opening lots of UDP
// sockets and without generating a private key.
type transport interface {
	sendPing(remote *Node, remoteAddr *net.UDPAddr, topics []Topic) (hash []byte)
	sendNeighbours(remote *Node, nodes []*Node)
	sendFindnodeHash(remote *Node, target common.Hash)
	sendTopicRegister(remote *Node, topics []Topic, topicIdx int, pong []byte)
	sendTopicNodes(remote *Node, queryHash common.Hash, nodes []*Node)

	send(remote *Node, ptype nodeEvent, p interface{}) (hash []byte)

	localAddr() *net.UDPAddr
	Close()
}

type findnodeQuery struct {
	remote   *Node
	target   common.Hash
	reply    chan<- []*Node
	nresults int // counter for received nodes
}

type topicRegisterReq struct {
	add   bool
	topic Topic
}

type topicSearchReq struct {
	topic  Topic
	found  chan<- *Node
	lookup chan<- bool
	delay  time.Duration
}

type topicSearchResult struct {
	target lookupInfo
	nodes  []*Node
}

type timeoutEvent struct {
	ev   nodeEvent
	node *Node
}

func newNetwork(conn transport, ourPubkey ecdsa.PublicKey, dbPath string, netrestrict *netutil.Netlist) (*Network, error) {
	ourID := PubkeyID(&ourPubkey)

	var db *nodeDB
	if dbPath != "<no database>" {
		var err error
		if db, err = newNodeDB(dbPath, Version, ourID); err != nil {
			return nil, err
		}
	}

	tab := newTable(ourID, conn.localAddr())  // 创建 table 实例, 里面有  k-bucket 的引用

	net := &Network{
		db:               db,
		conn:             conn,
		netrestrict:      netrestrict,
		tab:              tab,
		topictab:         newTopicTable(db, tab.self),
		ticketStore:      newTicketStore(),
		refreshReq:       make(chan []*Node),
		refreshResp:      make(chan (<-chan struct{})),
		closed:           make(chan struct{}),
		closeReq:         make(chan struct{}),
		read:             make(chan ingressPacket, 100),
		timeout:          make(chan timeoutEvent),
		timeoutTimers:    make(map[timeoutEvent]*time.Timer),
		tableOpReq:       make(chan func()),
		tableOpResp:      make(chan struct{}),
		queryReq:         make(chan *findnodeQuery),
		topicRegisterReq: make(chan topicRegisterReq),
		topicSearchReq:   make(chan topicSearchReq),
		nodes:            make(map[NodeID]*Node),
	}
	go net.loop()
	return net, nil
}

// Close terminates the network listener and flushes the node database.
func (net *Network) Close() {
	net.conn.Close()
	select {
	case <-net.closed:
	case net.closeReq <- struct{}{}:
		<-net.closed
	}
}

// Self returns the local node.
// The returned node should not be modified by the caller.
func (net *Network) Self() *Node {
	return net.tab.self
}

// ReadRandomNodes fills the given slice with random nodes from the
// table. It will not write the same node more than once. The nodes in
// the slice are copies and can be modified by the caller.
func (net *Network) ReadRandomNodes(buf []*Node) (n int) {
	net.reqTableOp(func() { n = net.tab.readRandomNodes(buf) })
	return n
}

// SetFallbackNodes sets the initial points of contact. These nodes
// are used to connect to the network if the table is empty and there
// are no known nodes in the database.
//
//  todo 设置 种子节点
//
// `SetFallbackNodes()` 设置 初始 连接点 peer.
// 						如果 table 为空并且 本地 db 中没有已知 peer，这些节点将用于连接到网络.
func (net *Network) SetFallbackNodes(nodes []*Node) error {
	nursery := make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		if err := n.validateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap/fallback node %q (%v)", n, err)
		}
		// Recompute cpy.sha because the node might not have been
		// created by NewNode or ParseNode.
		cpy := *n
		cpy.sha = crypto.Keccak256Hash(n.ID[:])
		nursery = append(nursery, &cpy)
	}
	net.reqRefresh(nursery)
	return nil
}

// Resolve searches for a specific node with the given ID.
// It returns nil if the node could not be found.
func (net *Network) Resolve(targetID NodeID) *Node {
	result := net.lookup(crypto.Keccak256Hash(targetID[:]), true)
	for _, n := range result {
		if n.ID == targetID {
			return n
		}
	}
	return nil
}

// Lookup performs a network search for nodes close
// to the given target. It approaches the target by querying
// nodes that are closer to it on each iteration.
// The given target does not need to be an actual node
// identifier.
//
// The local node may be included in the result.
//
//
// 开始  根据 target 做自我查找以填充存储桶
func (net *Network) Lookup(targetID NodeID) []*Node {  // 这里回去发起 FIND_NODE 请求去 刷桶
	return net.lookup(crypto.Keccak256Hash(targetID[:]), false)
}

func (net *Network) lookup(target common.Hash, stopOnMatch bool) []*Node {
	var (
		asked          = make(map[NodeID]bool)
		seen           = make(map[NodeID]bool)
		reply          = make(chan []*Node, alpha)
		result         = nodesByDistance{target: target}		//  用来 接收 返回 一组请求数据的结构
		pendingQueries = 0										//  正在处理中的 req 计数器
	)
	// Get initial answers from the local node.
	result.push(net.tab.self, bucketSize)  // 将 当前本地 node 加入到 result 的 k-bucket 中
	for {
		// Ask the α closest nodes that we haven't asked yet.
		for i := 0; i < len(result.entries) && pendingQueries < alpha; i++ {
			n := result.entries[i]
			if !asked[n.ID] {
				asked[n.ID] = true
				pendingQueries++
				net.reqQueryFindnode(n, target, reply)   // 向 target 发起 FIND_NODE n 的请求
			}
		}
		if pendingQueries == 0 {
			// We have asked all closest nodes, stop the search.
			break
		}
		// Wait for the next reply.
		select {

		// 接收到了  target 返回的一批离 n 近的 node信息
		case nodes := <-reply:
			for _, n := range nodes {
				if n != nil && !seen[n.ID] {
					seen[n.ID] = true
					result.push(n, bucketSize)   // 全部收集到 result 中
					if stopOnMatch && n.sha == target {
						return result.entries
					}
				}
			}
			pendingQueries--

		// 超时
		case <-time.After(respTimeout):
			// forget all pending requests, start new ones
			pendingQueries = 0
			reply = make(chan []*Node, alpha)
		}
	}
	return result.entries
}

func (net *Network) RegisterTopic(topic Topic, stop <-chan struct{}) {
	select {
	case net.topicRegisterReq <- topicRegisterReq{true, topic}:
	case <-net.closed:
		return
	}
	select {
	case <-net.closed:
	case <-stop:
		select {
		case net.topicRegisterReq <- topicRegisterReq{false, topic}:
		case <-net.closed:
		}
	}
}

func (net *Network) SearchTopic(topic Topic, setPeriod <-chan time.Duration, found chan<- *Node, lookup chan<- bool) {
	for {
		select {
		case <-net.closed:
			return
		case delay, ok := <-setPeriod:
			select {
			case net.topicSearchReq <- topicSearchReq{topic: topic, found: found, lookup: lookup, delay: delay}:
			case <-net.closed:
				return
			}
			if !ok {
				return
			}
		}
	}
}

// 请求更新 本地 k-bucket 等信息
func (net *Network) reqRefresh(nursery []*Node) <-chan struct{} {
	select {
	case net.refreshReq <- nursery:
		return <-net.refreshResp
	case <-net.closed:
		return net.closed
	}
}

// 发起 FIND_NODE 请求 chan 信号
func (net *Network) reqQueryFindnode(n *Node, target common.Hash, reply chan []*Node) bool {
	q := &findnodeQuery{remote: n, target: target, reply: reply}
	select {
	case net.queryReq <- q:
		return true
	case <-net.closed:
		return false
	}
}

func (net *Network) reqReadPacket(pkt ingressPacket) {
	select {
	case net.read <- pkt:
	case <-net.closed:
	}
}

func (net *Network) reqTableOp(f func()) (called bool) {
	select {
	case net.tableOpReq <- f:
		<-net.tableOpResp
		return true
	case <-net.closed:
		return false
	}
}

// TODO: external address handling.

type topicSearchInfo struct {
	lookupChn chan<- bool
	period    time.Duration
}

const maxSearchCount = 5

func (net *Network) loop() {
	var (
		refreshTimer       = time.NewTicker(autoRefreshInterval)					// 对当前本地node发起刷 bucket 动作				1 小时
		bucketRefreshTimer = time.NewTimer(bucketRefreshInterval)					// 让 随机的target节点的k-bucket得以更新??      1 分钟
		refreshDone        chan struct{} // closed when the 'refresh' lookup has ended
	)

	// Tracking the next ticket to register.
	var (
		nextTicket        *ticketRef
		nextRegisterTimer *time.Timer
		nextRegisterTime  <-chan time.Time
	)
	defer func() {
		if nextRegisterTimer != nil {
			nextRegisterTimer.Stop()
		}
	}()
	resetNextTicket := func() {
		ticket, timeout := net.ticketStore.nextFilteredTicket()
		if nextTicket != ticket {
			nextTicket = ticket
			if nextRegisterTimer != nil {
				nextRegisterTimer.Stop()
				nextRegisterTime = nil
			}
			if ticket != nil {
				nextRegisterTimer = time.NewTimer(timeout)
				nextRegisterTime = nextRegisterTimer.C
			}
		}
	}

	// Tracking registration and search lookups.
	var (
		topicRegisterLookupTarget lookupInfo
		topicRegisterLookupDone   chan []*Node
		topicRegisterLookupTick   = time.NewTimer(0)
		searchReqWhenRefreshDone  []topicSearchReq
		searchInfo                = make(map[Topic]topicSearchInfo)
		activeSearchCount         int
	)
	topicSearchLookupDone := make(chan topicSearchResult, 100)
	topicSearch := make(chan Topic, 100)
	<-topicRegisterLookupTick.C

	statsDump := time.NewTicker(10 * time.Second)

loop:
	for {
		resetNextTicket()

		select {
		case <-net.closeReq:
			log.Trace("<-net.closeReq")
			break loop

		// Ingress packet handling.
		case pkt := <-net.read:
			//fmt.Println("read", pkt.ev)
			log.Trace("<-net.read")
			n := net.internNode(&pkt)
			prestate := n.state
			status := "ok"
			if err := net.handle(n, pkt.ev, &pkt); err != nil {
				status = err.Error()
			}
			log.Trace("", "msg", log.Lazy{Fn: func() string {
				return fmt.Sprintf("<<< (%d) %v from %x@%v: %v -> %v (%v)",
					net.tab.count, pkt.ev, pkt.remoteID[:8], pkt.remoteAddr, prestate, n.state, status)
			}})
			// TODO: persist state if n.state goes >= known, delete if it goes <= known

		// State transition timeouts.
		case timeout := <-net.timeout:
			log.Trace("<-net.timeout")
			if net.timeoutTimers[timeout] == nil {
				// Stale timer (was aborted).
				continue
			}
			delete(net.timeoutTimers, timeout)
			prestate := timeout.node.state
			status := "ok"
			if err := net.handle(timeout.node, timeout.ev, nil); err != nil {
				status = err.Error()
			}
			log.Trace("", "msg", log.Lazy{Fn: func() string {
				return fmt.Sprintf("--- (%d) %v for %x@%v: %v -> %v (%v)",
					net.tab.count, timeout.ev, timeout.node.ID[:8], timeout.node.addr(), prestate, timeout.node.state, status)
			}})

		// Querying.
		case q := <-net.queryReq:   // 向 target 发起 FIND_NODE 请求
			log.Trace("<-net.queryReq")
			if !q.start(net) {  // 向 target 节点发起 FIND_NODE  remote 节点的请求
				q.remote.deferQuery(q)
			}

		// Interacting with the table.
		case f := <-net.tableOpReq:
			log.Trace("<-net.tableOpReq")
			f()
			net.tableOpResp <- struct{}{}

		// Topic registration stuff.

		/**
		todo 轻节点的 Server 和 Client 相互查找 `节点发现` 的处理方式

		todo 这里是 轻节点 Server 处理 `srvr.DiscV5.RegisterTopic` 过来的
		 */
		case req := <-net.topicRegisterReq:
			log.Trace("<-net.topicRegisterReq")
			if !req.add {
				net.ticketStore.removeRegisterTopic(req.topic)
				continue
			}
			net.ticketStore.addTopic(req.topic, true)
			// If we're currently waiting idle (nothing to look up), give the ticket store a
			// chance to start it sooner. This should speed up convergence of the radius
			// determination for new topics.
			//
			/**
			如果我们当前正在等待空闲状态（什么都不想查找），请给售票处一个机会，尽快启动它。
			这应加快新主题半径确定的收敛性.

			 */
			// if topicRegisterLookupDone == nil {
			if topicRegisterLookupTarget.target == (common.Hash{}) {
				log.Trace("topicRegisterLookupTarget == null")
				if topicRegisterLookupTick.Stop() {
					<-topicRegisterLookupTick.C
				}
				target, delay := net.ticketStore.nextRegisterLookup()
				topicRegisterLookupTarget = target
				topicRegisterLookupTick.Reset(delay)
			}

		case nodes := <-topicRegisterLookupDone:
			log.Trace("<-topicRegisterLookupDone")
			net.ticketStore.registerLookupDone(topicRegisterLookupTarget, nodes, func(n *Node) []byte {
				net.ping(n, n.addr())
				return n.pingEcho
			})
			target, delay := net.ticketStore.nextRegisterLookup()
			topicRegisterLookupTarget = target
			topicRegisterLookupTick.Reset(delay)
			topicRegisterLookupDone = nil

		case <-topicRegisterLookupTick.C:
			log.Trace("<-topicRegisterLookupTick")
			if (topicRegisterLookupTarget.target == common.Hash{}) {
				target, delay := net.ticketStore.nextRegisterLookup()
				topicRegisterLookupTarget = target
				topicRegisterLookupTick.Reset(delay)
				topicRegisterLookupDone = nil
			} else {
				topicRegisterLookupDone = make(chan []*Node)
				target := topicRegisterLookupTarget.target
				go func() { topicRegisterLookupDone <- net.lookup(target, false) }()
			}

		case <-nextRegisterTime:
			log.Trace("<-nextRegisterTime")
			net.ticketStore.ticketRegistered(*nextTicket)
			//fmt.Println("sendTopicRegister", nextTicket.t.node.addr().String(), nextTicket.t.topics, nextTicket.idx, nextTicket.t.pong)
			net.conn.sendTopicRegister(nextTicket.t.node, nextTicket.t.topics, nextTicket.idx, nextTicket.t.pong)


		/**
		todo 轻节点的 Server 和 Client 相互查找 `节点发现` 的处理方式

		todo 这里是轻节点 处理 `pool.server.DiscV5.SearchTopic` 过来的
		 */
		case req := <-net.topicSearchReq:
			if refreshDone == nil {
				log.Trace("<-net.topicSearchReq")
				info, ok := searchInfo[req.topic]
				if ok {
					if req.delay == time.Duration(0) {
						delete(searchInfo, req.topic)
						net.ticketStore.removeSearchTopic(req.topic)
					} else {
						info.period = req.delay
						searchInfo[req.topic] = info
					}
					continue
				}
				if req.delay != time.Duration(0) {
					var info topicSearchInfo
					info.period = req.delay
					info.lookupChn = req.lookup
					searchInfo[req.topic] = info
					net.ticketStore.addSearchTopic(req.topic, req.found)
					topicSearch <- req.topic
				}
			} else {
				searchReqWhenRefreshDone = append(searchReqWhenRefreshDone, req)
			}

		case topic := <-topicSearch:
			if activeSearchCount < maxSearchCount {
				activeSearchCount++
				target := net.ticketStore.nextSearchLookup(topic)
				go func() {
					nodes := net.lookup(target.target, false)
					topicSearchLookupDone <- topicSearchResult{target: target, nodes: nodes}
				}()
			}
			period := searchInfo[topic].period
			if period != time.Duration(0) {
				go func() {
					time.Sleep(period)
					topicSearch <- topic
				}()
			}

		case res := <-topicSearchLookupDone:
			activeSearchCount--
			if lookupChn := searchInfo[res.target.topic].lookupChn; lookupChn != nil {
				lookupChn <- net.ticketStore.radius[res.target.topic].converged
			}
			net.ticketStore.searchLookupDone(res.target, res.nodes, func(n *Node, topic Topic) []byte {
				if n.state != nil && n.state.canQuery {
					return net.conn.send(n, topicQueryPacket, topicQuery{Topic: topic}) // TODO: set expiration
				} else {
					if n.state == unknown {
						net.ping(n, n.addr())
					}
					return nil
				}
			})

		case <-statsDump.C:
			log.Trace("<-statsDump.C")
			/*r, ok := net.ticketStore.radius[testTopic]
			if !ok {
				fmt.Printf("(%x) no radius @ %v\n", net.tab.self.ID[:8], time.Now())
			} else {
				topics := len(net.ticketStore.tickets)
				tickets := len(net.ticketStore.nodes)
				rad := r.radius / (maxRadius/10000+1)
				fmt.Printf("(%x) topics:%d radius:%d tickets:%d @ %v\n", net.tab.self.ID[:8], topics, rad, tickets, time.Now())
			}*/

			tm := mclock.Now()
			for topic, r := range net.ticketStore.radius {
				if printTestImgLogs {
					rad := r.radius / (maxRadius/1000000 + 1)
					minrad := r.minRadius / (maxRadius/1000000 + 1)
					fmt.Printf("*R %d %v %016x %v\n", tm/1000000, topic, net.tab.self.sha[:8], rad)
					fmt.Printf("*MR %d %v %016x %v\n", tm/1000000, topic, net.tab.self.sha[:8], minrad)
				}
			}
			for topic, t := range net.topictab.topics {
				wp := t.wcl.nextWaitPeriod(tm)
				if printTestImgLogs {
					fmt.Printf("*W %d %v %016x %d\n", tm/1000000, topic, net.tab.self.sha[:8], wp/1000000)
				}
			}

		// Periodic / lookup-initiated bucket refresh.
		//
		// 每小时 一次
		case <-refreshTimer.C:
			log.Trace("<-refreshTimer.C")
			// TODO: ideally we would start the refresh timer after
			// fallback nodes have been set for the first time.
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				net.refresh(refreshDone)  // 每小时 一次，  发起对当前本地node做刷桶的请求
			}

		// 每分钟 一次
		case <-bucketRefreshTimer.C:
			target := net.tab.chooseBucketRefreshTarget()  // 让 随机的target节点的k-bucket得以更新??
			go func() {
				net.lookup(target, false)
				bucketRefreshTimer.Reset(bucketRefreshInterval)
			}()
		case newNursery := <-net.refreshReq:
			log.Trace("<-net.refreshReq")
			if newNursery != nil {
				net.nursery = newNursery
			}
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				net.refresh(refreshDone)  // 每分钟 一次，  发起对当前本地node做刷桶的请求
			}
			net.refreshResp <- refreshDone

		// 用来监听 刷新 完成 信号
		case <-refreshDone:
			log.Trace("<-net.refreshDone", "table size", net.tab.count)
			if net.tab.count != 0 {
				refreshDone = nil
				list := searchReqWhenRefreshDone
				searchReqWhenRefreshDone = nil
				go func() {
					for _, req := range list {
						net.topicSearchReq <- req
					}
				}()
			} else {
				refreshDone = make(chan struct{})
				net.refresh(refreshDone) // 用来监听 刷新 完成 信号，  发起对当前本地node做刷桶的请求
			}
		}
	}
	log.Trace("loop stopped")

	log.Debug(fmt.Sprintf("shutting down"))
	if net.conn != nil {
		net.conn.Close()
	}
	if refreshDone != nil {
		// TODO: wait for pending refresh.
		//<-refreshResults
	}
	// Cancel all pending timeouts.
	for _, timer := range net.timeoutTimers {
		timer.Stop()
	}
	if net.db != nil {
		net.db.close()
	}
	close(net.closed)
}

// Everything below runs on the Network.loop goroutine
// and can modify Node, Table and Network at any time without locking.

// 发起对当前本地node做刷桶的请求
func (net *Network) refresh(done chan<- struct{}) {
	var seeds []*Node
	if net.db != nil {
		seeds = net.db.querySeeds(seedCount, seedMaxAge)  // 检索随机节点，以用作自举的潜在种子节点   每次 至少 返回 30 个
	}
	if len(seeds) == 0 {
		seeds = net.nursery
	}
	if len(seeds) == 0 {
		log.Trace("no seed nodes found")
		time.AfterFunc(time.Second*10, func() { close(done) })
		return
	}

	// 根据 随机出来的 node, 我们校验 它的最后一个 和当前本地node的 pong 时间
	for _, n := range seeds {
		log.Debug("", "msg", log.Lazy{Fn: func() string {
			var age string
			if net.db != nil {
				age = time.Since(net.db.lastPong(n.ID)).String()
			} else {
				age = "unknown"
			}
			return fmt.Sprintf("seed node (age %s): %v", age, n)
		}})
		n = net.internNodeFromDB(n)
		if n.state == unknown {
			net.transition(n, verifyinit)
		}
		// Force-add the seed node so Lookup does something.
		// It will be deleted again if verification fails.
		//
		//  强制添加种子节点，以便Lookup执行某些操作
		//  如果验证失败，它将再次删除
		net.tab.add(n)
	}
	// Start self lookup to fill up the buckets.
	//
	// 开始自我查找以填充存储桶
	go func() {
		net.Lookup(net.tab.self.ID)  // 发起刷桶动作
		close(done)
	}()
}

// Node Interning.

func (net *Network) internNode(pkt *ingressPacket) *Node {
	if n := net.nodes[pkt.remoteID]; n != nil {
		n.IP = pkt.remoteAddr.IP
		n.UDP = uint16(pkt.remoteAddr.Port)
		n.TCP = uint16(pkt.remoteAddr.Port)
		return n
	}
	n := NewNode(pkt.remoteID, pkt.remoteAddr.IP, uint16(pkt.remoteAddr.Port), uint16(pkt.remoteAddr.Port))
	n.state = unknown
	net.nodes[pkt.remoteID] = n
	return n
}

func (net *Network) internNodeFromDB(dbn *Node) *Node {
	if n := net.nodes[dbn.ID]; n != nil {
		return n
	}
	n := NewNode(dbn.ID, dbn.IP, dbn.UDP, dbn.TCP)
	n.state = unknown
	net.nodes[n.ID] = n
	return n
}

func (net *Network) internNodeFromNeighbours(sender *net.UDPAddr, rn rpcNode) (n *Node, err error) {
	if rn.ID == net.tab.self.ID {
		return nil, errors.New("is self")
	}
	if rn.UDP <= lowPort {
		return nil, errors.New("low port")
	}
	n = net.nodes[rn.ID]
	if n == nil {
		// We haven't seen this node before.
		n, err = nodeFromRPC(sender, rn)
		if net.netrestrict != nil && !net.netrestrict.Contains(n.IP) {
			return n, errors.New("not contained in netrestrict whitelist")
		}
		if err == nil {
			n.state = unknown
			net.nodes[n.ID] = n
		}
		return n, err
	}
	if !n.IP.Equal(rn.IP) || n.UDP != rn.UDP || n.TCP != rn.TCP {
		if n.state == known {
			// reject address change if node is known by us
			err = fmt.Errorf("metadata mismatch: got %v, want %v", rn, n)
		} else {
			// accept otherwise; this will be handled nicer with signed ENRs
			n.IP = rn.IP
			n.UDP = rn.UDP
			n.TCP = rn.TCP
		}
	}
	return n, err
}

// nodeNetGuts is embedded in Node and contains fields.
//
// nodeNetGuts嵌入在Node中并包含字段
type nodeNetGuts struct {
	// This is a cached copy of sha3(ID) which is used for node
	// distance calculations. This is part of Node in order to make it
	// possible to write tests that need a node at a certain distance.
	// In those tests, the content of sha will not actually correspond
	// with ID.
	//
	//
	//  这是 sha3(ID 的缓存副本，用于节点距离计算。 这是Node的一部分，以便可以编写需要一定距离的节点的测试。
	//  在这些测试中，sha的内容实际上不会与ID对应。
	sha common.Hash

	// State machine fields. Access to these fields
	// is restricted to the Network.loop goroutine.
	state             *nodeState
	pingEcho          []byte           // hash of last ping sent by us
	pingTopics        []Topic          // topic set sent by us in last ping

	// 一堆 没被发送成功 或者 还未发送的 req
	deferredQueries   []*findnodeQuery // queries that can't be sent yet
	pendingNeighbours *findnodeQuery   // current query, waiting for reply
	queryTimeouts     int
}

func (n *nodeNetGuts) deferQuery(q *findnodeQuery) {
	n.deferredQueries = append(n.deferredQueries, q)
}

func (n *nodeNetGuts) startNextQuery(net *Network) {
	if len(n.deferredQueries) == 0 {
		return
	}
	nextq := n.deferredQueries[0]
	if nextq.start(net) {
		n.deferredQueries = append(n.deferredQueries[:0], n.deferredQueries[1:]...)
	}
}

func (q *findnodeQuery) start(net *Network) bool {
	// Satisfy queries against the local node directly.

	// 如果 req 中的 远端 node 就是 自己
	if q.remote == net.tab.self {
		closest := net.tab.closest(crypto.Keccak256Hash(q.target[:]), bucketSize)
		q.reply <- closest.entries
		return true
	}
	if q.remote.state.canQuery && q.remote.pendingNeighbours == nil {
		net.conn.sendFindnodeHash(q.remote, q.target)      // 向 target 节点发起 FIND_NODE  remote 节点的请求
		net.timedEvent(respTimeout, q.remote, neighboursTimeout)
		q.remote.pendingNeighbours = q
		return true
	}
	// If the node is not known yet, it won't accept queries.
	// Initiate the transition to known.
	// The request will be sent later when the node reaches known state.
	if q.remote.state == unknown {
		net.transition(q.remote, verifyinit)
	}
	return false
}

// Node Events (the input to the state machine).

type nodeEvent uint

//go:generate stringer -type=nodeEvent

const (

	// Packet type events.
	// These correspond to packet types in the UDP protocol.
	pingPacket = iota + 1
	pongPacket
	findnodePacket
	neighborsPacket
	findnodeHashPacket
	topicRegisterPacket
	topicQueryPacket
	topicNodesPacket

	// Non-packet events.
	// Event values in this category are allocated outside
	// the packet type range (packet types are encoded as a single byte).
	pongTimeout nodeEvent = iota + 256		// 264
	pingTimeout								// 265
	neighboursTimeout						// 266
)

// Node State Machine.

type nodeState struct {
	name     string
	handle   func(*Network, *Node, nodeEvent, *ingressPacket) (next *nodeState, err error)
	enter    func(*Network, *Node)
	canQuery bool
}

func (s *nodeState) String() string {
	return s.name
}

var (
	unknown          *nodeState
	verifyinit       *nodeState
	verifywait       *nodeState
	remoteverifywait *nodeState
	known            *nodeState
	contested        *nodeState
	unresponsive     *nodeState
)

func init() {
	unknown = &nodeState{
		name: "unknown",
		enter: func(net *Network, n *Node) {
			net.tab.delete(n)
			n.pingEcho = nil
			// Abort active queries.
			for _, q := range n.deferredQueries {
				q.reply <- nil
			}
			n.deferredQueries = nil
			if n.pendingNeighbours != nil {
				n.pendingNeighbours.reply <- nil
				n.pendingNeighbours = nil
			}
			n.queryTimeouts = 0
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				net.ping(n, pkt.remoteAddr)
				return verifywait, nil
			default:
				return unknown, errInvalidEvent
			}
		},
	}

	verifyinit = &nodeState{
		name: "verifyinit",
		enter: func(net *Network, n *Node) {
			net.ping(n, n.addr())
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return verifywait, nil
			case pongPacket:
				err := net.handleKnownPong(n, pkt)
				return remoteverifywait, err
			case pongTimeout:
				return unknown, nil
			default:
				return verifyinit, errInvalidEvent
			}
		},
	}

	verifywait = &nodeState{
		name: "verifywait",
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return verifywait, nil
			case pongPacket:
				err := net.handleKnownPong(n, pkt)
				return known, err
			case pongTimeout:
				return unknown, nil
			default:
				return verifywait, errInvalidEvent
			}
		},
	}

	remoteverifywait = &nodeState{
		name: "remoteverifywait",
		enter: func(net *Network, n *Node) {
			net.timedEvent(respTimeout, n, pingTimeout)
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return remoteverifywait, nil
			case pingTimeout:
				return known, nil
			default:
				return remoteverifywait, errInvalidEvent
			}
		},
	}

	known = &nodeState{
		name:     "known",
		canQuery: true,
		enter: func(net *Network, n *Node) {
			n.queryTimeouts = 0
			n.startNextQuery(net)
			// Insert into the table and start revalidation of the last node
			// in the bucket if it is full.
			last := net.tab.add(n)
			if last != nil && last.state == known {
				// TODO: do this asynchronously
				net.transition(last, contested)
			}
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return known, nil
			case pongPacket:
				err := net.handleKnownPong(n, pkt)
				return known, err
			default:
				return net.handleQueryEvent(n, ev, pkt)
			}
		},
	}

	contested = &nodeState{
		name:     "contested",
		canQuery: true,
		enter: func(net *Network, n *Node) {
			net.ping(n, n.addr())
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pongPacket:
				// Node is still alive.
				err := net.handleKnownPong(n, pkt)
				return known, err
			case pongTimeout:
				net.tab.deleteReplace(n)
				return unresponsive, nil
			case pingPacket:
				net.handlePing(n, pkt)
				return contested, nil
			default:
				return net.handleQueryEvent(n, ev, pkt)
			}
		},
	}

	unresponsive = &nodeState{
		name:     "unresponsive",
		canQuery: true,
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return known, nil
			case pongPacket:
				err := net.handleKnownPong(n, pkt)
				return known, err
			default:
				return net.handleQueryEvent(n, ev, pkt)
			}
		},
	}
}

// handle processes packets sent by n and events related to n.
func (net *Network) handle(n *Node, ev nodeEvent, pkt *ingressPacket) error {
	//fmt.Println("handle", n.addr().String(), n.state, ev)
	if pkt != nil {
		if err := net.checkPacket(n, ev, pkt); err != nil {
			//fmt.Println("check err:", err)
			return err
		}
		// Start the background expiration goroutine after the first
		// successful communication. Subsequent calls have no effect if it
		// is already running. We do this here instead of somewhere else
		// so that the search for seed nodes also considers older nodes
		// that would otherwise be removed by the expirer.
		if net.db != nil {
			net.db.ensureExpirer()
		}
	}
	if n.state == nil {
		n.state = unknown //???
	}
	next, err := n.state.handle(net, n, ev, pkt)
	net.transition(n, next)
	//fmt.Println("new state:", n.state)
	return err
}

func (net *Network) checkPacket(n *Node, ev nodeEvent, pkt *ingressPacket) error {
	// Replay prevention checks.
	switch ev {
	case pingPacket, findnodeHashPacket, neighborsPacket:
		// TODO: check date is > last date seen
		// TODO: check ping version
	case pongPacket:
		if !bytes.Equal(pkt.data.(*pong).ReplyTok, n.pingEcho) {
			// fmt.Println("pong reply token mismatch")
			return fmt.Errorf("pong reply token mismatch")
		}
		n.pingEcho = nil
	}
	// Address validation.
	// TODO: Ideally we would do the following:
	//  - reject all packets with wrong address except ping.
	//  - for ping with new address, transition to verifywait but keep the
	//    previous node (with old address) around. if the new one reaches known,
	//    swap it out.
	return nil
}

func (net *Network) transition(n *Node, next *nodeState) {
	if n.state != next {
		n.state = next
		if next.enter != nil {
			next.enter(net, n)
		}
	}

	// TODO: persist/unpersist node
}

func (net *Network) timedEvent(d time.Duration, n *Node, ev nodeEvent) {
	timeout := timeoutEvent{ev, n}
	net.timeoutTimers[timeout] = time.AfterFunc(d, func() {
		select {
		case net.timeout <- timeout:
		case <-net.closed:
		}
	})
}

func (net *Network) abortTimedEvent(n *Node, ev nodeEvent) {
	timer := net.timeoutTimers[timeoutEvent{ev, n}]
	if timer != nil {
		timer.Stop()
		delete(net.timeoutTimers, timeoutEvent{ev, n})
	}
}

func (net *Network) ping(n *Node, addr *net.UDPAddr) {
	//fmt.Println("ping", n.addr().String(), n.ID.String(), n.sha.Hex())
	if n.pingEcho != nil || n.ID == net.tab.self.ID {
		//fmt.Println(" not sent")
		return
	}
	log.Trace("Pinging remote node", "node", n.ID)
	n.pingTopics = net.ticketStore.regTopicSet()
	n.pingEcho = net.conn.sendPing(n, addr, n.pingTopics)
	net.timedEvent(respTimeout, n, pongTimeout)
}

func (net *Network) handlePing(n *Node, pkt *ingressPacket) {
	log.Trace("Handling remote ping", "node", n.ID)
	ping := pkt.data.(*ping)
	n.TCP = ping.From.TCP
	t := net.topictab.getTicket(n, ping.Topics)

	pong := &pong{
		To:         makeEndpoint(n.addr(), n.TCP), // TODO: maybe use known TCP port from DB
		ReplyTok:   pkt.hash,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	ticketToPong(t, pong)
	net.conn.send(n, pongPacket, pong)
}

func (net *Network) handleKnownPong(n *Node, pkt *ingressPacket) error {
	log.Trace("Handling known pong", "node", n.ID)
	net.abortTimedEvent(n, pongTimeout)
	now := mclock.Now()
	ticket, err := pongToTicket(now, n.pingTopics, n, pkt)
	if err == nil {
		// fmt.Printf("(%x) ticket: %+v\n", net.tab.self.ID[:8], pkt.data)
		net.ticketStore.addTicket(now, pkt.data.(*pong).ReplyTok, ticket)
	} else {
		log.Trace("Failed to convert pong to ticket", "err", err)
	}
	n.pingEcho = nil
	n.pingTopics = nil
	return err
}

func (net *Network) handleQueryEvent(n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
	switch ev {
	case findnodePacket:
		target := crypto.Keccak256Hash(pkt.data.(*findnode).Target[:])
		results := net.tab.closest(target, bucketSize).entries
		net.conn.sendNeighbours(n, results)
		return n.state, nil
	case neighborsPacket:
		err := net.handleNeighboursPacket(n, pkt)
		return n.state, err
	case neighboursTimeout:
		if n.pendingNeighbours != nil {
			n.pendingNeighbours.reply <- nil
			n.pendingNeighbours = nil
		}
		n.queryTimeouts++
		if n.queryTimeouts > maxFindnodeFailures && n.state == known {
			return contested, errors.New("too many timeouts")
		}
		return n.state, nil

	// v5

	case findnodeHashPacket:
		results := net.tab.closest(pkt.data.(*findnodeHash).Target, bucketSize).entries
		net.conn.sendNeighbours(n, results)
		return n.state, nil
	case topicRegisterPacket:
		//fmt.Println("got topicRegisterPacket")
		regdata := pkt.data.(*topicRegister)
		pong, err := net.checkTopicRegister(regdata)
		if err != nil {
			//fmt.Println(err)
			return n.state, fmt.Errorf("bad waiting ticket: %v", err)
		}
		net.topictab.useTicket(n, pong.TicketSerial, regdata.Topics, int(regdata.Idx), pong.Expiration, pong.WaitPeriods)
		return n.state, nil
	case topicQueryPacket:
		// TODO: handle expiration
		topic := pkt.data.(*topicQuery).Topic
		results := net.topictab.getEntries(topic)
		if _, ok := net.ticketStore.tickets[topic]; ok {
			results = append(results, net.tab.self) // we're not registering in our own table but if we're advertising, return ourselves too
		}
		if len(results) > 10 {
			results = results[:10]
		}
		var hash common.Hash
		copy(hash[:], pkt.hash)
		net.conn.sendTopicNodes(n, hash, results)
		return n.state, nil
	case topicNodesPacket:
		p := pkt.data.(*topicNodes)
		if net.ticketStore.gotTopicNodes(n, p.Echo, p.Nodes) {
			n.queryTimeouts++
			if n.queryTimeouts > maxFindnodeFailures && n.state == known {
				return contested, errors.New("too many timeouts")
			}
		}
		return n.state, nil

	default:
		return n.state, errInvalidEvent
	}
}

func (net *Network) checkTopicRegister(data *topicRegister) (*pong, error) {
	var pongpkt ingressPacket
	if err := decodePacket(data.Pong, &pongpkt); err != nil {
		return nil, err
	}
	if pongpkt.ev != pongPacket {
		return nil, errors.New("is not pong packet")
	}
	if pongpkt.remoteID != net.tab.self.ID {
		return nil, errors.New("not signed by us")
	}
	// check that we previously authorised all topics
	// that the other side is trying to register.
	if rlpHash(data.Topics) != pongpkt.data.(*pong).TopicHash {
		return nil, errors.New("topic hash mismatch")
	}
	if int(data.Idx) < 0 || int(data.Idx) >= len(data.Topics) {
		return nil, errors.New("topic index out of range")
	}
	return pongpkt.data.(*pong), nil
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func (net *Network) handleNeighboursPacket(n *Node, pkt *ingressPacket) error {
	if n.pendingNeighbours == nil {
		return errNoQuery
	}
	net.abortTimedEvent(n, neighboursTimeout)

	req := pkt.data.(*neighbors)
	nodes := make([]*Node, len(req.Nodes))
	for i, rn := range req.Nodes {
		nn, err := net.internNodeFromNeighbours(pkt.remoteAddr, rn)
		if err != nil {
			log.Debug(fmt.Sprintf("invalid neighbour (%v) from %x@%v: %v", rn.IP, n.ID[:8], pkt.remoteAddr, err))
			continue
		}
		nodes[i] = nn
		// Start validation of query results immediately.
		// This fills the table quickly.
		// TODO: generates way too many packets, maybe do it via queue.
		if nn.state == unknown {
			net.transition(nn, verifyinit)
		}
	}
	// TODO: don't ignore second packet
	n.pendingNeighbours.reply <- nodes
	n.pendingNeighbours = nil
	// Now that this query is done, start the next one.
	n.startNextQuery(net)
	return nil
}
