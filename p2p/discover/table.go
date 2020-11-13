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

// Package discover implements the Node Discovery Protocol.
//
// The Node Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.
package discover

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/crypto"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/p2p/netutil"
)

const (
	alpha           = 3  // Kademlia concurrency factor
	bucketSize      = 16 // Kademlia bucket size
	maxReplacements = 10 // Size of per-bucket replacement list

	// We keep buckets for the upper 1/15 of distances because
	// it's very unlikely we'll ever encounter a node that's closer.
	hashBits          = len(common.Hash{}) * 8
	nBuckets          = hashBits / 15       // Number of buckets
	bucketMinDistance = hashBits - nBuckets // Log distance of closest bucket

	// IP address limits.
	bucketIPLimit, bucketSubnet = 2, 24 // at most 2 addresses from the same /24
	tableIPLimit, tableSubnet   = 10, 24

	maxFindnodeFailures = 5 // Nodes exceeding this limit are dropped
	refreshInterval     = 30 * time.Minute			// 每 30 分钟做刷桶
	revalidateInterval  = 10 * time.Second			// 重新验证 k-bucket 间隔,  10 s
	copyNodesInterval   = 30 * time.Second
	seedMinTableTime    = 5 * time.Minute
	seedCount           = 30
	seedMaxAge          = 5 * 24 * time.Hour
)

type Table struct {
	mutex   sync.Mutex        // protects buckets, bucket content, nursery, rand
	buckets [nBuckets]*bucket // index of known nodes by distance

	// 存放 引导节点, 种子节点   nursery: 苗圃
	nursery []*Node           // bootstrap nodes
	rand    *mrand.Rand       // source of randomness, periodically reseeded
	ips     netutil.DistinctNetSet

	db         *nodeDB // database of known nodes
	refreshReq chan chan struct{}
	initDone   chan struct{}
	closeReq   chan struct{}
	closed     chan struct{}

	nodeAddedHook func(*Node) // for testing

	net  transport
	self *Node // metadata of the local node
}

// transport is implemented by the UDP transport.
// it is an interface so we can test without opening lots of UDP
// sockets and without generating a private key.
type transport interface {
	ping(NodeID, *net.UDPAddr) error
	findnode(toid NodeID, addr *net.UDPAddr, target NodeID) ([]*Node, error)
	close()
}

// bucket contains nodes, ordered by their last activity. the entry
// that was most recently active is the first element in entries.
type bucket struct {

	// k-bucket 的真实队列  (最多放 16 个)
	entries      []*Node // live entries, sorted by time of last contact      		实时条目，按上次联系时间排序

	// k-bucket 的备选队列 (在entries 满时, 没有直接丢掉 node， 而是先加到这里)  最多放 10 个
	replacements []*Node // recently seen nodes to be used if revalidation fails    如果重新验证失败，则使用最近使用的节点
	ips          netutil.DistinctNetSet
}

func newTable(t transport, ourID NodeID, ourAddr *net.UDPAddr, nodeDBPath string, bootnodes []*Node) (*Table, error) {
	// If no node database was given, use an in-memory one
	db, err := newNodeDB(nodeDBPath, nodeDBVersion, ourID)  // todo 实例化一个 存放  node 信息的 leveldb
	if err != nil {
		return nil, err
	}
	tab := &Table{
		net:        t,
		db:         db,
		self:       NewNode(ourID, ourAddr.IP, uint16(ourAddr.Port), uint16(ourAddr.Port)),
		refreshReq: make(chan chan struct{}),
		initDone:   make(chan struct{}),
		closeReq:   make(chan struct{}),
		closed:     make(chan struct{}),
		rand:       mrand.New(mrand.NewSource(0)),
		ips:        netutil.DistinctNetSet{Subnet: tableSubnet, Limit: tableIPLimit},
	}
	if err := tab.setFallbackNodes(bootnodes); err != nil { // 设置启动节点信息到桶的tab.nursery数组中
		return nil, err
	}

	// 先实例化 table 中的  257 个 空的 bucket 实例
	for i := range tab.buckets {
		tab.buckets[i] = &bucket{
			ips: netutil.DistinctNetSet{Subnet: bucketSubnet, Limit: bucketIPLimit},
		}
	}

	tab.seedRand()			// 初始化 table 的 随机种子,  到时候 节点发现生成 随机的target 用的
	tab.loadSeedNodes()		// 从 本地 db 中 随机加载一部分 (活跃的) node 信息 和 配置的 种子节点一起返回  (用来做 启动引导用)
	// Start the background expiration goroutine after loading seeds so that the search for
	// seed nodes also considers older nodes that would otherwise be removed by the
	// expiration.
	tab.db.ensureExpirer()		// 启动  db 中清除 (不活跃) node的信息
	go tab.loop()  // 异步启动刷桶逻辑
	return tab, nil
}

func (tab *Table) seedRand() {
	var b [8]byte
	crand.Read(b[:])

	tab.mutex.Lock()
	tab.rand.Seed(int64(binary.BigEndian.Uint64(b[:])))
	tab.mutex.Unlock()
}

// Self returns the local node.
// The returned node should not be modified by the caller.
func (tab *Table) Self() *Node {
	return tab.self
}

// ReadRandomNodes fills the given slice with random nodes from the
// table. It will not write the same node more than once. The nodes in
// the slice are copies and can be modified by the caller.
func (tab *Table) ReadRandomNodes(buf []*Node) (n int) {
	if !tab.isInitDone() {
		return 0
	}
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// Find all non-empty buckets and get a fresh slice of their entries.
	var buckets [][]*Node
	for _, b := range &tab.buckets {
		if len(b.entries) > 0 {
			buckets = append(buckets, b.entries[:])
		}
	}
	if len(buckets) == 0 {
		return 0
	}
	// Shuffle the buckets.
	for i := len(buckets) - 1; i > 0; i-- {
		j := tab.rand.Intn(len(buckets))
		buckets[i], buckets[j] = buckets[j], buckets[i]
	}
	// Move head of each bucket into buf, removing buckets that become empty.
	var i, j int
	for ; i < len(buf); i, j = i+1, (j+1)%len(buckets) {
		b := buckets[j]
		buf[i] = &(*b[0])
		buckets[j] = b[1:]
		if len(b) == 1 {
			buckets = append(buckets[:j], buckets[j+1:]...)
		}
		if len(buckets) == 0 {
			break
		}
	}
	return i + 1
}

// Close terminates the network listener and flushes the node database.
func (tab *Table) Close() {
	select {
	case <-tab.closed:
		// already closed.
	case tab.closeReq <- struct{}{}:
		<-tab.closed // wait for refreshLoop to end.
	}
}

// setFallbackNodes sets the initial points of contact. These nodes
// are used to connect to the network if the table is empty and there
// are no known nodes in the database.
func (tab *Table) setFallbackNodes(nodes []*Node) error { // 设置启动节点信息到桶的tab.nursery数组中
	for _, n := range nodes {
		if err := n.validateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap/fallback node %q (%v)", n, err)
		}
	}
	tab.nursery = make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		cpy := *n
		// Recompute cpy.sha because the node might not have been
		// created by NewNode or ParseNode.
		cpy.sha = crypto.Keccak256Hash(n.ID[:])
		tab.nursery = append(tab.nursery, &cpy)
	}
	return nil
}

// isInitDone returns whether the table's initial seeding procedure has completed.
func (tab *Table) isInitDone() bool {
	select {
	case <-tab.initDone:
		return true
	default:
		return false
	}
}

// Resolve searches for a specific node with the given ID.
// It returns nil if the node could not be found.
func (tab *Table) Resolve(targetID NodeID) *Node {
	// If the node is present in the local table, no
	// network interaction is required.
	hash := crypto.Keccak256Hash(targetID[:])
	tab.mutex.Lock()
	cl := tab.closest(hash, 1)
	tab.mutex.Unlock()
	if len(cl.entries) > 0 && cl.entries[0].ID == targetID {
		return cl.entries[0]
	}
	// Otherwise, do a network lookup.
	result := tab.Lookup(targetID)  // 做 k-bucket 的刷桶    (tab *Table) Resolve(targetID NodeID)   只有   (t *dialTask) Do() 连接对端peer时 会调到这里来 ...
	for _, n := range result {
		if n.ID == targetID {   // 返回 目标节点
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
func (tab *Table) Lookup(targetID NodeID) []*Node {
	return tab.lookup(targetID, true)   // 最终是调用 真正刷桶的动作    (tab *Table) Lookup(targetID NodeID)
}

// 真正激发刷桶动作的函数
func (tab *Table) lookup(targetID NodeID, refreshIfEmpty bool) []*Node {
	var (
		target         = crypto.Keccak256Hash(targetID[:])  // 对 nodeId 算 hash
		asked          = make(map[NodeID]bool)
		seen           = make(map[NodeID]bool)
		reply          = make(chan []*Node, alpha)
		pendingQueries = 0
		result         *nodesByDistance
	)
	// don't query further if we hit ourself.
	// unlikely to happen often in practice.
	asked[tab.self.ID] = true

	for {
		tab.mutex.Lock()
		// generate initial result set
		result = tab.closest(target, bucketSize)   // 先根据 target 找出 16 个 和target比较近的 结果
		tab.mutex.Unlock()
		if len(result.entries) > 0 || !refreshIfEmpty {
			break
		}
		// The result set is empty, all nodes were dropped, refresh.
		// We actually wait for the refresh to complete here. The very
		// first query will hit this case and run the bootstrapping
		// logic.
		<-tab.refresh()  // 调用 主动发起 刷桶请求, 并返回 done 的信号通道
		refreshIfEmpty = false
	}


	// 先根据 target 找出 16 个 和target比较近的 node  去做 p2p 发现
	for {
		// ask the alpha closest nodes that we haven't asked yet
		for i := 0; i < len(result.entries) && pendingQueries < alpha; i++ {
			n := result.entries[i]
			if !asked[n.ID] {
				asked[n.ID] = true
				pendingQueries++
				go tab.findnode(n, targetID, reply)   // todo 发起  FIND_NODE
			}
		}
		if pendingQueries == 0 {
			// we have asked all closest nodes, stop the search
			break
		}
		// wait for the next reply
		for _, n := range <-reply {
			if n != nil && !seen[n.ID] {
				seen[n.ID] = true
				result.push(n, bucketSize)
			}
		}
		pendingQueries--
	}
	return result.entries
}

func (tab *Table) findnode(n *Node, targetID NodeID, reply chan<- []*Node) {
	fails := tab.db.findFails(n.ID)
	r, err := tab.net.findnode(n.ID, n.addr(), targetID)  // 向  n 节点发起 FIND_NODE 消息包, 请求查找 target 节点
	if err != nil || len(r) == 0 {
		fails++
		tab.db.updateFindFails(n.ID, fails)
		log.Trace("Findnode failed", "id", n.ID, "failcount", fails, "err", err)
		if fails >= maxFindnodeFailures {
			log.Trace("Too many findnode failures, dropping", "id", n.ID, "failcount", fails)
			tab.delete(n)
		}
	} else if fails > 0 {
		tab.db.updateFindFails(n.ID, fails-1)
	}

	// Grab as many nodes as possible. Some of them might not be alive anymore, but we'll
	// just remove those again during revalidation.
	for _, n := range r {
		tab.add(n)
	}
	reply <- r
}

func (tab *Table) refresh() <-chan struct{} {  //  主动发起 刷桶请求, 并返回 done 的信号通道
	done := make(chan struct{})
	select {
	case tab.refreshReq <- done:
	case <-tab.closed:
		close(done)
	}
	return done
}

// loop schedules refresh, revalidate runs and coordinates shutdown.
func (tab *Table) loop() {  // 异步启动刷桶逻辑
	var (
		revalidate     = time.NewTimer(tab.nextRevalidateTime())   	// 从 [0, 10s) 随机一个时间, 作为 随机 对 k-bucket 的内容做验证, 更新桶 (清除失效的 node)
		refresh        = time.NewTicker(refreshInterval)			// 每30分钟 节点发现刷桶
		copyNodes      = time.NewTicker(copyNodesInterval)			// 30秒
		revalidateDone = make(chan struct{})
		refreshDone    = make(chan struct{})           // where doRefresh reports completion
		waiting        = []chan struct{}{tab.initDone} // holds waiting callers while doRefresh runs
	)
	defer refresh.Stop()
	defer revalidate.Stop()
	defer copyNodes.Stop()

	// Start initial refresh.
	go tab.doRefresh(refreshDone)  // 进来先刷一波 桶

loop:
	for {
		select {

		// 每30分钟 节点发现刷桶
		case <-refresh.C:
			tab.seedRand()
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)  // 每30分钟 节点发现刷桶
			}
		// 接收到 刷桶 req
		case req := <-tab.refreshReq:
			waiting = append(waiting, req)  // waiting 是个  done 信号通道的 队列
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone) // 接收到 刷桶 req
			}
		case <-refreshDone:
			for _, ch := range waiting {  // 逐个处理 done 通道
				close(ch)
			}
			waiting, refreshDone = nil, nil

		// [0, 10s)
		case <-revalidate.C:
			go tab.doRevalidate(revalidateDone)  // [0, 10s) 验证 k-bucket 中的 node 的有效性,  ping-pong
		case <-revalidateDone:
			revalidate.Reset(tab.nextRevalidateTime())
		// 每 30 s 一次
		case <-copyNodes.C:
			go tab.copyLiveNodes() // （每 30 s 一次） 如果 node 在表中的存在时间超过了minTableTime，则copyLiveNodes() 将表中的 node 添加到 db 中
		case <-tab.closeReq:
			break loop
		}
	}

	if tab.net != nil {
		tab.net.close()
	}
	if refreshDone != nil {
		<-refreshDone
	}
	for _, ch := range waiting {
		close(ch)
	}
	tab.db.close()
	close(tab.closed)
}

// doRefresh performs a lookup for a random target to keep buckets
// full. seed nodes are inserted if the table is empty (initial
// bootstrap or discarded faulty peers).
func (tab *Table) doRefresh(done chan struct{}) {
	defer close(done)

	// Load nodes from the database and insert
	// them. This should yield a few previously seen nodes that are
	// (hopefully) still alive.
	//
	// 从 db 加载节点并将其插入. 这应该会产生一些以前希望看到的仍然活跃的节点.
	tab.loadSeedNodes()   // 从 本地 db 中 随机加载一部分 (活跃的) node 信息 和 配置的 种子节点一起返回  (用来做 启动引导用)

	// Run self lookup to discover new neighbor nodes.
	//
	// 先加载一波静态节点，然后根据当前节点信息先去刷一波桶拉回据当前节点的邻居节点
	tab.lookup(tab.self.ID, false)  // 这个才是做刷桶的动作      (tab *Table) doRefresh(done chan struct{}) 刷桶

	// The Kademlia paper specifies that the bucket refresh should
	// perform a lookup in the least recently used bucket. We cannot
	// adhere to this because the findnode target is a 512bit value
	// (not hash-sized) and it is not easily possible to generate a
	// sha3 preimage that falls into a chosen bucket.
	// We perform a few lookups with a random target instead.
	//
	//
	// Kademlia论文指定存储桶刷新 应在  最近最少使用  的存储桶中执行查找.
	// 我们不能坚持这一点，因为findnode目标是512位的值（不是散列大小），并且不容易生成落入所选存储桶的 sha3 preimage
	// 我们使用随机目标执行一些查找
	//
	for i := 0; i < 3; i++ {  // todo  for 3 次循环，每次生成一个随机nodeID即：target，再根据target去刷桶拉回距随机target节点的邻居节点
		var target NodeID
		crand.Read(target[:])
		tab.lookup(target, false) // 这个才是做刷桶的动作    (tab *Table) doRefresh(done chan struct{}) 刷桶  (3次刷桶, 对3个随机target节点做刷桶)
	}
}

// 从 本地 db 中 随机加载一部分 (活跃的) node 信息 和 配置的 种子节点一起返回
func (tab *Table) loadSeedNodes() {
	seeds := tab.db.querySeeds(seedCount, seedMaxAge)  	// 从 本地 db 中 随机加载一部分 (活跃的) node 信息
	seeds = append(seeds, tab.nursery...)  				// 将 引导节点(种子节点) 追加进去
	for i := range seeds {
		seed := seeds[i]
		age := log.Lazy{Fn: func() interface{} { return time.Since(tab.db.lastPongReceived(seed.ID)) }}
		log.Debug("Found seed node in database", "id", seed.ID, "addr", seed.addr(), "age", age)
		tab.add(seed)
	}
}

// doRevalidate checks that the last node in a random bucket is still live
// and replaces or deletes the node if it isn't.
func (tab *Table) doRevalidate(done chan<- struct{}) {  // 随机 验证 k-bucket 中的 某一个 node 的有效性,  ping-pong
	defer func() { done <- struct{}{} }()

	last, bi := tab.nodeToRevalidate()  // todo 返回  随机的 k-bucket 中 最后一个 node 和 第几个k-bucket 的索引.  (在队头的是新加的, 理论上 队尾的才是和当前node 认识最久的. 这里和正常的 kad 网络做法相反, 人家的是 认识最久的在 队首 新加的在队尾)
	if last == nil {
		// No non-empty bucket found.
		return
	}

	// Ping the selected node and wait for a pong.
	err := tab.net.ping(last.ID, last.addr())  // todo 对该 node 发出 ping 消息

	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	b := tab.buckets[bi]  // todo 获取该 last node 对用的 k-bucket
	if err == nil {
		// The node responded, move it to the front.
		log.Trace("Revalidated node", "b", bi, "id", last.ID)
		b.bump(last)
		return
	}

	// 如果有  ping - pong 的 p2p 消息 err,  那么需要使用一个 备选的 node 替换 这个 last node

	// No reply received, pick a replacement or delete the node if there aren't
	// any replacements.
	if r := tab.replace(b, last); r != nil {  // 从 k-bucket 的备选队列 replacements 中将 node 移动到 正常队列 entries 中
		log.Trace("Replaced dead node", "b", bi, "id", last.ID, "ip", last.IP, "r", r.ID, "rip", r.IP)
	} else {
		log.Trace("Removed dead node", "b", bi, "id", last.ID, "ip", last.IP)
	}
}

// nodeToRevalidate returns the last node in a random, non-empty bucket.
//
// `nodeToRevalidate()` 返回 随机非空存储桶中的最后一个节点.
func (tab *Table) nodeToRevalidate() (n *Node, bi int) {  // 随机返回 一个 node
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, bi = range tab.rand.Perm(len(tab.buckets)) {
		b := tab.buckets[bi]
		if len(b.entries) > 0 {
			last := b.entries[len(b.entries)-1]
			return last, bi
		}
	}
	return nil, 0
}

func (tab *Table) nextRevalidateTime() time.Duration {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	return time.Duration(tab.rand.Int63n(int64(revalidateInterval)))   // 从 [0, 10s) 随机一个时间
}

// copyLiveNodes adds nodes from the table to the database if they have been in the table
// longer then minTableTime.
//
// 如果节点在表中的存在时间超过了minTableTime，则copyLiveNodes() 将表中的节点添加到 db 中
//
// (在表中 呆的越久, 说明节点 稳定性越高, 大概率上没退出网络)
func (tab *Table) copyLiveNodes() {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	now := time.Now()

	// 遍历所有 k-bucket 中的 node
	for _, b := range &tab.buckets {
		for _, n := range b.entries {

			// 如果在 bucket 中呆的时间 超过 seedMinTableTime (5分钟), todo 说明节点越稳定,  将它的信息 刷入 db
			if now.Sub(n.addedAt) >= seedMinTableTime {
				tab.db.updateNode(n)  // 将一个节点（可能会覆盖）插入到 peer db 中
			}
		}
	}
}

// closest returns the n nodes in the table that are closest to the
// given id. The caller must hold tab.mutex.
func (tab *Table) closest(target common.Hash, nresults int) *nodesByDistance {
	// This is a very wasteful way to find the closest nodes but
	// obviously correct. I believe that tree-based buckets would make
	// this easier to implement efficiently.
	close := &nodesByDistance{target: target}  // 用来收集 和 target 距离最近的 一些 node
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			close.push(n, nresults)  // 取 距离target 更近的 nresults 个 node
		}
	}
	return close
}

func (tab *Table) len() (n int) {
	for _, b := range &tab.buckets {
		n += len(b.entries)
	}
	return n
}

// bucket returns the bucket for the given node ID hash.
func (tab *Table) bucket(sha common.Hash) *bucket { // 根据sha 节点 和 当前本地节点的 距离, 返回 table 中对应的 k-bucket
	d := logdist(tab.self.sha, sha)  // 计算 sha 节点 和 当前本地节点的 距离
	if d <= bucketMinDistance {
		return tab.buckets[0]
	}
	return tab.buckets[d-bucketMinDistance-1]  // 返回 table 中对应的 k-bucket
}

// add attempts to add the given node to its corresponding bucket. If the bucket has space
// available, adding the node succeeds immediately. Otherwise, the node is added if the
// least recently active node in the bucket does not respond to a ping packet.
//
// The caller must not hold tab.mutex.
func (tab *Table) add(n *Node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	b := tab.bucket(n.sha)   // 根据sha 节点 和 当前本地节点的 距离, 返回 table 中对应的 k-bucket
	if !tab.bumpOrAdd(b, n) {  // 加入 k-bucket 中, 如果桶满了, 则加到 备选中
		// Node is not in table. Add it to the replacement list.
		tab.addReplacement(b, n)
	}
}

// addThroughPing adds the given node to the table. Compared to plain
// 'add' there is an additional safety measure: if the table is still
// initializing the node is not added. This prevents an attack where the
// table could be filled by just sending ping repeatedly.
//
// The caller must not hold tab.mutex.
func (tab *Table) addThroughPing(n *Node) {
	if !tab.isInitDone() {
		return
	}
	tab.add(n)
}

// stuff adds nodes the table to the end of their corresponding bucket
// if the bucket is not full. The caller must not hold tab.mutex.
func (tab *Table) stuff(nodes []*Node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, n := range nodes {
		if n.ID == tab.self.ID {
			continue // don't add self
		}
		b := tab.bucket(n.sha)
		if len(b.entries) < bucketSize {
			tab.bumpOrAdd(b, n)
		}
	}
}

// delete removes an entry from the node table. It is used to evacuate dead nodes.
func (tab *Table) delete(node *Node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	tab.deleteInBucket(tab.bucket(node.sha), node)
}

func (tab *Table) addIP(b *bucket, ip net.IP) bool {
	if netutil.IsLAN(ip) {
		return true
	}
	if !tab.ips.Add(ip) {
		log.Debug("IP exceeds table limit", "ip", ip)
		return false
	}
	if !b.ips.Add(ip) {
		log.Debug("IP exceeds bucket limit", "ip", ip)
		tab.ips.Remove(ip)
		return false
	}
	return true
}

func (tab *Table) removeIP(b *bucket, ip net.IP) {
	if netutil.IsLAN(ip) {
		return
	}
	tab.ips.Remove(ip)
	b.ips.Remove(ip)
}

func (tab *Table) addReplacement(b *bucket, n *Node) {
	for _, e := range b.replacements {
		if e.ID == n.ID {
			return // already in list
		}
	}
	if !tab.addIP(b, n.IP) {
		return
	}
	var removed *Node
	b.replacements, removed = pushNode(b.replacements, n, maxReplacements)  // 加到 备选队列中 (10 个 node)
	if removed != nil {
		tab.removeIP(b, removed.IP)
	}
}

// replace removes n from the replacement list and replaces 'last' with it if it is the
// last entry in the bucket. If 'last' isn't the last entry, it has either been replaced
// with someone else or became active.
func (tab *Table) replace(b *bucket, last *Node) *Node {  // 从 k-bucket 的备选队列 replacements 中将 node 移动到 正常队列 entries 中
	if len(b.entries) == 0 || b.entries[len(b.entries)-1].ID != last.ID {
		// Entry has moved, don't replace it.
		return nil
	}
	// Still the last entry.
	if len(b.replacements) == 0 {
		tab.deleteInBucket(b, last)
		return nil
	}

	// 从 k-bucket 的备选队列 replacements 中将 node 移动到 正常队列 entries 中
	r := b.replacements[tab.rand.Intn(len(b.replacements))]
	b.replacements = deleteNode(b.replacements, r)
	b.entries[len(b.entries)-1] = r
	tab.removeIP(b, last.IP)
	return r
}

// bump moves the given node to the front of the bucket entry list
// if it is contained in that list.
func (b *bucket) bump(n *Node) bool {
	for i := range b.entries {
		if b.entries[i].ID == n.ID {
			// move it to the front
			copy(b.entries[1:], b.entries[:i])
			b.entries[0] = n
			return true
		}
	}
	return false
}

// bumpOrAdd moves n to the front of the bucket entry list or adds it if the list isn't
// full. The return value is true if n is in the bucket.
func (tab *Table) bumpOrAdd(b *bucket, n *Node) bool {
	if b.bump(n) {
		return true
	}
	if len(b.entries) >= bucketSize || !tab.addIP(b, n.IP) {   // 桶满了, 直接丢掉 n (在外面会把它 加入到 备选队列  replacements 中的 ...)
		return false
	}

	// 正常 加入 k-bucket 中,  需要检查是否从 备选队列 中移除, (因为上一次可能已经将 n 加入备选队列中了)
	b.entries, _ = pushNode(b.entries, n, bucketSize) // 加入 k-bucket 的正常队列  （16个node）
	b.replacements = deleteNode(b.replacements, n)
	n.addedAt = time.Now()
	if tab.nodeAddedHook != nil {
		tab.nodeAddedHook(n)
	}
	return true
}

func (tab *Table) deleteInBucket(b *bucket, n *Node) {
	b.entries = deleteNode(b.entries, n)
	tab.removeIP(b, n.IP)
}

// pushNode adds n to the front of list, keeping at most max items.
func pushNode(list []*Node, n *Node, max int) ([]*Node, *Node) {
	if len(list) < max {
		list = append(list, nil)
	}
	removed := list[len(list)-1]
	copy(list[1:], list)
	list[0] = n  // 新进来的 node 加到 bucket 头部
	return list, removed
}

// deleteNode removes n from list.
func deleteNode(list []*Node, n *Node) []*Node {
	for i := range list {
		if list[i].ID == n.ID {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// nodesByDistance is a list of nodes, ordered by
// distance to target.
type nodesByDistance struct {  // 用来收集 和 target 距离最近的 一些 node
	entries []*Node
	target  common.Hash
}

// push adds the given node to the list, keeping the total size below maxElems.
func (h *nodesByDistance) push(n *Node, maxElems int) {  // 取 距离target 更近的 maxElems 个 node
	ix := sort.Search(len(h.entries), func(i int) bool {
		return distcmp(h.target, h.entries[i].sha, n.sha) > 0   // 取 距离target 更近的 node
	})
	if len(h.entries) < maxElems {
		h.entries = append(h.entries, n)
	}
	if ix == len(h.entries) {
		// farther away than all nodes we already have.
		// if there was room for it, the node is now the last element.
	} else {
		// slide existing entries down to make room
		// this will overwrite the entry we just appended.
		copy(h.entries[ix+1:], h.entries[ix:])
		h.entries[ix] = n
	}
}
