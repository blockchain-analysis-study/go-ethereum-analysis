// Copyright 2018 The github.com/go-ethereum-analysis Authors
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

package trie

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/ethdb"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/metrics"
	"github.com/go-ethereum-analysis/rlp"
)

var (
	memcacheFlushTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/flush/time", nil)
	memcacheFlushNodesMeter = metrics.NewRegisteredMeter("trie/memcache/flush/nodes", nil)
	memcacheFlushSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/flush/size", nil)

	memcacheGCTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/gc/time", nil)
	memcacheGCNodesMeter = metrics.NewRegisteredMeter("trie/memcache/gc/nodes", nil)
	memcacheGCSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/gc/size", nil)

	memcacheCommitTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/commit/time", nil)
	memcacheCommitNodesMeter = metrics.NewRegisteredMeter("trie/memcache/commit/nodes", nil)
	memcacheCommitSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/commit/size", nil)
)

// secureKeyPrefix is the database key prefix used to store trie node preimages.
var secureKeyPrefix = []byte("secure-key-")

// secureKeyLength is the length of the above prefix + 32byte hash.
const secureKeyLength = 11 + 32

// DatabaseReader wraps the Get and Has method of a backing store for the trie.
type DatabaseReader interface {
	// Get retrieves the value associated with key from the database.
	Get(key []byte) (value []byte, err error)

	// Has retrieves whether a key is present in the database.
	Has(key []byte) (bool, error)
}

// Database is an intermediate write layer between the trie data structures and
// the disk database. The aim is to accumulate trie writes in-memory and only
// periodically flush a couple tries to disk, garbage collecting the remainder.
//
/**
Database
	todo 是在 `trie数据结构` 和 `磁盘数据库` 之间的中间写入层。
		目的是在内存中累积trie写操作，并且仅定期刷新一对尝试写入磁盘的内容，垃圾收集剩余的内容。
 */
type Database struct {
	// 永久存储成熟的Trie节点
	diskdb ethdb.Database // Persistent storage for matured trie nodes

	// trie node 的 数据 和 Hash 关系   todo (node.key 做了 compact编码之后的node计算的hash作为 key ->  并将该node作为 value)
	nodes  map[common.Hash]*cachedNode // Data and references relationships of a node

	// 最早跟踪的节点，刷新列表头
	oldest common.Hash                 // Oldest tracked node, flush-list head
	// 最新跟踪的节点，刷新列表尾
	newest common.Hash                 // Newest tracked node, flush-list tail

	// 安全Trie中节点的原像
	preimages map[common.Hash][]byte // Preimages of nodes from the secure trie
	// 临时缓冲区，用于计算 preimage keys
	seckeybuf [secureKeyLength]byte  // Ephemeral buffer for calculating preimage keys

	// 自上次提交以来在 gc 上花费的时间
	gctime  time.Duration      // Time spent on garbage collection since last commit
	// 自上次提交以来 gc的node个数
	gcnodes uint64             // Nodes garbage collected since last commit
	// 自上次提交以来 gc的存储数据数量
	gcsize  common.StorageSize // Data storage garbage collected since last commit

	// 自上次提交以来花在数据刷新上的时间
	flushtime  time.Duration      // Time spent on data flushing since last commit
	// 自上次提交以来 节点被刷新的个数
	flushnodes uint64             // Nodes flushed since last commit
	// 自上次以来 被刷新的数据数量
	flushsize  common.StorageSize // Data storage flushed since last commit

	// 节点缓存的存储大小（不包括刷新列表）
	nodesSize     common.StorageSize // Storage size of the nodes cache (exc. flushlist)

	// preimages缓存的存储大小
	preimagesSize common.StorageSize // Storage size of the preimages cache

	lock sync.RWMutex
}

// rawNode is a simple binary blob used to differentiate between collapsed trie
// nodes and already encoded RLP binary blobs (while at the same time store them
// in the same cache fields).
type rawNode []byte

func (n rawNode) canUnload(uint16, uint16) bool { panic("this should never end up in a live trie") }
func (n rawNode) cache() (hashNode, bool)       { panic("this should never end up in a live trie") }
func (n rawNode) fstring(ind string) string     { panic("this should never end up in a live trie") }

// rawFullNode represents only the useful data content of a full node, with the
// caches and flags stripped out to minimize its data storage. This type honors
// the same RLP encoding as the original parent.
type rawFullNode [17]node

func (n rawFullNode) canUnload(uint16, uint16) bool { panic("this should never end up in a live trie") }
func (n rawFullNode) cache() (hashNode, bool)       { panic("this should never end up in a live trie") }
func (n rawFullNode) fstring(ind string) string     { panic("this should never end up in a live trie") }

func (n rawFullNode) EncodeRLP(w io.Writer) error {
	var nodes [17]node

	for i, child := range n {
		if child != nil {
			nodes[i] = child
		} else {
			nodes[i] = nilValueNode
		}
	}
	return rlp.Encode(w, nodes)
}

// rawShortNode represents only the useful data content of a short node, with the
// caches and flags stripped out to minimize its data storage. This type honors
// the same RLP encoding as the original parent.

/**
rawShortNode 仅表示 短节点 的有用数据内容，其中剥离了缓存和 flags
（node 四种实现中的fullNode 和shortNode 都有的flags，表示该node的Hash）
以最小化其数据存储。 此类型遵循与原始父级相同的RLP编码。

就是说和shortNode一致，只是没了cache和flags部分只剩 key和val
 */
type rawShortNode struct {
	Key []byte
	Val node
}

func (n rawShortNode) canUnload(uint16, uint16) bool { panic("this should never end up in a live trie") }
func (n rawShortNode) cache() (hashNode, bool)       { panic("this should never end up in a live trie") }
func (n rawShortNode) fstring(ind string) string     { panic("this should never end up in a live trie") }

// cachedNode is all the information we know about a single cached node in the
// memory database write layer.
/** cachedNode表示着 在内存database实例中的写入层的单个 缓存node信息 */
type cachedNode struct {
	// 缓存经过折叠的trie节点或原始rlp数据
	node node   // Cached collapsed trie node, or raw rlp data
	// 有用的缓存数据的字节大小
	// 目前剩余可用的缓存数据的 字节大小
	size uint16 // Byte size of the useful cached data

	// 引用了 当前节点的活动节点数 (也就是当前节点被多少个 parent引用着)
	parents  uint16                 // Number of live nodes referencing this one
	// 当前节点所引用的所有外部子节点 缓存
	children map[common.Hash]uint16 // External children referenced by this node

	// flush-list中的上一个节点Hash
	flushPrev common.Hash // Previous node in the flush-list
	// flush-list中的下一个节点Hash
	flushNext common.Hash // Next node in the flush-list
}

// rlp returns the raw rlp encoded blob of the cached node, either directly from
// the cache, or by regenerating it from the collapsed node.
func (n *cachedNode) rlp() []byte {
	if node, ok := n.node.(rawNode); ok {
		return node
	}
	blob, err := rlp.EncodeToBytes(n.node)
	if err != nil {
		panic(err)
	}
	return blob
}

// obj returns the decoded and expanded trie node, either directly from the cache,
// or by regenerating it from the rlp encoded blob.
func (n *cachedNode) obj(hash common.Hash, cachegen uint16) node {
	if node, ok := n.node.(rawNode); ok {
		return mustDecodeNode(hash[:], node, cachegen)  // todo 这里会做. 将 node.key 从 compact 编码转回 hex 编码
	}
	return expandNode(hash[:], n.node, cachegen)
}

// childs returns all the tracked children of this node, both the implicit ones
// from inside the node as well as the explicit ones from outside the node.
// childs函数 返回 当前节点的所有（被跟踪）子节点，包括节点内部的隐式子节点以及节点外部的显式子节点。
func (n *cachedNode) childs() []common.Hash {
	// 缓存当前节点的所有子节点的中转 切片
	children := make([]common.Hash, 0, 16)
	// 遍历当前节点缓存的所有子节点信息
	for child := range n.children {
		children = append(children, child)
	}
	// 转化当前节点为 rawNode 类型 (这个是记录着当前节点 对应下属子节点的那 16个 hash头字符索引)
	if _, ok := n.node.(rawNode); !ok {
		gatherChildren(n.node, &children)
	}
	return children
}

// gatherChildren traverses the node hierarchy of a collapsed storage node and
// retrieves all the hashnode children.
// gatherChildren函数 会遍历折叠存储节点的节点层次结构并检索所有hashnode子节点。
/** 递归折叠节点及其子节点 */
func gatherChildren(n node, children *[]common.Hash) {
	switch n := n.(type) {
	case *rawShortNode:
		gatherChildren(n.Val, children)

	case rawFullNode:
		for i := 0; i < 16; i++ {
			gatherChildren(n[i], children)
		}
	case hashNode:
		*children = append(*children, common.BytesToHash(n))

	case valueNode, nil:

	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}

// simplifyNode traverses the hierarchy of an expanded memory node and discards
// all the internal caches, returning a node that only contains the raw data.
func simplifyNode(n node) node {
	switch n := n.(type) {
	case *shortNode:
		// Short nodes discard the flags and cascade
		return &rawShortNode{Key: n.Key, Val: simplifyNode(n.Val)}

	case *fullNode:
		// Full nodes discard the flags and cascade
		node := rawFullNode(n.Children)
		for i := 0; i < len(node); i++ {
			if node[i] != nil {
				node[i] = simplifyNode(node[i])
			}
		}
		return node

	case valueNode, hashNode, rawNode:
		return n

	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}

// expandNode traverses the node hierarchy of a collapsed storage node and converts
// all fields and keys into expanded memory form.
func expandNode(hash hashNode, n node, cachegen uint16) node {
	switch n := n.(type) {
	case *rawShortNode:
		// Short nodes need key and child expansion
		return &shortNode{
			Key: compactToHex(n.Key),
			Val: expandNode(nil, n.Val, cachegen),
			flags: nodeFlag{
				hash: hash,
				gen:  cachegen,
			},
		}

	case rawFullNode:
		// Full nodes need child expansion
		node := &fullNode{
			flags: nodeFlag{
				hash: hash,
				gen:  cachegen,
			},
		}
		for i := 0; i < len(node.Children); i++ {
			if n[i] != nil {
				node.Children[i] = expandNode(nil, n[i], cachegen)
			}
		}
		return node

	case valueNode, hashNode:
		return n

	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}

// NewDatabase creates a new trie database to store ephemeral trie content before
// its written out to disk or garbage collected.
/**
对 db 实例的封装
 */
func NewDatabase(diskdb ethdb.Database) *Database {
	/**
	返回一个 封装过后的db实例
	nodes
	 */
	return &Database{
		diskdb:    diskdb,
		// 一个存放 trie 的node的缓存 map
		nodes:     map[common.Hash]*cachedNode{{}: {}},
		// 一个存放 state 数据的缓存 map
		preimages: make(map[common.Hash][]byte),
	}
}

// DiskDB retrieves the persistent storage backing the trie database.
func (db *Database) DiskDB() DatabaseReader {
	return db.diskdb
}

// InsertBlob writes a new reference tracked blob to the memory database if it's
// yet unknown. This method should only be used for non-trie nodes that require
// reference counting, since trie nodes are garbage collected directly through
// their embedded children.
//
/**
如果尚不知道，InsertBlob 会将新的引用跟踪的Blob 写入  内存数据库。
todo 此方法仅应用于需要引用计数的非trie节点，
因为trie节点是直接通过其嵌入式子节点进行gc的。

todo 说白了目前这种只用来存储 code
 */
func (db *Database) InsertBlob(hash common.Hash, blob []byte) {
	db.lock.Lock()
	defer db.lock.Unlock()

	db.insert(hash, blob, rawNode(blob))
}

// 只有两个地方用:
//
//		InsertBlob() 直接将 code 存入db
//
//		store() 将 node 存入db
//
// insert inserts a collapsed trie node into the memory database. This method is
// a more generic version of InsertBlob, supporting both raw blob insertions as
// well ex trie node insertions. The blob must always be specified to allow proper
// size tracking.
func (db *Database) insert(hash common.Hash, blob []byte, node node) {
	// If the node's already cached, skip
	if _, ok := db.nodes[hash]; ok {
		return
	}
	// Create the cached entry for this node
	entry := &cachedNode{
		node:      simplifyNode(node),    // 简单的转换一些 node 格式   (statedb node  => db node)
		size:      uint16(len(blob)),
		flushPrev: db.newest,
	}
	for _, child := range entry.childs() {
		if c := db.nodes[child]; c != nil {
			c.parents++
		}
	}
	// todo 放入cache中    (此时的 hash  为 node.key 做了 compact 编码之后的 node计算出的hash)
	db.nodes[hash] = entry

	// Update the flush-list endpoints
	if db.oldest == (common.Hash{}) {
		db.oldest, db.newest = hash, hash
	} else {
		db.nodes[db.newest].flushNext, db.newest = hash, hash
	}
	db.nodesSize += common.StorageSize(common.HashLength + entry.size)
}

// insertPreimage writes a new trie node pre-image to the memory database if it's
// yet unknown. The method will make a copy of the slice.
//
// Note, this method assumes that the database's lock is held!
func (db *Database) insertPreimage(hash common.Hash, preimage []byte) {
	if _, ok := db.preimages[hash]; ok {
		return
	}
	db.preimages[hash] = common.CopyBytes(preimage)
	db.preimagesSize += common.StorageSize(common.HashLength + len(preimage))
}

// node retrieves a cached trie node from memory, or returns nil if none can be
// found in the memory cache.
//
// todo 根据 nodeHash 查找 node
//
// 根据 hash 去 全局 node map 中找, 找不到再从  disk 找
func (db *Database) node(hash common.Hash, cachegen uint16) node {
	// Retrieve the node from cache if available
	db.lock.RLock()
	node := db.nodes[hash]  // 先从 缓存获取 node   todo (这里的hash 是 node.key 做了 compact 编码之后的node计算的hash,  node: 就是 key 做了 compact编码后的node )
	db.lock.RUnlock()

	if node != nil {
		return node.obj(hash, cachegen)   // todo 这里会做. 将 node.key 从 compact 编码转回 hex 编码
	}
	// Content unavailable in memory, attempt to retrieve from disk
	//
	// 缓存找不到时, 从 disk 获取 node
	enc, err := db.diskdb.Get(hash[:])
	if err != nil || enc == nil {
		return nil
	}
	return mustDecodeNode(hash[:], enc, cachegen)   // todo 这里会做. 将 node.key 从 compact 编码转回 hex 编码
}

// Node retrieves an encoded cached trie node from memory. If it cannot be found
// cached, the method queries the persistent database for the content.
func (db *Database) Node(hash common.Hash) ([]byte, error) {
	// Retrieve the node from cache if available
	db.lock.RLock()
	node := db.nodes[hash]
	db.lock.RUnlock()

	if node != nil {
		return node.rlp(), nil
	}
	// Content unavailable in memory, attempt to retrieve from disk
	return db.diskdb.Get(hash[:])
}

// preimage retrieves a cached trie node pre-image from memory. If it cannot be
// found cached, the method queries the persistent database for the content.
func (db *Database) preimage(hash common.Hash) ([]byte, error) {
	// Retrieve the node from cache if available
	db.lock.RLock()
	preimage := db.preimages[hash]
	db.lock.RUnlock()

	if preimage != nil {
		return preimage, nil
	}
	// Content unavailable in memory, attempt to retrieve from disk
	return db.diskdb.Get(db.secureKey(hash[:]))
}

// secureKey returns the database key for the preimage of key, as an ephemeral
// buffer. The caller must not hold onto the return value because it will become
// invalid on the next call.
func (db *Database) secureKey(key []byte) []byte {
	buf := append(db.seckeybuf[:0], secureKeyPrefix...)
	buf = append(buf, key...)
	return buf
}

// Nodes retrieves the hashes of all the nodes cached within the memory database.
// This method is extremely expensive and should only be used to validate internal
// states in test code.
func (db *Database) Nodes() []common.Hash {
	db.lock.RLock()
	defer db.lock.RUnlock()

	var hashes = make([]common.Hash, 0, len(db.nodes))
	for hash := range db.nodes {
		if hash != (common.Hash{}) { // Special case for "root" references/nodes
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

// Reference adds a new reference from a parent node to a child node.
// 根据父节点到子节点添加新的 引用
func (db *Database) Reference(child common.Hash, parent common.Hash) {
	db.lock.RLock()
	defer db.lock.RUnlock()
	fmt.Println("进入Reference", "parent", parent.String(), "curr", child.String())
	db.reference(child, parent)
}

// reference is the private locked version of Reference.
func (db *Database) reference(child common.Hash, parent common.Hash) {
	// If the node does not exist, it's a node pulled from disk, skip
	// 如果该节点不存在，则它是从磁盘拉出的节点，跳过
	node, ok := db.nodes[child]
	if !ok {
		return
	}
	// If the reference already exists, only duplicate for roots
	// 如果引用已存在，则只复制根
	if db.nodes[parent].children == nil {
		db.nodes[parent].children = make(map[common.Hash]uint16)
	} else if _, ok = db.nodes[parent].children[child]; ok && parent != (common.Hash{}) {
		return
	}
	// 只要当前节点有被 parent引用则，他爹的计数器加一
	node.parents++
	// 把当前节点放置到对应的爹的 children map 中
	db.nodes[parent].children[child]++
}

// Dereference removes an existing reference from a root node.
// 删除掉 之前reference 中的 某个 trie root 对应的trie 的所有 node
func (db *Database) Dereference(root common.Hash) {

	// Sanity check to ensure that the meta-root is not removed
	if root == (common.Hash{}) {
		log.Error("Attempted to dereference the trie cache meta root")
		return
	}
	db.lock.Lock()
	defer db.lock.Unlock()
	fmt.Println("进入 Dereference", "curr", root.String())
	nodes, storage, start := len(db.nodes), db.nodesSize, time.Now()
	// 根据某个 node 递归删除 nodes中的该node的所有下属node
	db.dereference(root, common.Hash{})

	db.gcnodes += uint64(nodes - len(db.nodes))
	db.gcsize += storage - db.nodesSize
	db.gctime += time.Since(start)

	memcacheGCTimeTimer.Update(time.Since(start))
	memcacheGCSizeMeter.Mark(int64(storage - db.nodesSize))
	memcacheGCNodesMeter.Mark(int64(nodes - len(db.nodes)))

	log.Debug("Dereferenced trie from memory database", "nodes", nodes-len(db.nodes), "size", storage-db.nodesSize, "time", time.Since(start),
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.nodes), "livesize", db.nodesSize)
}

// dereference is the private locked version of Dereference.
func (db *Database) dereference(child common.Hash, parent common.Hash) {
	// Dereference the parent-child
	node := db.nodes[parent]

	if node.children != nil && node.children[child] > 0 {
		node.children[child]--
		if node.children[child] == 0 {
			delete(node.children, child)
		}
	}
	// If the child does not exist, it's a previously committed node.
	node, ok := db.nodes[child]
	if !ok {
		return
	}
	// If there are no more references to the child, delete it and cascade
	if node.parents > 0 {
		// This is a special cornercase where a node loaded from disk (i.e. not in the
		// memcache any more) gets reinjected as a new node (short node split into full,
		// then reverted into short), causing a cached node to have no parents. That is
		// no problem in itself, but don't make maxint parents out of it.
		node.parents--
	}
	if node.parents == 0 {
		// Remove the node from the flush-list
		switch child {
		case db.oldest:
			db.oldest = node.flushNext
			db.nodes[node.flushNext].flushPrev = common.Hash{}
		case db.newest:
			db.newest = node.flushPrev
			db.nodes[node.flushPrev].flushNext = common.Hash{}
		default:
			db.nodes[node.flushPrev].flushNext = node.flushNext
			db.nodes[node.flushNext].flushPrev = node.flushPrev
		}
		// Dereference all children and delete the node
		for _, hash := range node.childs() {
			db.dereference(hash, child)
		}
		delete(db.nodes, child)
		db.nodesSize -= common.StorageSize(common.HashLength + int(node.size))
	}
}

// Cap iteratively flushes old but still referenced trie nodes until the total
// memory usage goes below the given threshold.
/**  Cap迭代地刷新,旧的但仍然被引用的trie节点，直到总内存使用率低于给定阈值。 */
func (db *Database) Cap(limit common.StorageSize) error {
	fmt.Println("这里进入 triedb.Cap ...")
	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	/**
  	创建一个 batch 用来持久化数据。
  	外部代码看不到不一致的状态这个是很重要的
  	（所引用的数据在 commit 期间从内存缓存中删除 但尚未在持久存储中删除）。
  	当写入 levelDB 操作完成后 需要确保清空缓存中的数据
	*/

	/**
	(这里的读锁主要是用来操作 db.preimages、db.nodes) 和 batch 无关
	 */
	db.lock.RLock()

	nodes, storage, start := len(db.nodes), db.nodesSize, time.Now()
	batch := db.diskdb.NewBatch()

	// db.nodesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted. For every useful node, we track 2 extra hashes as the flushlist.
	size := db.nodesSize + common.StorageSize((len(db.nodes)-1)*2*common.HashLength)

	// If the preimage cache got large enough, push to disk. If it's still small
	// leave for later to deduplicate writes.
	flushPreimages := db.preimagesSize > 4*1024*1024
	if flushPreimages {
		for hash, preimage := range db.preimages {
			if err := batch.Put(db.secureKey(hash[:]), preimage); err != nil {
				log.Error("Failed to commit preimage from trie database", "err", err)
				db.lock.RUnlock()
				return err
			}
			if batch.ValueSize() > ethdb.IdealBatchSize {
				if err := batch.Write(); err != nil {
					db.lock.RUnlock()
					return err
				}
				batch.Reset()
			}
		}
	}
	// Keep committing nodes from the flush-list until we're below allowance
	oldest := db.oldest
	for size > limit && oldest != (common.Hash{}) {
		// Fetch the oldest referenced node and push into the batch
		node := db.nodes[oldest]
		if err := batch.Put(oldest[:], node.rlp()); err != nil {
			db.lock.RUnlock()
			return err
		}
		// If we exceeded the ideal batch size, commit and reset
		if batch.ValueSize() >= ethdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				log.Error("Failed to write flush list to disk", "err", err)
				db.lock.RUnlock()
				return err
			}
			batch.Reset()
		}
		// Iterate to the next flush item, or abort if the size cap was achieved. Size
		// is the total size, including both the useful cached data (hash -> blob), as
		// well as the flushlist metadata (2*hash). When flushing items from the cache,
		// we need to reduce both.
		size -= common.StorageSize(3*common.HashLength + int(node.size))
		oldest = node.flushNext
	}
	// Flush out any remainder data from the last batch
	if err := batch.Write(); err != nil {
		log.Error("Failed to write flush list to disk", "err", err)
		db.lock.RUnlock()
		return err
	}
	db.lock.RUnlock()

	// Write successful, clear out the flushed data
	db.lock.Lock()
	defer db.lock.Unlock()

	if flushPreimages {
		db.preimages = make(map[common.Hash][]byte)
		db.preimagesSize = 0
	}
	for db.oldest != oldest {
		node := db.nodes[db.oldest]
		delete(db.nodes, db.oldest)
		db.oldest = node.flushNext

		db.nodesSize -= common.StorageSize(common.HashLength + int(node.size))
	}
	if db.oldest != (common.Hash{}) {
		db.nodes[db.oldest].flushPrev = common.Hash{}
	}
	db.flushnodes += uint64(nodes - len(db.nodes))
	db.flushsize += storage - db.nodesSize
	db.flushtime += time.Since(start)

	memcacheFlushTimeTimer.Update(time.Since(start))
	memcacheFlushSizeMeter.Mark(int64(storage - db.nodesSize))
	memcacheFlushNodesMeter.Mark(int64(nodes - len(db.nodes)))

	log.Debug("Persisted nodes from memory database", "nodes", nodes-len(db.nodes), "size", storage-db.nodesSize, "time", time.Since(start),
		"flushnodes", db.flushnodes, "flushsize", db.flushsize, "flushtime", db.flushtime, "livenodes", len(db.nodes), "livesize", db.nodesSize)

	return nil
}

// Commit iterates over all the children of a particular node, writes them out
// to disk, forcefully tearing down all references in both directions.
// Commit 迭代特定节点的所有子节点，将它们写入磁盘，强行拆除两个方向上的所有引用。
//
// As a side effect, all pre-images accumulated up to this point are also written.
// 该函数的副作用是：到当前时间点为止 所累积的所有 preimages 中的数据也被一起写入levelDB。
// (因为：本身该函数只是 写 db.nodes 中的trie 的所有nodes的)
func (db *Database) Commit(node common.Hash, report bool) error {
	fmt.Println("进入 triedb.Commit ...")
	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	/**
	 创建一个 batch 用来持久化数据。
	 外部代码看不到不一致的状态这个是很重要的
	 （所引用的数据在 commit 期间从内存缓存中删除 但尚未在持久存储中删除）。
	 当写入 levelDB 操作完成后 需要确保清空缓存中的数据
	 */


	/**
	(这里的读锁主要是用来操作 db.preimages、db.nodes) 和 batch 无关
	 */
	db.lock.RLock()

	start := time.Now()
	// 获取一个 ldbBatch 实例
	batch := db.diskdb.NewBatch()

	/** 往leveldb 提交之前缓存的 state 和 stateObject 变动的数据 */
	// Move all of the accumulated preimages into a write batch
	// 将所有累积的preimages移动到写入 batch 中
	for hash, preimage := range db.preimages {
		// 将给定键/值对的“put操作”附加到 ldbBatch 中。
		// Put 并不是修改之前的内容，而是追加。
		if err := batch.Put(db.secureKey(hash[:]), preimage); err != nil {
			log.Error("Failed to commit preimage from trie database", "err", err)
			db.lock.RUnlock()
			return err
		}
		// 当 batch 缓存的数据的 字节数 (byte 数目)超过 100*1024 == 100 kb
		if batch.ValueSize() > ethdb.IdealBatchSize {
			// 一次性将 bacth 缓存的内容写入 levelDB
			if err := batch.Write(); err != nil {
				return err
			}
			// 重置 batch 缓存空间 和缓存字节数计数
			batch.Reset()
		}
	}

	/** 往 levelDB 提交当前 state的 trie nodes (根据入参的node 也即 root 去提交) commit是个自身递归的func */
	// Move the trie itself into the batch, flushing if enough data is accumulated
	// 将整颗 trie 移动到 ldbBatch中，如果累积了足够的数据则将其刷入 ldbBatch中
	nodes, storage := len(db.nodes), db.nodesSize
	if err := db.commit(node, batch); err != nil {
		log.Error("Failed to commit trie from trie database", "err", err)
		db.lock.RUnlock()
		return err
	}
	// Write batch ready, unlock for readers during persistence
	// 写入 ldbBatch中，在写的期间 为读操作解锁 (这里的读锁主要是用来操作 db.preimages、db.nodes)
	// 这里再一次写是因为 commit 中的最后一次put 可能数据量不超过需要触发 Batch.Write() 的操作，
	// 所以在外面最后再次 Write 一次
	if err := batch.Write(); err != nil {
		log.Error("Failed to write trie to disk", "err", err)
		db.lock.RUnlock()
		return err
	}
	db.lock.RUnlock()

	// Write successful, clear out the flushed data
	// 当写成功的时候需要参数所有缓存数据 （主要是 db.preimages、db.nodes 等等的数据）
	db.lock.Lock()
	defer db.lock.Unlock()

	db.preimages = make(map[common.Hash][]byte)
	db.preimagesSize = 0

	// 从 db.nodes 缓存中删除对应的 trie 的所有 node
	// 有 root入参 自身递归去 删除
	db.uncache(node)

	memcacheCommitTimeTimer.Update(time.Since(start))
	memcacheCommitSizeMeter.Mark(int64(storage - db.nodesSize))
	memcacheCommitNodesMeter.Mark(int64(nodes - len(db.nodes)))


	logger := log.Info
	if !report {
		logger = log.Debug
	}
	logger("Persisted trie from memory database", "nodes", nodes-len(db.nodes)+int(db.flushnodes), "size", storage-db.nodesSize+db.flushsize, "time", time.Since(start)+db.flushtime,
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.nodes), "livesize", db.nodesSize)

	// Reset the garbage collection statistics
	// 重置 gc 统计
	db.gcnodes, db.gcsize, db.gctime = 0, 0, 0
	db.flushnodes, db.flushsize, db.flushtime = 0, 0, 0

	return nil
}

// commit is the private locked version of Commit.
func (db *Database) commit(hash common.Hash, batch ethdb.Batch) error {
	// If the node does not exist, it's a previously committed node
	// 如果该节点不存在，则它极可能是之前就提交过的节点
	node, ok := db.nodes[hash]
	if !ok {
		return nil
	}
	// 递归提交trie 上的所有 节点到 batch 中
	for _, child := range node.childs() {
		if err := db.commit(child, batch); err != nil {
			return err
		}
	}
	// 提交当前节点至 batch中
	if err := batch.Put(hash[:], node.rlp()); err != nil {
		return err
	}
	// If we've reached an optimal batch size, commit and start over
	// 当 batch 缓存的数据的 字节数 (byte 数目)超过 100*1024 == 100 kb
	if batch.ValueSize() >= ethdb.IdealBatchSize {
		if err := batch.Write(); err != nil {
			return err
		}
		batch.Reset()
	}
	return nil
}

// uncache is the post-processing step of a commit operation where the already
// persisted trie is removed from the cache. The reason behind the two-phase
// commit is to ensure consistent data availability while moving from memory
// to disk.
/**
uncache 函数是 commit 操作的后处理步骤，其中已经 从 cache中删除了保留的trie。
在两次 commit 之后的原因是 确保从内存到磁盘的一致数据可用性。
 */
// 从 db.nodes 缓存中删除对应的 trie 的所有 node
// 有 root入参 自身递归去 删除
func (db *Database) uncache(hash common.Hash) {
	// If the node does not exist, we're done on this path
	node, ok := db.nodes[hash]
	if !ok {
		return
	}
	// Node still exists, remove it from the flush-list
	switch hash {
	case db.oldest:
		db.oldest = node.flushNext
		db.nodes[node.flushNext].flushPrev = common.Hash{}
	case db.newest:
		db.newest = node.flushPrev
		db.nodes[node.flushPrev].flushNext = common.Hash{}
	default:
		db.nodes[node.flushPrev].flushNext = node.flushNext
		db.nodes[node.flushNext].flushPrev = node.flushPrev
	}
	// Uncache the node's subtries and remove the node itself too
	for _, child := range node.childs() {
		db.uncache(child)
	}
	//  从db.nodes 缓存中删除当前 node
	delete(db.nodes, hash)
	// 计数器 递减
	db.nodesSize -= common.StorageSize(common.HashLength + int(node.size))
}

// Size returns the current storage size of the memory cache in front of the
// persistent database layer.
func (db *Database) Size() (common.StorageSize, common.StorageSize) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	// db.nodesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted. For every useful node, we track 2 extra hashes as the flushlist.
	var flushlistSize = common.StorageSize((len(db.nodes) - 1) * 2 * common.HashLength)
	return db.nodesSize + flushlistSize, db.preimagesSize
}

// verifyIntegrity is a debug method to iterate over the entire trie stored in
// memory and check whether every node is reachable from the meta root. The goal
// is to find any errors that might cause memory leaks and or trie nodes to go
// missing.
//
// This method is extremely CPU and memory intensive, only use when must.
func (db *Database) verifyIntegrity() {
	// Iterate over all the cached nodes and accumulate them into a set
	reachable := map[common.Hash]struct{}{{}: {}}

	for child := range db.nodes[common.Hash{}].children {
		db.accumulate(child, reachable)
	}
	// Find any unreachable but cached nodes
	unreachable := []string{}
	for hash, node := range db.nodes {
		if _, ok := reachable[hash]; !ok {
			unreachable = append(unreachable, fmt.Sprintf("%x: {Node: %v, Parents: %d, Prev: %x, Next: %x}",
				hash, node.node, node.parents, node.flushPrev, node.flushNext))
		}
	}
	if len(unreachable) != 0 {
		panic(fmt.Sprintf("trie cache memory leak: %v", unreachable))
	}
}

// accumulate iterates over the trie defined by hash and accumulates all the
// cached children found in memory.
func (db *Database) accumulate(hash common.Hash, reachable map[common.Hash]struct{}) {
	// Mark the node reachable if present in the memory cache
	node, ok := db.nodes[hash]
	if !ok {
		return
	}
	reachable[hash] = struct{}{}

	// Iterate over all the children and accumulate them too
	for _, child := range node.childs() {
		db.accumulate(child, reachable)
	}
}
