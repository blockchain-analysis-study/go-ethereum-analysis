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

// Package discv5 implements the RLPx v5 Topic Discovery Protocol.
//
// The Topic Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.
package discv5

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"github.com/go-ethereum-analysis/common"
)

const (
	alpha      = 3  // Kademlia concurrency factor
	bucketSize = 16 // Kademlia bucket size			// 每个 k-bucket 最多可以放 16 个 node 信息   todo  所以 以太坊的 k-bucket 是  16-bucket
	hashBits   = len(common.Hash{}) * 8  // 32 * 8 == 256   (为什么 * 8, 因为 一个 byte 是 8 bit 啊，  nodeId_a  XOR  nodeId_b 计算距离用的是  bit 啊)
	nBuckets   = hashBits + 1 // Number of buckets    256 + 1 == 257

	maxFindnodeFailures = 5
)

type Table struct {
	count         int               // number of nodes
	buckets       [nBuckets]*bucket // index of known nodes by distance    (以太坊的 k-bucket 有 257 个)
	nodeAddedHook func(*Node)       // for testing
	self          *Node             // metadata of the local node     指向当前本地 node
}

// bucket contains nodes, ordered by their last activity. the entry
// that was most recently active is the first element in entries.
type bucket struct {
	entries      []*Node		// 数组
	replacements []*Node
}

// 创建 table 实例, 里面有  k-bucket 的引用
func newTable(ourID NodeID, ourAddr *net.UDPAddr) *Table {

	// 创建当前 node 的相关信息
	self := NewNode(ourID, ourAddr.IP, uint16(ourAddr.Port), uint16(ourAddr.Port))
	tab := &Table{self: self}
	for i := range tab.buckets {
		tab.buckets[i] = new(bucket)
	}
	return tab
}

const printTable = false

// chooseBucketRefreshTarget selects random refresh targets to keep all Kademlia
// buckets filled with live connections and keep the network topology healthy.
// This requires selecting addresses closer to our own with a higher probability
// in order to refresh closer buckets too.
//
// This algorithm approximates the distance distribution of existing nodes in the
// table by selecting a random node from the table and selecting a target address
// with a distance less than twice of that of the selected node.
// This algorithm will be improved later to specifically target the least recently
// used buckets.
//
//  todo  随机性的去激 发某些节点 对当前本地node及本地node的临近node信息的 更新  (让 随机的target节点的k-bucket得以更新??)
//
//
//  todo 根据现有的 k-bucket饱和度 及 当前本地 nodeId 算出一个 随机的 targetNodeId
//
// `chooseBucketRefreshTarget()`  选择随机刷新目标，以使所有 Kademlia存储桶 中都充满实时连接，并保持网络拓扑健康.
//
// 	这需要以较高的 概率选择 更接近我们的地址，以便刷新更近的存储桶
//
// 此算法通过从 table 中选择一个随机节点 并选择距离 小于 该随机节点的距离两倍 的目标地址来近似表中现有节点的距离分布
//
// 此算法将在以后进行改进，以专门针对     最近最少使用的存储桶
//
func (tab *Table) chooseBucketRefreshTarget() common.Hash {
	entries := 0
	if printTable {
		fmt.Println()
	}


	for i, b := range &tab.buckets {

		entries += len(b.entries)  // 累计 所有一直 node 信息数量

		if printTable {  // 跨平台编译, 根据 `printTable` 的值判断是否做测试打印  k-bucket 的数据
			for _, e := range b.entries {
				fmt.Println(i, e.state, e.addr().String(), e.ID.String(), e.sha.Hex())
			}
		}
	}

	// 取出当前 当前本地 node 的 sha3(nodeId) 的前 8 byte 作为计算前缀值
	prefix := binary.BigEndian.Uint64(tab.self.sha[0:8])
	dist := ^uint64(0)			//  1111111111 ... 111111 一个最大值
	entry := int(randUint(uint32(entries + 1)))   // [0,  当前记录的所有 node信息个数 +1) 算出一个 随机数

	// 遍历所有的 k-bucket
	for _, b := range &tab.buckets {
		if entry < len(b.entries) {
			n := b.entries[entry]
			dist = binary.BigEndian.Uint64(n.sha[0:8]) ^ prefix
			break
		}
		entry -= len(b.entries)
	}

	ddist := ^uint64(0)   //  1111111111 ... 111111 一个最大值

	if dist+dist > dist {  // 这 ???????
		ddist = dist
	}
	targetPrefix := prefix ^ randUint64n(ddist)

	var target common.Hash
	binary.BigEndian.PutUint64(target[0:8], targetPrefix)
	rand.Read(target[8:])  // 随机 填充后面剩余的  byte
	return target  // todo 目的是 得到一个 随机的 nodeId
}

// readRandomNodes fills the given slice with random nodes from the
// table. It will not write the same node more than once. The nodes in
// the slice are copies and can be modified by the caller.
func (tab *Table) readRandomNodes(buf []*Node) (n int) {
	// TODO: tree-based buckets would help here
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
	for i := uint32(len(buckets)) - 1; i > 0; i-- {
		j := randUint(i)
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

func randUint(max uint32) uint32 {
	if max < 2 {
		return 0
	}
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:]) % max
}

func randUint64n(max uint64) uint64 {
	if max < 2 {
		return 0
	}
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) % max
}

// closest returns the n nodes in the table that are closest to the
// given id. The caller must hold tab.mutex.
func (tab *Table) closest(target common.Hash, nresults int) *nodesByDistance {
	// This is a very wasteful way to find the closest nodes but
	// obviously correct. I believe that tree-based buckets would make
	// this easier to implement efficiently.
	close := &nodesByDistance{target: target}
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			close.push(n, nresults)
		}
	}
	return close
}

// add attempts to add the given node its corresponding bucket. If the
// bucket has space available, adding the node succeeds immediately.
// Otherwise, the node is added to the replacement cache for the bucket.
//
// 往本地 对应的  k-bucket 中加入 一个新node信息
//
// 添加尝试将给定节点添加到其对应的存储桶. 如果存储桶有可用空间，则添加节点将立即成功.
// 否则，该节点将添加到存储桶的替换缓存中.
func (tab *Table) add(n *Node) (contested *Node) {
	//fmt.Println("add", n.addr().String(), n.ID.String(), n.sha.Hex())
	if n.ID == tab.self.ID {
		return
	}
	b := tab.buckets[logdist(tab.self.sha, n.sha)]
	switch {
	case b.bump(n):
		// n exists in b.
		return nil
	case len(b.entries) < bucketSize:
		// b has space available.
		b.addFront(n)
		tab.count++
		if tab.nodeAddedHook != nil {
			tab.nodeAddedHook(n)
		}
		return nil
	default:
		// b has no space left, add to replacement cache
		// and revalidate the last entry.
		// TODO: drop previous node
		b.replacements = append(b.replacements, n)
		if len(b.replacements) > bucketSize {
			copy(b.replacements, b.replacements[1:])
			b.replacements = b.replacements[:len(b.replacements)-1]
		}
		return b.entries[len(b.entries)-1]
	}
}

// stuff adds nodes the table to the end of their corresponding bucket
// if the bucket is not full.
func (tab *Table) stuff(nodes []*Node) {
outer:
	for _, n := range nodes {
		if n.ID == tab.self.ID {
			continue // don't add self
		}
		bucket := tab.buckets[logdist(tab.self.sha, n.sha)]
		for i := range bucket.entries {
			if bucket.entries[i].ID == n.ID {
				continue outer // already in bucket
			}
		}
		if len(bucket.entries) < bucketSize {
			bucket.entries = append(bucket.entries, n)
			tab.count++
			if tab.nodeAddedHook != nil {
				tab.nodeAddedHook(n)
			}
		}
	}
}

// delete removes an entry from the node table (used to evacuate
// failed/non-bonded discovery peers).
func (tab *Table) delete(node *Node) {
	//fmt.Println("delete", node.addr().String(), node.ID.String(), node.sha.Hex())
	bucket := tab.buckets[logdist(tab.self.sha, node.sha)]
	for i := range bucket.entries {
		if bucket.entries[i].ID == node.ID {
			bucket.entries = append(bucket.entries[:i], bucket.entries[i+1:]...)
			tab.count--
			return
		}
	}
}

func (tab *Table) deleteReplace(node *Node) {
	b := tab.buckets[logdist(tab.self.sha, node.sha)]
	i := 0
	for i < len(b.entries) {
		if b.entries[i].ID == node.ID {
			b.entries = append(b.entries[:i], b.entries[i+1:]...)
			tab.count--
		} else {
			i++
		}
	}
	// refill from replacement cache
	// TODO: maybe use random index
	if len(b.entries) < bucketSize && len(b.replacements) > 0 {
		ri := len(b.replacements) - 1
		b.addFront(b.replacements[ri])
		tab.count++
		b.replacements[ri] = nil
		b.replacements = b.replacements[:ri]
	}
}

func (b *bucket) addFront(n *Node) {
	b.entries = append(b.entries, nil)
	copy(b.entries[1:], b.entries)
	b.entries[0] = n
}

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

// nodesByDistance is a list of nodes, ordered by
// distance to target.
type nodesByDistance struct {
	entries []*Node		  // FIND_NODE 的响应 NEIGHBOURS消息返回的 一组 和 目标node 相近的 node
	target  common.Hash   // FIND_NODE请求中的 目标node 的 Hash
}

// 将 n 加入到 某个k-bucket 中
//
//    	1、如果当前 k-bucket 没满, 则 直接将 n 追加到 bucket 尾部
//		2、如果当前 k-bucket 已满:
//			1、且bucket 最后一个 node 离 target 比 n 离 target 更近,  丢弃 n
//			2、否则, 使用 n 替换掉最后一个 node
//
// push adds the given node to the list, keeping the total size below maxElems.
func (h *nodesByDistance) push(n *Node, maxElems int) {

	// 返回第一个满足里面条件的 node (k-bucket 中的 node 的 索引)
	ix := sort.Search(len(h.entries), func(i int) bool {
		// 比较 在 k-bucket 中的node 离 target 节点近 还是   当前本地node 离 target 节点近
		return distcmp(h.target, h.entries[i].sha, n.sha) > 0
	})

	// 如果当前 k-bucket 没满, 则 直接将 n 追加到 bucket 尾部
	if len(h.entries) < maxElems {
		h.entries = append(h.entries, n)
	}

	// 如果 bucket 满了  且 bucket 中的 最后一个 node 离 target 比 n 离 target 更近,  丢弃 n
	if ix == len(h.entries) {
		// farther away than all nodes we already have.
		// if there was room for it, the node is now the last element.

	// 否则, 使用 n 替换掉 ix索引的 node
	} else {
		// slide existing entries down to make room
		// this will overwrite the entry we just appended.
		copy(h.entries[ix+1:], h.entries[ix:])
		h.entries[ix] = n
	}
}
