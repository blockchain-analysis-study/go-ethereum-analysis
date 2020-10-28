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

package trie

import (
	"hash"
	"sync"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/crypto/sha3"
	"github.com/go-ethereum-analysis/rlp"
)

type hasher struct {
	tmp        sliceBuffer
	sha        keccakState
	// 这两个值. 就是 trie 中的 chachegen 和 cachelimit
	cachegen   uint16			//
	cachelimit uint16			//
	onleaf     LeafCallback   	// 这个 回调指针; 只有在  db.store() 的时候 调用, 而且 stateObject.Trie.Commit() 传nil, 只有 stateDB.Trie.Commit() 才传的回调
}

// keccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

type sliceBuffer []byte

func (b *sliceBuffer) Write(data []byte) (n int, err error) {
	*b = append(*b, data...)
	return len(data), nil
}

func (b *sliceBuffer) Reset() {
	*b = (*b)[:0]
}

// hashers live in a global db.
var hasherPool = sync.Pool{
	New: func() interface{} {
		return &hasher{
			tmp: make(sliceBuffer, 0, 550), // cap is as large as a full fullNode.
			sha: sha3.NewKeccak256().(keccakState),
		}
	},
}

// 从  sync.Pool 中 获取  `key` 对应的 Hash
func newHasher(cachegen, cachelimit uint16, onleaf LeafCallback) *hasher {
	h := hasherPool.Get().(*hasher)
	h.cachegen, h.cachelimit, h.onleaf = cachegen, cachelimit, onleaf   // 将 trie 的 cachegen 和 cachelimit 赋值给  hasher
	return h
}

func returnHasherToPool(h *hasher) {
	hasherPool.Put(h)
}

// hash collapses a node down into a hash node, also returning a copy of the
// original node initialized with the computed hash to replace the original one.
//
// hash将节点向下折叠为hash node，同时返回用计算出的散列初始化的原始节点的副本以替换原始节点。

// 如果 trie.cachegen - node.cachegen > cachelimit，就可以把节点从内存里面卸载掉。
// 也就是说节点经过几次Commit，都没有修改，那么就把节点从内存里面卸载，以便节约内存给其他节点使用。

// 卸载过程在我们的 hasher.hash方法中
// 这个方法是在commit的时候调用。如果方法的canUnload方法调用返回真，那么就卸载节点
// 观察他的返回值，只返回了hash节点，而没有返回node节点，这样节点就没有引用，不久就会被gc清除掉。
// 节点被卸载掉之后，会用一个hashNode节点来表示这个节点以及其子节点。
// 如果后续需要使用，可以通过方法把这个节点加载到内存里面来。
/**
hash:
将一个节点折叠成一个散列节点，
还返回用计算得到的散列初始化的原始节点的副本以替换原始节点.


todo hash方法主要做了两个操作。
	一个是保留原有的树形结构，并用cache变量中，
	另一个是计算原有树形结构的hash并把hash值存放到cache变量中保存下来

返回:
node: 节点折叠后的 hashNode
node: 将 key 转成byte的shortNode/fullNode
 */
func (h *hasher) hash(n node, db *Database, force bool) (node, node, error) {

	// If we're not storing the node, just hashing, use available cached data
	//
	// 当我们可以获取 node 对应的 nodeHash 时,
	//
	// 我们需要判断该 node 是否满足 从 内存中释放掉. 并只留她的 hash 作为 hashNode  todo (被释放的 node 会在 tryGet() 中会根据 hashNode 从 db中 load 回来, 并替换掉 hashNode)
	if hash, dirty := n.cache(); hash != nil {
		if db == nil {
			return hash, n, nil
		}
		// 是否 将 node 从 内存中删掉
		if n.canUnload(h.cachegen, h.cachelimit) {
			// Unload the node from cache. All of its subnodes will have a lower or equal
			// cache generation number.
			//
			// 从缓存中卸载节点。它的所有子节点将具有较低或相等的缓存世代号码
			cacheUnloadCounter.Inc(1)

			// 只, 返回 hash  和 hash形成的 hashNode
			return hash, hash, nil
		}

		// 如果 node  近期没有用 变动, 且 不需要充内存中删除, 返回 hash  和 node
		if !dirty {
			return hash, n, nil
		}
	}

	// todo 走到这里 说明之前做过 insert 或者 delete, 各个 node 上的 hash 已经被清空. 需要重新计算
	//
	// Trie not processed yet or needs storage, walk the children
	//
	// todo 这里将进入间接的递归
	//
	// todo 首先调用h.hashChildren(n,db)把所有的子节点的hash值求出来，把原有的子节点替换成子节点的hash值.
	// 		这是一个递归调用的过程，会从树叶依次往上计算直到树根。
	// 		然后调用store方法计算当前节点的hash值，并把当前节点的hash值放入cache节点，
	// 		设置dirty参数为false [新创建的节点的dirty值是为true的]，然后返回。
	//
	//
	// collapsed: 将 key被折叠的shortNode返回  (key 被 compact 编码了)
	// cached: 将 key 转成byte的shortNode/fullNode返回  (key 还是原来的 hex 编码)
	collapsed, cached, err := h.hashChildren(n, db)   // todo 处理每个节点
	if err != nil {
		return hashNode{}, n, err
	}

	// todo 这里就是将该node 折叠之后的信息 存起来
	//
	// todo 细节: `force`
	// 	根节点调用hash函数的时候， force参数是为true的，
	// 	其他的子节点调用的时候force参数是为false的。
	// 	force参数的用途是当节点的RLP字节长度小于32也对节点的RLP进行hash计算，
	// 	这样保证无论如何也会对根节点进行Hash计算.
	//
	hashed, err := h.store(collapsed, db, force)   // todo 将当前节点生成hash       (collapsed: 为 key做了 compact 编码, 需要存入 磁盘的 node)
	if err != nil {
		return hashNode{}, n, err
	}

	// todo 将计算出 fullnode  和 shortnode 的 hash 存好,  并清楚 最近变更标识位 dirty
	//
	// Cache the hash of the node for later reuse and remove
	// the dirty flag in commit mode. It's fine to assign these values directly
	// without copying the node first because hashChildren copies it.
	cachedHash, _ := hashed.(hashNode)
	switch cn := cached.(type) {
	case *shortNode:
		cn.flags.hash = cachedHash	// 将当前节点的hasn保存在flags中    (此时的 Hash 是使用了 collapsed <key做了 compact 编码之后的 node> 计算出来的,  并将它 赋给 内存 那份对应的 <key 还是原来的  hex 编码> node)
		if db != nil {
			// 因为新创建的节点的dirty值是为true的
			cn.flags.dirty = false
		}
	case *fullNode:
		cn.flags.hash = cachedHash	// 将当前节点的hasn保存在flags中
		if db != nil {
			// 因为新创建的节点的dirty值是为true的
			cn.flags.dirty = false
		}
	}

	// 返回值说明，
	// hashed: 变量返回了当前节点的hash值(这个值其实是根据node和node的所有子节点计算出来的)
	// cached: 变量包含了原有的node节点，并且包含了node节点的hash值。
	//
	return hashed, cached, nil
}

// hashChildren replaces the children of a node with their hashes if the encoded
// size of the child is larger than a hash, returning the collapsed node as well
// as a replacement for the original node with the child hashes cached in.
//
// todo hashChildren方法,这个方法把所有的子节点替换成他们的hash，可以看到
// 	cached: 接管了原来的Trie树的完整结构，
// 	collapsed: 把子节点替换成子节点的hash值.
//
// 1) 如果当前节点是shortNode, 首先把collapsed.Key从Hex Encoding 替换成 Compact Encoding,
// 		然后递归调用hash方法计算子节点的hash和cache，这样就把子节点替换成了子节点的hash值.
// 2) 如果当前节点是fullNode, 那么遍历每个子节点，把子节点替换成子节点的Hash值.
// 3) 否则的话这个节点没有children, 直接返回.
//
/**
如果子节点的编码大小大于哈希值，
则hashChildren用其哈希值替换节点的子节点，
并返回折叠的节点，并用缓存在其中的子哈希值替换原始节点。

返回:
collapsed: 将 key被折叠的shortNode/fullNode返回
cached: 将 key 转成byte的shortNode/fullNode返回


这个方法真正最主要的目的就是将当前所在节点复制了两份（分别叫做collapsed, cached），这样此时加上原先传入的总共就有3份当前节点数据了。

todo 复制的两份，其中一份collapsed是为了将来db磁盘存储；而另一份cached会保留在内存中，回调结束后trie.root会指向这个cached，这样，原先的那一份就会被gc了（trie.root原先是指向这一份）
 */
func (h *hasher) hashChildren(original node, db *Database) (node, node, error) {
	var err error


	switch n := original.(type) {

	// 如果该 node 为shortNode
	case *shortNode:
		// Hash the short node's child, caching the newly hashed subtree
		//
		// 散列 short节点的 child节点，缓存新散列的子树
		collapsed, cached := n.copy(), n.copy()

		// todo 将 key 进行 折叠
		//
		// 节点放入数据库时候的key用到的就是Compact编码，可以节约磁盘空间
		// hex 转 Compact编码 <压缩编码>
		collapsed.Key = hexToCompact(n.Key)  // todo 将 内存中 node 的前缀hex key 转为compact，方便磁盘存储   (insert 的时候  node.Key 是 hex编码的)
		// hex 转 bytes
		cached.Key = common.CopyBytes(n.Key)   // 将key 字节数组复制给cached

		// 如果 shortNode 存在valueNode子节点
		if _, ok := n.Val.(valueNode); !ok {

			collapsed.Val, cached.Val, err = h.hash(n.Val, db, false)
			if err != nil {
				return original, original, err
			}
		}

		// collapsed: 将 key被折叠的shortNode返回
		// cached: 将 key 转成byte的shortNode返回
		return collapsed, cached, nil  // 前者是用于磁盘存储的节点，后者是hash化的节点，可以称为轻节点

	case *fullNode:
		// Hash the full node's children, caching the newly hashed subtrees
		collapsed, cached := n.copy(), n.copy()

		// 只算 0 ->  15 儿子的 hash
		for i := 0; i < 16; i++ {
			if n.Children[i] != nil {  // 类似，处理每个节点  (nil 的儿子不处理)
				collapsed.Children[i], cached.Children[i], err = h.hash(n.Children[i], db, false)
				if err != nil {
					return original, original, err
				}
			}
		}

		// 自己的 value 不需要算 Hash
		cached.Children[16] = n.Children[16]

		// collapsed: 将 key被折叠的fullNode返回
		// cached: 将 key 转成byte的fullNode返回
		return collapsed, cached, nil

	default:
		// Value and hash nodes don't have children so they're left as were
		//
		// valueNode和 hashNode没有子节点，因此它们照原样保留
		return n, original, nil
	}
}

// store hashes the node n and if we have a storage layer specified, it writes
// the key/value pair to it and tracks any node->child references as well as any
// node->external trie references.
//
//
// todo 将 经过 compact 编码key的node算出 node Hash, 并将node存到 db 缓存(最终会被刷入 db)， 且返回 nodeHash
//
// store方法:
// 如果一个node的所有子节点都替换成了子节点的hash值，
// 那么直接调用rlp.Encode方法对这个节点进行编码
// 如果编码后的值小于32，并且这个节点不是`根节点`，那么就把他们直接存储在他们的父节点里面.
// 否者调用h.sha.Write方法进行hash计算，
// 然后把hash值和编码后的数据存储到数据库里面，然后返回hash值.
// 可以看到每个值大于32的节点的值和hash都存储到了数据库里面，
//
//  todo 如果  force 设置为true，则即使长度再小的节点，也要进行rlp编码
func (h *hasher) store(n node, db *Database, force bool) (node, error) {
	// Don't store hashes or empty nodes.
	if _, isHash := n.(hashNode); n == nil || isHash {   // 空数据  或者 hashNode，则不处理
		return n, nil
	}
	// todo 将 node 做 rlp
	// Generate the RLP encoding of the node
	h.tmp.Reset()  // 缓存初始化
	if err := rlp.Encode(&h.tmp, n); err != nil {
		panic("encode error: " + err.Error())
	}
	if len(h.tmp) < 32 && !force {   // todo 编码后的node长度小于32，若force为true，则可确保所有节点都被编码
		// 小于32个字节的节点存储在其父级内部
		return n, nil // Nodes smaller than 32 bytes are stored inside their parent
	}

	//  todo 如果  force 设置为true，则即使长度再小的节点，也要进行rlp编码

	// Larger nodes are replaced by their hash and stored in the database.   长度过大的，则都将被新计算出来的hash取代
	hash, _ := n.cache() //  取出当前 node 的hash  （node.flag中的hash）
	if hash == nil {

		// 使用 rlp 之后的  node 算Hash
		hash = h.makeHashNode(h.tmp)   // todo  可以得知,  node 计算Hash 时,  key已经是 compact 编码的了
	}

	if db != nil {
		// We are pooling the trie nodes into an intermediate memory cache
		//
		// 我们正在将Trie节点合并到中间内存缓存中
		// 这里来了一次字节数组与hash的转换
		hash := common.BytesToHash(hash)

		db.lock.Lock()
		// todo 这里最终将当前节点的hash值放入cache,即 db.nodes
		//
		// 果然数据库里面插入的key是node的RLP之后的hash值(其实就是hashNode)，
		// value为node的RLP值的字节数组.
		db.insert(hash, h.tmp, n)   // todo (这里的 node.key 已经是  compact 编码的了)
		db.lock.Unlock()

		// Track external references from account->storage trie
		if h.onleaf != nil {

			// 判断当前处理的  node 类型
			switch n := n.(type) {

			// 如果是 拓展节点, 只处理  下属的  value node  和当前 short node 的引用关系
			case *shortNode:

				if child, ok := n.Val.(valueNode); ok {
					h.onleaf(child, hash)   	// 用于关联  parent 和 child 的 node 引用关系 todo  onleaf 回调只有 StateDB.Commit时传入.  stateObject.Commit传 nil
				}

			// 如果是 分支节点,  只处理	  下属的  value node  和当前 full node 的引用关系
			case *fullNode:

				// 逐个 处理 fullNode 下所有的 valueNode child
				for i := 0; i < 16; i++ {
					if child, ok := n.Children[i].(valueNode); ok {
						h.onleaf(child, hash)  	// 用于关联  parent 和 child 的 node 引用关系 todo  onleaf 回调只有 StateDB.Commit时传入.  stateObject.Commit传 nil
					}
				}
			}
		}
	}
	return hash, nil
}

// 根据 rlp 之后的 node 计算 nodeHash
func (h *hasher) makeHashNode(data []byte) hashNode {
	n := make(hashNode, h.sha.Size())
	h.sha.Reset()
	h.sha.Write(data)
	h.sha.Read(n)
	return n
}
