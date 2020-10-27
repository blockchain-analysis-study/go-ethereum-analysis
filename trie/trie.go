// Copyright 2014 The github.com/go-ethereum-analysis Authors
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

// Package trie implements Merkle Patricia Tries.
package trie

import (
	"bytes"
	"fmt"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/crypto"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/metrics"
)

// todo 真正处理数据的是trie中的  insert()、delete()、tryGet() 这三个方法

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// emptyState is the known hash of an empty state trie entry.
	emptyState = crypto.Keccak256Hash(nil)
)

var (
	cacheMissCounter   = metrics.NewRegisteredCounter("trie/cachemiss", nil)			// 	用来记录,  从缓存中 找不到 trie ndoe 的计数器   (统计用)
	cacheUnloadCounter = metrics.NewRegisteredCounter("trie/cacheunload", nil)		//	用来记录, 将 node 从 内存中 清空只留 hash 的计数器 (统计用)
)

// CacheMisses retrieves a global counter measuring the number of cache misses
// the trie had since process startup. This isn't useful for anything apart from
// trie debugging purposes.
func CacheMisses() int64 {
	return cacheMissCounter.Count()
}

// CacheUnloads retrieves a global counter measuring the number of cache unloads
// the trie did since process startup. This isn't useful for anything apart from
// trie debugging purposes.
func CacheUnloads() int64 {
	return cacheUnloadCounter.Count()
}

// LeafCallback is a callback type invoked when a trie operation reaches a leaf
// node. It's used by state sync and commit to allow handling external references
// between account and storage tries.
type LeafCallback func(leaf []byte, parent common.Hash) error

// Trie is a Merkle Patricia Trie.
// The zero value is an empty trie with no database.
// Use New to create a trie that sits on top of a database.
//
// Trie is not safe for concurrent use.
type Trie struct {

	// todo trie 中存入db本身的是各种类型的node，也就是从root指向的那个node开始存储，root本身并不存储.
	//
	// http://www.wjblog.top/articles/636a5647/
	// http://www.wjblog.top/articles/dcade07d/

	db           *Database
	root         node			// 根结点
	originalRoot common.Hash   	// 32位byte[], 从db中恢复出完整的trie

	// Cache generation values.
	// cachegen increases by one with each commit operation.
	// new nodes are tagged with the current generation and unloaded
	// when their generation is older than than cachegen-cachelimit.
	//
	//
	// 缓存 生成值
	// 每个提交操作的 cachegen 增加一
	// 将新节点标记为当前节点，并在它们的年代早于 cachegen-cachelimit 时将其卸载
	//
	//
	//	cachegen:	表示当前trie树的版本，trie每次commit，则增加1
	//	cachelimit:	如果当前的cache时代, cachelimit参数 大于node的cache时代，那么node会从cache里面卸载，以便节约内存. todo 该值决定 trie 的某些node 是要在内存中保存 node 还是保存 nodeHash,节省内存用
	cachegen, cachelimit uint16
}

// SetCacheLimit sets the number of 'cache generations' to keep.
// A cache generation is created by a call to Commit.
func (t *Trie) SetCacheLimit(l uint16) {
	t.cachelimit = l
}

// newFlag returns the cache flag value for a newly created node.
//
// todo 只要trie树上的某条路径上有节点 【新增】或者 【删除】，那这条路径的节点都会被重新实例化并负值，如此一来，节点的nodeFlag中的dirty也被改为true，这样就表示这条路径的所有节点都需要重新插入到db
func (t *Trie) newFlag() nodeFlag {
	return nodeFlag{dirty: true, gen: t.cachegen}
}

// New creates a trie with an existing root node from db.
//
// If root is the zero hash or the sha3 hash of an empty string, the
// trie is initially empty and does not require a database. Otherwise,
// New will panic if db is nil and returns a MissingNodeError if root does
// not exist in the database. Accessing the trie loads nodes from db on demand.
//
//
/**
todo 这个方法超级重要
	从数据库加载一个已经存在的Trie树， 就调用 `trie.resolveHash()` 方法来加载整颗Trie树
 */
func New(root common.Hash, db *Database) (*Trie, error) {
	if db == nil {
		panic("trie.New called without a database")
	}
	trie := &Trie{
		db:           db,
		originalRoot: root,
	}
	if root != (common.Hash{}) && root != emptyRoot {

		// todo 加载整棵树,并返回rootNode
		rootnode, err := trie.resolveHash(root[:], nil)
		if err != nil {
			return nil, err
		}
		trie.root = rootnode
	}
	return trie, nil
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration starts at
// the key after the given start key.
func (t *Trie) NodeIterator(start []byte) NodeIterator {
	return newNodeIterator(t, start)
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
func (t *Trie) Get(key []byte) []byte {
	res, err := t.TryGet(key)
	if err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
	return res
}

// TryGet returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
// If a node was not found in the database, a MissingNodeError is returned.
//
//
// `TryGet()` 返回存储在trie中的 key 的 value
//
//	调用者不得修改值字节
//
//
// 如果在数据库中找不到节点，则返回MissingNodeError
func (t *Trie) TryGet(key []byte) ([]byte, error) {

	// todo 编码, 先将 key 转成 hex (16进制)
	key = keybytesToHex(key)

	// 再去 trie 上 查 value
	value, newroot, didResolve, err := t.tryGet(t.root, key, 0)
	if err == nil && didResolve {
		t.root = newroot
	}
	return value, err
}


// 此时 入参的 key 一定是 16进制的
//
//	origNode：	当前查找的起始node位置
//	key：		输入要查找的数据的 hash
//	pos：		当前hash匹配到第几位
//
//  didResolve: 这个东西，用于判断trie树是否会发生变化，按理tryGet()只是用来获取数据的，哪里会影响trie发生变化，todo 但是因为有可能我们会根据hashNode去db中获取该node值，获取到后，需要更新现有的trie，didResolve就会发生变化
func (t *Trie) tryGet(origNode node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {

	// 第一次 递归进来的  origNode 一定是 root node
	switch n := (origNode).(type) {

	// 这表示当前trie是空树
	case nil:
		return nil, nil, false, nil

	//这就是我们要查找的 叶子节点对应的数据
	case valueNode:
		return n, n, false, nil

	// 在 叶子节点 或者 扩展节点匹配
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			// key not found in trie
			return nil, n, false, nil
		}
		value, newnode, didResolve, err = t.tryGet(n.Val, key, pos+len(n.Key))
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
			n.flags.gen = t.cachegen
		}
		return value, n, didResolve, err

	// 在分支节点匹配
	case *fullNode:
		value, newnode, didResolve, err = t.tryGet(n.Children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.flags.gen = t.cachegen
			n.Children[key[pos]] = newnode
		}
		return value, n, didResolve, err


	// todo 只有 hashNode 才会返回  `didResolve` == true
	case hashNode:

		/**
		若某节点数据一直没有发生变化，则仅仅保留该节点的32位hash值，剩下的内容全部释放
		若需要插入或者删除某节点，先通过该hash值db中查找对应的节点，并加载到内存，之后再进行删除插入操作

		所以, 比如: 有时  root -> rootHash 这时候 内存中没有 root node, 则需要走这一步， 当然 其他节点也可以是这样的.
		 */

		// 根据 某个node 的Hash 去 DB 加载整个 node
		child, err := t.resolveHash(n, key[:pos])   // todo 在t.resolveHash() 里, 最终调 mustDecodeNode() 会做. 将 node.key 从 compact 编码转回 hex 编码
		if err != nil {
			return nil, n, true, err  // trie重组，因此需要返回true
		}

		// 根据 node 的 Hash 获取了 node, 然后进入继续的 递归
		value, newnode, _, err := t.tryGet(child, key, pos)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
func (t *Trie) Update(key, value []byte) {
	if err := t.TryUpdate(key, value); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// TryUpdate associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If a node was not found in the database, a MissingNodeError is returned.
func (t *Trie) TryUpdate(key, value []byte) error {
	k := keybytesToHex(key)

	// todo trie的Update() 只有两种,  insert 和 delete
	if len(value) != 0 {

		// 将  k-v 插入 trie
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		t.root = n
	} else {

		// 将  k-v 从trie上删除
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

/**

todo 只要节点中某条路径下 新增 或者 删除 节点，整条路径的节点都会被重新实例化，然后重新插入db

入参:
prefix: key的前缀
key: 完整的key
value: 完整的value

返回值:
bool: 表示树是否有更改
node: 插入完成后的子树的根节点
 */
func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		/**
		其实这一个操作就是为了结束 insert的递归调用的
		 */
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		// 要在节点A中新增节点B，若A和B本身数据一致，则认为已经新增，则直接返回true
		return true, value, nil
	}

	// 这里才是每次都判断node 的类型
	switch n := n.(type) {

	// 当前是shortNode(也就是叶子节点)，
	// 首先计算公共前缀，如果公共前缀就等于key，那么说明这两个key是一样的，
	// 如果value也一样的(dirty == false)，那么返回。
	// 如果没有错误就更新shortNode的值然后返回。
	// 如果公共前缀不完全匹配，那么就需要把公共前缀提取出来形成一个独立的节点(扩展节点),
	// 		扩展节点后面连接一个 分支节点， 分支节点后面看情况连接两个short节点
	// 		首先构建一个branch节点(branch := &fullNode{flags: t.newFlag()}),
	// 		然后再branch节点的Children位置调用t.insert插入剩下的两个short节点.
	case *shortNode:

		//n.Key是扩展节点的公共key，这是公共结点匹配
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		//
		// 如果整个key匹配，则保持此短节点不变，仅更新该value。
		if matchlen == len(n.Key) {
			dirty, nn, err := t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)

			// 如果value也一样(即: 树没有被更新,dirty==false;或者 有err, 都直接返回)
			if !dirty || err != nil {
				return false, n, err
			}
			// 新增返回的必是叶子结点
			// 从这里可以看出，从根路径到插入数据的位置，整条路径的节点都会被重新实例化，node的dirty也被改为true，表示要重新更新
			return true, &shortNode{n.Key, nn, t.newFlag()}, nil
		}
		// Otherwise branch out at the index where they differ.
		//
		// 否则在它们 <入参的 node和key> 不同的索引处分支

		//  剩余部分代码，是为了将一个扩展节点拆分为两部分

		// 新建一个 分支节点
		branch := &fullNode{flags: t.newFlag()}
		var err error

		// todo 下面 两步 操作 就变成了. 将 原来的short node 和 新入参的 k-v 组成的 short node 挂到一个 新建的 full node 下面

		// todo 插入 入参node
		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		// todo 插入入参key和valu组成的 shortNode
		_, branch.Children[key[matchlen]], err = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}

		// Replace this shortNode with the branch if it occurs at index 0.
		//
		// 如果该shortNode出现在索引0处，则将其替换为 full Node
		//
		// 即: 待插入数据和trie中当前节点的前缀key一个也没匹配，则返回 分支节点
		if matchlen == 0 {
			return true, branch, nil
		}
		// Otherwise, replace it with a short node leading up to the branch.
		//
		// 否则，将其替换为 通向 新建 full Node 的 short Node    （hex 编码的 key）
		return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil


	// 当前的节点是fullNode(也就是branch节点)，那么直接往对应的孩子节点调用insert方法,然后把对应的孩子节点指向新生成的节点.
	case *fullNode:
		dirty, nn, err := t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag() // 构建新的 nodeFlag, 其中 hash字段中的 hashNode 是nil的,只有在trie求Hash的时候才填充
		n.Children[key[0]] = nn
		return true, n, nil

	// 节点类型是nil(一颗全新的Trie树的节点就是nil的),这个时候整颗树是空的，直接返回
	//
	 //  也就是说，在 空trie中添加一个节点，就是 叶子节点，返回shortNode
	case nil:
		// 所有一颗新的单节点树,跟节点就是 shortNode    （hex 编码的 key）
		return true, &shortNode{key, value, t.newFlag()}, nil

	// 当前节点是hashNode, hashNode的意思是当前节点还没有加载到内存里面来，
	// todo 还是存放在数据库里面，那么首先调用 t.resolveHash(n, prefix)来加载到内存，
	// 		然后对加载出来的节点调用insert方法来进行插入.
	//
	//
	 // 恢复一个存储在db中的node
	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		//
		// 我们已经找到了尚未加载的trie部分。 加载节点并将其插入
		// 这将所有子节点留在了到Trie中值的路径上
		//
		// 现根据 hashNode 加载出 剩余的 subtrie
		rn, err := t.resolveHash(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(rn, prefix, key, value)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// Delete removes any existing value for key from the trie.
func (t *Trie) Delete(key []byte) {
	if err := t.TryDelete(key); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// TryDelete removes any existing value for key from the trie.
// If a node was not found in the database, a MissingNodeError is returned.
func (t *Trie) TryDelete(key []byte) error {
	k := keybytesToHex(key)
	_, n, err := t.delete(t.root, nil, k)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

// todo 只要节点中某条路径下 新增 或者 删除 节点，整条路径的节点都会被重新实例化，然后重新插入db
//
//
// delete returns the new root of the trie with key deleted.
// It reduces the trie to minimal form by simplifying
// nodes on the way up after deleting recursively.
//
//
// `delete()` 返回带有已删除键的trie的新 root
// 通过递归删除后的路径简化节点，从而将Trie简化为最小形式
func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)

		// 入参的 key 不包含 拓展node 中的 key, 说明, 不是这条前缀路径的
		if matchlen < len(n.Key) {
			return false, n, nil // don't replace n on mismatch
		}

		// 入参的 key 完全等于 拓展node 中的 key, 说明, 就是需要删除当前 拓展node
		//
		// 走到这一步,  基本上是返回到上级   ·full node 逻辑·, 或者是 ·上级 short node 的 下面的逻辑·
		if matchlen == len(key) {
			return true, nil, nil // remove n entirely for whole matches   完全删除 n
		}


		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		//
		// 如果 key 长于n.Key (包含 且 长于).  则 key 继续转由 下级 子trie 查找, 并处理下级查找返回的 东西
		dirty, child, err := t.delete(n.Val, append(prefix, key[:len(n.Key)]...), key[len(n.Key):])
		// 处理下级zitrie查找返回的东西
		if !dirty || err != nil {
			return false, n, err
		}

		// 如果 key 在 下级 子trie 中找到的话. 处理 delete
		switch child := child.(type) {
		case *shortNode:
			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			//
			//
			// 从 子trie 中删除将其减少到另一个短节点. 合并节点以避免创建shortNode {...，shortNode {...}}.
			// 使用concat（总是创建一个新的片）而不是追加，以避免修改n.Key，因为它可能与其他节点共享.
			//
			//  说白了, 就是原来的   short node 下级 有一个 分支节点 fullNode，那么返回的 full node 基本上不会是 nil   (看 full node 逻辑)
			return true, &shortNode{concat(n.Key, child.Key...), child.Val, t.newFlag()}, nil
		default:

			// 否则, 根据查找到的  child， 构造一个新的 short node,
			//
			//  注意: 如果 当前 short node 的下级是 value node 的话. 那么 返回的是   nil
			return true, &shortNode{n.Key, child, t.newFlag()}, nil
		}

	case *fullNode:

		// 如果是 分支node 的话, 直接继续往下级 trie 查找
		dirty, nn, err := t.delete(n.Children[key[0]], append(prefix, key[0]), key[1:])

		// 找不到, 直接出去
		if !dirty || err != nil {
			return false, n, err
		}

		// 找到了, 开始处理

		n = n.copy()				// 值拷贝
		n.flags = t.newFlag()		// 初始化(清空) node Hash
		n.Children[key[0]] = nn		// 基本上这里返回的 是一个 nil

		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		//
		//
		//	检查删除后还剩下多少非零条目，如果只剩下一个条目，则将整个节点缩减为 short节点。 由于n在删除之前必须至少包含两个子节点（否则它将不是完整节点），因此n永远不能减少为nil
		//
		//	循环完成后，pos 包含n中保留的单个值的索引；
		//
		// 如果n包含至少两个值，则pos -2
		//
		//
		pos := -1
		for i, cld := range &n.Children {
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// If the remaining entry is a short node, it replaces
				// n and its key gets the missing nibble tacked to the
				// front. This avoids creating an invalid
				// shortNode{..., shortNode{...}}.  Since the entry
				// might not be loaded yet, resolve it just for this
				// check.
				//
				//
				//  如果其余条目是一个 short 节点，它将替换n，并且其键会将丢失的半字节固定在最前面.
				//
				//  这样可以避免创建无效的shortNode {...，shortNode {...}}. 由于可能尚未加载该条目，请仅对此检查进行解决.
				//
				//
				cnode, err := t.resolve(n.Children[pos], prefix)   // 根据 node.hash  从 db中获取 node 实例
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					k := append([]byte{byte(pos)}, cnode.Key...)
					return true, &shortNode{k, cnode.Val, t.newFlag()}, nil
				}
			}
			// Otherwise, n is replaced by a one-nibble short node
			// containing the child.
			//
			// 否则，n将被 包含 该子节点的一个半字节  short节点替换
			return true, &shortNode{[]byte{byte(pos)}, n.Children[pos], t.newFlag()}, nil
		}
		// n still contains at least two values and cannot be reduced.
		//
		// full node 仍然至少包含两个值，并且不能减少.
		return true, n, nil

	// 看了 short node 的逻辑后,  感觉是找不到  value node 的啊
	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		//
		// 根据 Hash 去 db 中加载 node 实例, 然后接着往下 递归
		rn, err := t.resolveHash(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(rn, prefix, key)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key))
	}
}

func concat(s1 []byte, s2 ...byte) []byte {
	r := make([]byte, len(s1)+len(s2))
	copy(r, s1)
	copy(r[len(s1):], s2)
	return r
}

func (t *Trie) resolve(n node, prefix []byte) (node, error) {
	if n, ok := n.(hashNode); ok {
		return t.resolveHash(n, prefix)
	}
	return n, nil
}

// insert()   delete()  tryGet() 当 node 为 hashNode 时, 都会 来调这个方法
//
// 根据 某个node 的Hash 去 DB 加载整个 node
func (t *Trie) resolveHash(n hashNode, prefix []byte) (node, error) {
	//每执行一次resolveHash()方法，计数器+1
	cacheMissCounter.Inc(1)

	hash := common.BytesToHash(n) // HexBytes  -> HexHash  （slice -> arr）

	// 根据 hash 去 全局 node map 中找, 找不到再从  disk 找
	if node := t.db.node(hash, t.cachegen); node != nil {    // todo 注意:  node 的 Hash 其实都是之前 使用 node.Key 做了 compact 编码之后的node 计算得到的
		return node, nil     // todo 在 t.db.node 里, 最终调 mustDecodeNode() 会做. 将 node.key 从 compact 编码转回 hex 编码
	}
	return nil, &MissingNodeError{NodeHash: hash, Path: prefix}
}

// Root returns the root hash of the trie.
// Deprecated: use Hash instead.
func (t *Trie) Root() []byte { return t.Hash().Bytes() }

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *Trie) Hash() common.Hash {
	hash, cached, _ := t.hashRoot(nil, nil)
	t.root = cached
	return common.BytesToHash(hash.(hashNode))
}

// Commit writes all nodes to the trie's memory database, tracking the internal
// and external (for account tries) references.
//
/**
Commit:
将所有node写入trie的内存数据库，跟踪内部和外部（用于帐户尝试）引用。
 */
func (t *Trie) Commit(onleaf LeafCallback) (root common.Hash, err error) {
	if t.db == nil {
		panic("commit called on trie with nil database")
	}

	// TODO 写入部分操作,在这里
	// hash: 节点折叠后的 hashNode
	// cached: 将 key 转成byte的shortNode/fullNode
	hash, cached, err := t.hashRoot(t.db, onleaf)    // todo 在  commit  trie 时, 计算 整棵树的hash, 并做 compact 编码  (trie树序列化后，真正保存在磁盘上，是使用的Compact Encoding编码，这样会节省空间)
	if err != nil {
		return common.Hash{}, err
	}
	t.root = cached
	t.cachegen++   // 每次 提交树 的时候, trie 的 cachegen 计数都 +1
	return common.BytesToHash(hash.(hashNode)), nil
}

// 折叠node的入口是hasher.hash()，在执行中，hash()和hashChildren()相互调用以遍历整个MPT结构，
// store()对节点作RLP哈希计算。折叠node的基本逻辑是：
// 如果node没有子节点，那么直接返回；
// 如果这个node带有子节点，那么首先将子节点折叠成hashNode。当这个node的子节点全都变成哈希值hashNode之后，
// 再对这个node作RLP+哈希计算，得到它的哈希值，亦即hashNode。
// 注意到hash()和hashChildren()返回两个node类型对象，第一个@hash是入参n经过折叠的hashNode哈希值，
// 第二个@cached是没有经过折叠的n，并且n的hashNode还被赋值了。
func (t *Trie) hashRoot(db *Database, onleaf LeafCallback) (node, node, error) {
	if t.root == nil {
		return hashNode(emptyRoot.Bytes()), nil, nil
	}
	h := newHasher(t.cachegen, t.cachelimit, onleaf)  // 每次 算 root 的时候 都重新将 trie 的 cachegen 和 cachelimit 赋值给  hasher. 用来决定 是否将对应的  node从 内存中 清除掉
	defer returnHasherToPool(h)

	// 这里才是真正 折叠node   (将 node.key 从 hex 编码 转成 compact 编码)
	// node: 节点折叠后的 hashNode
	// node: 将 key 转成byte的shortNode/fullNode
	return h.hash(t.root, db, true)   // 为每个节点生成一个 未编码的hash
}
