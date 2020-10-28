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

package trie

import (
	"bytes"
	"container/heap"
	"errors"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/rlp"
)

// Iterator is a key-value trie iterator that traverses a Trie.
type Iterator struct {
	nodeIt NodeIterator

	Key   []byte // Current data key on which the iterator is positioned on
	Value []byte // Current data value on which the iterator is positioned on
	Err   error
}

// NewIterator creates a new key-value iterator from a node iterator
func NewIterator(it NodeIterator) *Iterator {
	return &Iterator{
		nodeIt: it,
	}
}

// Next moves the iterator forward one key-value entry.
func (it *Iterator) Next() bool {
	for it.nodeIt.Next(true) {
		if it.nodeIt.Leaf() {
			it.Key = it.nodeIt.LeafKey()		// 返回 hex key
			it.Value = it.nodeIt.LeafBlob()		// 返回 valueNode (也是 value的原始数据啦)
			return true
		}
	}
	it.Key = nil
	it.Value = nil
	it.Err = it.nodeIt.Error()
	return false
}

// Prove generates the Merkle proof for the leaf node the iterator is currently
// positioned on.
func (it *Iterator) Prove() [][]byte {
	return it.nodeIt.LeafProof()
}

// NodeIterator is an iterator to traverse the trie pre-order.
type NodeIterator interface {
	// Next moves the iterator to the next node. If the parameter is false, any child
	// nodes will be skipped.
	Next(bool) bool

	// Error returns the error status of the iterator.
	Error() error

	// Hash returns the hash of the current node.
	Hash() common.Hash

	// Parent returns the hash of the parent of the current node. The hash may be the one
	// grandparent if the immediate parent is an internal node with no hash.
	Parent() common.Hash

	// Path returns the hex-encoded path to the current node.
	// Callers must not retain references to the return value after calling Next.
	// For leaf nodes, the last element of the path is the 'terminator symbol' 0x10.
	Path() []byte

	// Leaf returns true iff the current node is a leaf node.
	Leaf() bool

	// LeafKey returns the key of the leaf. The method panics if the iterator is not
	// positioned at a leaf. Callers must not retain references to the value after
	// calling Next.
	LeafKey() []byte

	// LeafBlob returns the content of the leaf. The method panics if the iterator
	// is not positioned at a leaf. Callers must not retain references to the value
	// after calling Next.
	LeafBlob() []byte

	// LeafProof returns the Merkle proof of the leaf. The method panics if the
	// iterator is not positioned at a leaf. Callers must not retain references
	// to the value after calling Next.
	LeafProof() [][]byte
}

// trie 迭代器的 状态
//
// nodeIteratorState represents the iteration state at one particular node of the
// trie, which can be resumed at a later invocation.
type nodeIteratorState struct {

	// 当前状态对应 trie上的 node的 hash
	hash    common.Hash // Hash of the node being iterated (nil if not standalone)
	// 当前状态对应 trie上的 node
	node    node        // Trie node being iterated
	parent  common.Hash // Hash of the first full ancestor node (nil if current is the root)
	index   int         // Child to be processed next
	pathlen int         // Length of the path to this node
}

// trie节点迭代器的实现
type nodeIterator struct {

	// 迭代器引用的 trie 本身
	trie  *Trie                // Trie being iterated
	// 持久化迭代状态的 trie node 的层次结构 （里面装的是 遍历到的每个 node 的 state, 在 `it.push()` 中被放置）
	stack []*nodeIteratorState // Hierarchy of trie nodes persisting the iteration state
	// 当前被遍历到的 node
	path  []byte               // Path to the current node
	err   error                // Failure set in case of an internal error in the iterator
}

// errIteratorEnd is stored in nodeIterator.err when iteration is done.
var errIteratorEnd = errors.New("end of iteration")

// seekError is stored in nodeIterator.err if the initial seek has failed.
type seekError struct {
	key []byte
	err error
}

func (e seekError) Error() string {
	return "seek error: " + e.err.Error()
}
// 根据 key 的前缀 返回 一个 trie 的迭代器
func newNodeIterator(trie *Trie, start []byte) NodeIterator {
	if trie.Hash() == emptyState {
		return new(nodeIterator)
	}
	it := &nodeIterator{trie: trie}
	// 根据 key 的前缀, 全部加载 prefix 匹配的key 路径上所有 node
	it.err = it.seek(start) // 处理迭代器, 这时候 it.stack 队列中装的就是 trie 根据 start前缀找到的 key 的所有node
	return it
}

func (it *nodeIterator) Hash() common.Hash {
	if len(it.stack) == 0 {
		return common.Hash{}
	}
	return it.stack[len(it.stack)-1].hash
}

func (it *nodeIterator) Parent() common.Hash {
	if len(it.stack) == 0 {
		return common.Hash{}
	}
	return it.stack[len(it.stack)-1].parent
}

func (it *nodeIterator) Leaf() bool {
	return hasTerm(it.path)  // it.path: key 的某个片段,  hasTerm() 判断 it.path 是否为一个完整的 hex 的key
}

func (it *nodeIterator) LeafKey() []byte {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			return hexToKeybytes(it.path)  // 直接返回 hex key -> byte key
		}
	}
	panic("not at leaf")
}

func (it *nodeIterator) LeafBlob() []byte {
	if len(it.stack) > 0 {
		if node, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			return []byte(node)  // 从 it.stack 中获取 node数据 todo (注意, 这里只取 stack 中最后一个, 因为 最后一个才是 valueNode 才是 key对应的value)
		}
	}
	panic("not at leaf")
}

func (it *nodeIterator) LeafProof() [][]byte {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			hasher := newHasher(0, 0, nil)
			proofs := make([][]byte, 0, len(it.stack))

			for i, item := range it.stack[:len(it.stack)-1] {
				// Gather nodes that end up as hash nodes (or the root)
				node, _, _ := hasher.hashChildren(item.node, nil)
				hashed, _ := hasher.store(node, nil, false)
				if _, ok := hashed.(hashNode); ok || i == 0 {
					enc, _ := rlp.EncodeToBytes(node)
					proofs = append(proofs, enc)
				}
			}
			return proofs
		}
	}
	panic("not at leaf")
}

func (it *nodeIterator) Path() []byte {
	return it.path
}

func (it *nodeIterator) Error() error {
	if it.err == errIteratorEnd {
		return nil
	}
	if seek, ok := it.err.(seekError); ok {
		return seek.err
	}
	return it.err
}

// Next moves the iterator to the next node, returning whether there are any
// further nodes. In case of an internal error this method returns false and
// sets the Error field to the encountered failure. If `descend` is false,
// skips iterating over any subnodes of the current node.
func (it *nodeIterator) Next(descend bool) bool {
	if it.err == errIteratorEnd {
		return false
	}
	if seek, ok := it.err.(seekError); ok {
		// 根据 key 的前缀, 全部加载 prefix 匹配的key 路径上所有 node
		if it.err = it.seek(seek.key); it.err != nil {
			return false
		}
	}
	// Otherwise step forward with the iterator and report any errors.
	//
	// 否则，请使用迭代器前进并报告任何错误   (即, 之前的 it.seek() 报 `seekError` 了, 那么我们自己使用 peek() 去尝试遍历 路径上的下一个 node)
	state, parentIndex, path, err := it.peek(descend)  // peek 创建迭代器的下一个状态
	it.err = err
	if it.err != nil {
		return false
	}
	it.push(state, parentIndex, path)
	return true
}

// 根据 key 的前缀, 全部加载 prefix 匹配的key 路径上所有 node
func (it *nodeIterator) seek(prefix []byte) error {
	// The path we're looking for is the hex encoded key without terminator.   我们正在寻找的路径是 不带终止符 (后面是 ·16· 这个数字的) 的十六进制编码 key
	key := keybytesToHex(prefix)		// 先做  byte -> hex
	key = key[:len(key)-1]
	// Move forward until we're just before the closest match to key.
	for {

		// 逐个将这哦trie 路径上的 node state 遍历出来, 并追加到 it.stack 中
		state, parentIndex, path, err := it.peek(bytes.HasPrefix(key, it.path))
		if err == errIteratorEnd {
			return errIteratorEnd
		} else if err != nil {
			return seekError{prefix, err}
		} else if bytes.Compare(path, key) >= 0 {   // 根据 前缀, 查找 key 结束了
			return nil
		}
		it.push(state, parentIndex, path) // 将当前最新 遍历到的 node 转入  it.stack
	}
}

// peek creates the next state of the iterator.
//
// peek 创建迭代器的下一个状态
func (it *nodeIterator) peek(descend bool) (*nodeIteratorState, *int, []byte, error) {

	// it.stack:  持久化迭代状态的 trie node 的层次结构
	//
	// 如果是 第一层, 那就从 root 开始
	if len(it.stack) == 0 {
		// Initialize the iterator if we've just started.   如果我们刚刚开始，则初始化迭代器
		root := it.trie.Hash()	// 先获取 trie 上的 root
		state := &nodeIteratorState{node: it.trie.root, index: -1}
		if root != emptyRoot {
			state.hash = root
		}
		err := state.resolve(it.trie, nil)   // 根据 遍历到 trie 的 root  <root其实是 rootNode hash> 从 db 将对应的 node加载出来
		return state, nil, nil, err
	}
	if !descend {
		// If we're skipping children, pop the current node first
		//
		// 如果我们要跳过子节点，请先弹出当前节点
		it.pop()
	}

	// Continue iteration to the next child
	//
	// 继续从  it.stack 中获取上一个 node, 并往下 遍历 child node
	for len(it.stack) > 0 {
		parent := it.stack[len(it.stack)-1]  // 每次去上一个, (尾巴的就是最新遍历到的node 也是key路径上目前遍历到的node)
		ancestor := parent.hash
		if (ancestor == common.Hash{}) {
			ancestor = parent.parent
		}
		// 往下继续遍历 child node
		state, path, ok := it.nextChild(parent, ancestor)
		if ok {
			if err := state.resolve(it.trie, path); err != nil {
				return parent, &parent.index, path, err
			}

			// 将 node 返回
			return state, &parent.index, path, nil
		}
		// No more child nodes, move back up.
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd // 遍历结束了
}

// 根据 遍历到 trie 的node 从 db 将对应的 node加载出来,
//
// 其实 往下看 path 目前并没啥用  (在 tr.resolveHash(hash, path) 中, 没啥实际用处)
func (st *nodeIteratorState) resolve(tr *Trie, path []byte) error {
	if hash, ok := st.node.(hashNode); ok {

		// todo 从 db 中将 hash 对应的 node实例加载出来
		resolved, err := tr.resolveHash(hash, path)
		if err != nil {
			return err
		}
		st.node = resolved
		st.hash = common.BytesToHash(hash)
	}
	return nil
}

func (it *nodeIterator) nextChild(parent *nodeIteratorState, ancestor common.Hash) (*nodeIteratorState, []byte, bool) {
	switch node := parent.node.(type) {
	case *fullNode:
		// Full node, move to the first non-nil child.
		for i := parent.index + 1; i < len(node.Children); i++ {
			child := node.Children[i]
			if child != nil {
				hash, _ := child.cache()
				state := &nodeIteratorState{
					hash:    common.BytesToHash(hash),
					node:    child,
					parent:  ancestor,
					index:   -1,
					pathlen: len(it.path),
				}
				path := append(it.path, byte(i))
				parent.index = i - 1
				return state, path, true
			}
		}
	case *shortNode:
		// Short node, return the pointer singleton child
		if parent.index < 0 {
			hash, _ := node.Val.cache()
			state := &nodeIteratorState{
				hash:    common.BytesToHash(hash),
				node:    node.Val,
				parent:  ancestor,
				index:   -1,
				pathlen: len(it.path),
			}
			path := append(it.path, node.Key...)
			return state, path, true
		}
	}
	return parent, it.path, false
}

func (it *nodeIterator) push(state *nodeIteratorState, parentIndex *int, path []byte) {
	it.path = path
	it.stack = append(it.stack, state)
	if parentIndex != nil {
		*parentIndex++
	}
}

func (it *nodeIterator) pop() {
	parent := it.stack[len(it.stack)-1]
	it.path = it.path[:parent.pathlen]
	it.stack = it.stack[:len(it.stack)-1]
}

func compareNodes(a, b NodeIterator) int {
	if cmp := bytes.Compare(a.Path(), b.Path()); cmp != 0 {
		return cmp
	}
	if a.Leaf() && !b.Leaf() {
		return -1
	} else if b.Leaf() && !a.Leaf() {
		return 1
	}
	if cmp := bytes.Compare(a.Hash().Bytes(), b.Hash().Bytes()); cmp != 0 {
		return cmp
	}
	if a.Leaf() && b.Leaf() {
		return bytes.Compare(a.LeafBlob(), b.LeafBlob())
	}
	return 0
}

type differenceIterator struct {
	a, b  NodeIterator // Nodes returned are those in b - a.
	eof   bool         // Indicates a has run out of elements
	count int          // Number of nodes scanned on either trie
}

// NewDifferenceIterator constructs a NodeIterator that iterates over elements in b that
// are not in a. Returns the iterator, and a pointer to an integer recording the number
// of nodes seen.
func NewDifferenceIterator(a, b NodeIterator) (NodeIterator, *int) {
	a.Next(true)
	it := &differenceIterator{
		a: a,
		b: b,
	}
	return it, &it.count
}

func (it *differenceIterator) Hash() common.Hash {
	return it.b.Hash()
}

func (it *differenceIterator) Parent() common.Hash {
	return it.b.Parent()
}

func (it *differenceIterator) Leaf() bool {
	return it.b.Leaf()
}

func (it *differenceIterator) LeafKey() []byte {
	return it.b.LeafKey()
}

func (it *differenceIterator) LeafBlob() []byte {
	return it.b.LeafBlob()
}

func (it *differenceIterator) LeafProof() [][]byte {
	return it.b.LeafProof()
}

func (it *differenceIterator) Path() []byte {
	return it.b.Path()
}

func (it *differenceIterator) Next(bool) bool {
	// Invariants:
	// - We always advance at least one element in b.
	// - At the start of this function, a's path is lexically greater than b's.
	if !it.b.Next(true) {
		return false
	}
	it.count++

	if it.eof {
		// a has reached eof, so we just return all elements from b
		return true
	}

	for {
		switch compareNodes(it.a, it.b) {
		case -1:
			// b jumped past a; advance a
			if !it.a.Next(true) {
				it.eof = true
				return true
			}
			it.count++
		case 1:
			// b is before a
			return true
		case 0:
			// a and b are identical; skip this whole subtree if the nodes have hashes
			hasHash := it.a.Hash() == common.Hash{}
			if !it.b.Next(hasHash) {
				return false
			}
			it.count++
			if !it.a.Next(hasHash) {
				it.eof = true
				return true
			}
			it.count++
		}
	}
}

func (it *differenceIterator) Error() error {
	if err := it.a.Error(); err != nil {
		return err
	}
	return it.b.Error()
}

type nodeIteratorHeap []NodeIterator

func (h nodeIteratorHeap) Len() int            { return len(h) }
func (h nodeIteratorHeap) Less(i, j int) bool  { return compareNodes(h[i], h[j]) < 0 }
func (h nodeIteratorHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *nodeIteratorHeap) Push(x interface{}) { *h = append(*h, x.(NodeIterator)) }
func (h *nodeIteratorHeap) Pop() interface{} {
	n := len(*h)
	x := (*h)[n-1]
	*h = (*h)[0 : n-1]
	return x
}

type unionIterator struct {
	items *nodeIteratorHeap // Nodes returned are the union of the ones in these iterators
	count int               // Number of nodes scanned across all tries
}

// NewUnionIterator constructs a NodeIterator that iterates over elements in the union
// of the provided NodeIterators. Returns the iterator, and a pointer to an integer
// recording the number of nodes visited.
func NewUnionIterator(iters []NodeIterator) (NodeIterator, *int) {
	h := make(nodeIteratorHeap, len(iters))
	copy(h, iters)
	heap.Init(&h)

	ui := &unionIterator{items: &h}
	return ui, &ui.count
}

func (it *unionIterator) Hash() common.Hash {
	return (*it.items)[0].Hash()
}

func (it *unionIterator) Parent() common.Hash {
	return (*it.items)[0].Parent()
}

func (it *unionIterator) Leaf() bool {
	return (*it.items)[0].Leaf()
}

func (it *unionIterator) LeafKey() []byte {
	return (*it.items)[0].LeafKey()
}

func (it *unionIterator) LeafBlob() []byte {
	return (*it.items)[0].LeafBlob()
}

func (it *unionIterator) LeafProof() [][]byte {
	return (*it.items)[0].LeafProof()
}

func (it *unionIterator) Path() []byte {
	return (*it.items)[0].Path()
}

// Next returns the next node in the union of tries being iterated over.
//
// It does this by maintaining a heap of iterators, sorted by the iteration
// order of their next elements, with one entry for each source trie. Each
// time Next() is called, it takes the least element from the heap to return,
// advancing any other iterators that also point to that same element. These
// iterators are called with descend=false, since we know that any nodes under
// these nodes will also be duplicates, found in the currently selected iterator.
// Whenever an iterator is advanced, it is pushed back into the heap if it still
// has elements remaining.
//
// In the case that descend=false - eg, we're asked to ignore all subnodes of the
// current node - we also advance any iterators in the heap that have the current
// path as a prefix.
func (it *unionIterator) Next(descend bool) bool {
	if len(*it.items) == 0 {
		return false
	}

	// Get the next key from the union
	least := heap.Pop(it.items).(NodeIterator)

	// Skip over other nodes as long as they're identical, or, if we're not descending, as
	// long as they have the same prefix as the current node.
	for len(*it.items) > 0 && ((!descend && bytes.HasPrefix((*it.items)[0].Path(), least.Path())) || compareNodes(least, (*it.items)[0]) == 0) {
		skipped := heap.Pop(it.items).(NodeIterator)
		// Skip the whole subtree if the nodes have hashes; otherwise just skip this node
		if skipped.Next(skipped.Hash() == common.Hash{}) {
			it.count++
			// If there are more elements, push the iterator back on the heap
			heap.Push(it.items, skipped)
		}
	}
	if least.Next(descend) {
		it.count++
		heap.Push(it.items, least)
	}
	return len(*it.items) > 0
}

func (it *unionIterator) Error() error {
	for i := 0; i < len(*it.items); i++ {
		if err := (*it.items)[i].Error(); err != nil {
			return err
		}
	}
	return nil
}
