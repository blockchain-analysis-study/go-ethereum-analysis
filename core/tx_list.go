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

package core

import (
	"container/heap"
	"math"
	"math/big"
	"sort"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/log"
)

// nonceHeap is a heap.Interface implementation over 64bit unsigned integers for
// retrieving sorted transactions from the possibly gapped future queue.
type nonceHeap []uint64

func (h nonceHeap) Len() int           { return len(h) }
func (h nonceHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h nonceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *nonceHeap) Push(x interface{}) {
	*h = append(*h, x.(uint64))
}

func (h *nonceHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// txSortedMap is a nonce->transaction hash map with a heap based index to allow
// iterating over the contents in a nonce-incrementing way.
/**
txSortedMap 是一个 根据heap做索引并允许以递增方式迭代内容，用 key为 nonce,value为 tx的map
 */
type txSortedMap struct {

	// nonce -> tx
	items map[uint64]*types.Transaction // Hash map storing the transaction data
	// 所有存储tx的nonce堆（最小堆）（非严格模式）
	index *nonceHeap                    // Heap of nonces of all the stored transactions (non-strict mode)
	// 缓存已排序的tx
	cache types.Transactions            // Cache of the transactions already sorted
}

// newTxSortedMap creates a new nonce-sorted transaction map.
func newTxSortedMap() *txSortedMap {
	return &txSortedMap{
		items: make(map[uint64]*types.Transaction),
		index: new(nonceHeap),
	}
}

// Get retrieves the current transactions associated with the given nonce.
func (m *txSortedMap) Get(nonce uint64) *types.Transaction {
	return m.items[nonce]
}

// Put inserts a new transaction into the map, also updating the map's nonce
// index. If a transaction already exists with the same nonce, it's overwritten.
func (m *txSortedMap) Put(tx *types.Transaction) {
	nonce := tx.Nonce()
	if m.items[nonce] == nil {
		heap.Push(m.index, nonce)
	}
	m.items[nonce], m.cache = tx, nil
}

// Forward removes all transactions from the map with a nonce lower than the
// provided threshold. Every removed transaction is returned for any post-removal
// maintenance.
/**
Forward 函数：
将使用低于提供的阈值的nonce的tx从列表中删除。
对于任何删除后的维护，都会返回每个已被删除的tx。
 */
func (m *txSortedMap) Forward(threshold uint64) types.Transactions {
	var removed types.Transactions

	// Pop off heap items until the threshold is reached
	// 弹出堆中元素，直到达到阈值
	for m.index.Len() > 0 && (*m.index)[0] < threshold {
		// heap 中的元素是在 Add 方法里面加的 参照：txList 结构自己就明白了
		nonce := heap.Pop(m.index).(uint64)
		// 把被删除的 元素收集起来，返回出去
		removed = append(removed, m.items[nonce])
		// 清楚 存储
		delete(m.items, nonce)
	}
	// If we had a cached order, shift the front
	// 如果我们有一个排序缓存，那么将当前被删除的集，向前转移
	if m.cache != nil {
		m.cache = m.cache[len(removed):]
	}
	return removed
}

// Filter iterates over the list of transactions and removes all of them for which
// the specified function evaluates to true.
/**
移除掉所有根据入参func 执行得到的结果为 true 的tx，并将收集返回
 */
func (m *txSortedMap) Filter(filter func(*types.Transaction) bool) types.Transactions {
	var removed types.Transactions

	// Collect all the transactions to filter out
	for nonce, tx := range m.items {
		if filter(tx) {
			// 收集移除的tx
			removed = append(removed, tx)
			// 从 当前或者账户的 tx map中移除该tx
			delete(m.items, nonce)
		}
	}
	// If transactions were removed, the heap and cache are ruined
	// 如果tx 被删除了，那么对应的heap和cache中和该tx相关的信息都 销毁掉
	if len(removed) > 0 {
		// 把剩下的 items中的内容重新调整堆
		*m.index = make([]uint64, 0, len(m.items))
		for nonce := range m.items {
			*m.index = append(*m.index, nonce)
		}
		heap.Init(m.index)
		// 清空缓存
		/**
		(【注意】： cache 是在 Flatten 函数中被 创建)
		*/
		m.cache = nil
	}
	// 返回被删除的tx集
	return removed
}

// Cap places a hard limit on the number of items, returning all transactions
// exceeding that limit.
/**
Cap函数：
对items (一个装有当前账户的 nonce -> tx 的map)的数量设置了硬限制，返回超过该限制的所有交易。
 */
func (m *txSortedMap) Cap(threshold int) types.Transactions {
	// Short circuit if the number of items is under the limit
	// 如果项目数量低于限制，则短路(直接返回)
	if len(m.items) <= threshold {
		return nil
	}
	// Otherwise gather and drop the highest nonce'd transactions
	// 否则收集和删除最高的nonce'd交易
	var drops types.Transactions

	// 排序之前最小堆中的所有 nonce
	sort.Sort(*m.index)

	// 遍历当前用户的所有 nonce -> tx 的map
	for size := len(m.items); size > threshold; size-- {
		// 将超出 硬限制的 nonce -> tx 的从 items中删除，并将 tx 收集到 drop中返回
		drops = append(drops, m.items[(*m.index)[size-1]])
		delete(m.items, (*m.index)[size-1])
	}
	// 只保留没有超过 硬限制数目部分的 nonce数组
	*m.index = (*m.index)[:threshold]
	// 重新调整最小堆
	heap.Init(m.index)

	// If we had a cache, shift the back
	// 如果我们有一个缓存，请向后移动
	if m.cache != nil {
		m.cache = m.cache[:len(m.cache)-len(drops)]
	}
	// 返回被删除的 tx
	return drops
}

// Remove deletes a transaction from the maintained map, returning whether the
// transaction was found.
func (m *txSortedMap) Remove(nonce uint64) bool {
	// Short circuit if no transaction is present
	_, ok := m.items[nonce]
	if !ok {
		return false
	}
	// Otherwise delete the transaction and fix the heap index
	for i := 0; i < m.index.Len(); i++ {
		if (*m.index)[i] == nonce {
			heap.Remove(m.index, i)
			break
		}
	}
	delete(m.items, nonce)
	/**
	(【注意】： cache 是在 Flatten 函数中被 创建)
	*/
	m.cache = nil

	return true
}

// Ready retrieves a sequentially increasing list of transactions starting at the
// provided nonce that is ready for processing. The returned transactions will be
// removed from the list.
//
// Note, all transactions with nonces lower than start will also be returned to
// prevent getting into and invalid state. This is not something that should ever
// happen but better to be self correcting than failing!
func (m *txSortedMap) Ready(start uint64) types.Transactions {
	// Short circuit if no transactions are available
	if m.index.Len() == 0 || (*m.index)[0] > start {
		return nil
	}
	// Otherwise start accumulating incremental transactions
	var ready types.Transactions
	for next := (*m.index)[0]; m.index.Len() > 0 && (*m.index)[0] == next; next++ {
		ready = append(ready, m.items[next])
		delete(m.items, next)
		heap.Pop(m.index)
	}

	/**
	(【注意】： cache 是在 Flatten 函数中被 创建)
	*/
	m.cache = nil

	return ready
}

// Len returns the length of the transaction map.
func (m *txSortedMap) Len() int {
	return len(m.items)
}

// Flatten creates a nonce-sorted slice of transactions based on the loosely
// sorted internal representation. The result of the sorting is cached in case
// it's requested again before any modifications are made to the contents.
/**
Flatten 函数：
基于松散排序的内部表现创建一个按照 nonce 排序的 tx slice。
如果在对内容进行任何修改之前再次请求，则对缓存的结果须是有序的。

即：对 tx list构建 构建一个 根据 nonce 从小到大的 排序的 cache，并返回 cache中的tx
 */
func (m *txSortedMap) Flatten() types.Transactions {
	// If the sorting was not cached yet, create and cache it
	// 如果尚未缓存排序，则创建并缓存它
	/**
	(【注意】： cache 是在 Filter、Remove、Ready 函数中被 清空)
	*/
	if m.cache == nil {
		m.cache = make(types.Transactions, 0, len(m.items))
		// 将 items 中的交易全部收集到 cache中
		for _, tx := range m.items {
			m.cache = append(m.cache, tx)
		}
		// 强转成 types.TxByNonce 类型，并排序
		sort.Sort(types.TxByNonce(m.cache))
	}
	// Copy the cache to prevent accidental modifications
	// 复制缓存以防止意外修改
	txs := make(types.Transactions, len(m.cache))
	copy(txs, m.cache)
	return txs
}

// txList is a "list" of transactions belonging to an account, sorted by account
// nonce. The same type can be used both for storing contiguous transactions for
// the executable/pending queue; and for storing gapped transactions for the non-
// executable/future queue, with minor behavioral changes.
/**
txList是属于单个帐户的tx的“列表”，
按帐户nonce排序(最小堆排)。
相同类型(该类型)可用于存储可执行/挂起队列的连续tx;
并且用于存储非可执行/未来队列的间隙事务，并且具有微小的行为变动。
 */
type txList struct {

	// 表示当前账户的txs 的 nonce是否严格连续
	strict bool         // Whether nonces are strictly continuous or not

	// 当前账户的所有 tx 相关
	// 按照 heap的索引去存储所有tx的map
	txs    *txSortedMap // Heap indexed sorted hash map of the transactions

	// 阈值：最高成本交易的价格（仅在超出余额时重置）
	costcap *big.Int // Price of the highest costing transaction (reset only if exceeds balance)

	// 阈值：最高支出交易的燃气限制（仅在超过限额时重置）
	gascap  uint64   // Gas limit of the highest spending transaction (reset only if exceeds block limit)
}

// newTxList create a new transaction list for maintaining nonce-indexable fast,
// gapped, sortable transaction lists.
func newTxList(strict bool) *txList {
	return &txList{
		strict:  strict,
		txs:     newTxSortedMap(),
		costcap: new(big.Int),
	}
}

// Overlaps returns whether the transaction specified has the same nonce as one
// already contained within the list.
// 判断当前tx的nonce是否之前就在pending 队列中出现过
// 是的话，说明是同一笔交易的更改提交
func (l *txList) Overlaps(tx *types.Transaction) bool {
	return l.txs.Get(tx.Nonce()) != nil
}

// Add tries to insert a new transaction into the list, returning whether the
// transaction was accepted, and if yes, any previous transaction it replaced.
//
// If the new transaction is accepted into the list, the lists' cost and gas
// thresholds are also potentially updated.
/**
添加尝试将新tx插入列表，返回 tx 是否被接受标识位，如果是，则替换之前的 tx。

如果新 tx被接受到列表中，则列表的成本和气体阈值也可能会更新。
 */
func (l *txList) Add(tx *types.Transaction, priceBump uint64) (bool, *types.Transaction) {
	// If there's an older better transaction, abort
	// 如果有较旧的更好的交易，则直接退出 func
	// 就是说 nonce一样的旧有 tx 比当前tx还要好的话，则直接返回
	old := l.txs.Get(tx.Nonce())
	if old != nil {
		// (old.gas * (100 + priceBump) / 100) 计算旧有tx的gas 的 110% 作为 阈值
		threshold := new(big.Int).Div(new(big.Int).Mul(old.GasPrice(), big.NewInt(100+int64(priceBump))), big.NewInt(100))
		// Have to ensure that the new gas price is higher than the old gas
		// price as well as checking the percentage threshold to ensure that
		// this is accurate for low (Wei-level) gas price replacements
		/**
		必须确保新的tx 的 gasPrice高于旧的tx的gasPrice以及检查百分比阈值，以确保这对于低（wei 级）gasPrice替换是准确的
		就是说：确保相同nonce值的新tx的gasPrice 比旧有的tx的gasPrice 高，并且要高于 old * 110%
		 */
		if old.GasPrice().Cmp(tx.GasPrice()) >= 0 || threshold.Cmp(tx.GasPrice()) > 0 {
			return false, nil
		}
	}
	// Otherwise overwrite the old transaction with the current one
	// 否则用当前tx覆盖旧tx
	l.txs.Put(tx)
	// 调整当前 list中 的最大成本
	if cost := tx.Cost(); l.costcap.Cmp(cost) < 0 {
		l.costcap = cost
	}
	// 调整当前list 中的最大 gas成本
	if gas := tx.Gas(); l.gascap < gas {
		l.gascap = gas
	}
	return true, old
}

// Forward removes all transactions from the list with a nonce lower than the
// provided threshold. Every removed transaction is returned for any post-removal
// maintenance.
/**
Forward 函数：
将使用低于提供的阈值的nonce的tx从列表中删除。
对于任何删除后的维护，都会返回每个已被删除的tx。
 */
func (l *txList) Forward(threshold uint64) types.Transactions {
	return l.txs.Forward(threshold)
}

// Filter removes all transactions from the list with a cost or gas limit higher
// than the provided thresholds. Every removed transaction is returned for any
// post-removal maintenance. Strict-mode invalidated transactions are also
// returned.
//
// This method uses the cached costcap and gascap to quickly decide if there's even
// a point in calculating all the costs or if the balance covers all. If the threshold
// is lower than the costgas cap, the caps will be reset to a new high after removing
// the newly invalidated transactions.
/**
过滤器从列表中删除所有tx，其成本或气体限制高于提供的阈值。  还返回严格模式的无效tx。

Filter 函数：(只过滤当前账户的所有 tx)
移除掉所有在tx集中由于 成本过高，或者 gas限制过高(本身gas不足于支付)的tx。
对于任何删除后维护，都会返回每个已删除的tx。
且返回在严格模式的无效tx。


此方法使用缓存的costcap和gascap来快速确定是否在计算所有成本或者余额是否涵盖完整。
如果阈值低于成本限额上限，则在删除新的无效tx后，上限将重置为新的高。

 */
func (l *txList) Filter(costLimit *big.Int, gasLimit uint64) (types.Transactions, types.Transactions) {
	// If all transactions are below the threshold, short circuit
	// 如果 所有tx 都低于阈值，那么就 短路(直接返回)： tx 低于阈值则说明 当前tx的 from的 balance 和gas是足够支付当前tx的，tx是合法的
	if l.costcap.Cmp(costLimit) <= 0 && l.gascap <= gasLimit {
		return nil, nil
	}
	l.costcap = new(big.Int).Set(costLimit) // Lower the caps to the thresholds  将上限降低到阈值
	l.gascap = gasLimit

	// Filter out all the transactions above the account's funds
	// 过滤掉帐户的所有 资金超出限额的交易
	removed := l.txs.Filter(func(tx *types.Transaction) bool {
		// todo Cost: tx.Value + tx.Gas*tx.GasPrice
		//
		// 收集
		// todo value + gas*gasPrice 大于from余额的 交易
		// todo tx.Gas 大于 pool 中的gasLimit 的 交易
		return tx.Cost().Cmp(costLimit) > 0 || tx.Gas() > gasLimit })

	// If the list was strict, filter anything above the lowest nonce
	// 如果列表是严格的，则过滤掉最低nonce之上的任何内容
	var invalids types.Transactions

	// 表示当前账户的txs 的 nonce是否严格连续
	// 且有被删除的tx
	if l.strict && len(removed) > 0 {
		// 取最大的 uint64
		lowest := uint64(math.MaxUint64)
		// 不断的调整 lowest 中间变量 (取出被删除的tx中的最小的那个nonce)
		for _, tx := range removed {
			if nonce := tx.Nonce(); lowest > nonce {
				lowest = nonce
			}
		}
		// 再次过滤出 比 被删除tx中最小nonce还要大的tx
		invalids = l.txs.Filter(func(tx *types.Transaction) bool { return tx.Nonce() > lowest })
	}
	// todo removed：不够支付转账金额 或者gas的交易
	// todo invalids：nonce比removed中最小nonce还大的tx (因为某tx都被删了，那么在 要求当前账户txs的nonce严格连续的条件下，比它nonce大的tx也就非法了)
	return removed, invalids
}

// Cap places a hard limit on the number of items, returning all transactions
// exceeding that limit.
func (l *txList) Cap(threshold int) types.Transactions {
	return l.txs.Cap(threshold)
}

// Remove deletes a transaction from the maintained list, returning whether the
// transaction was found, and also returning any transaction invalidated due to
// the deletion (strict mode only).
func (l *txList) Remove(tx *types.Transaction) (bool, types.Transactions) {
	// Remove the transaction from the set
	nonce := tx.Nonce()
	if removed := l.txs.Remove(nonce); !removed {
		return false, nil
	}
	// In strict mode, filter out non-executable transactions
	if l.strict {
		return true, l.txs.Filter(func(tx *types.Transaction) bool { return tx.Nonce() > nonce })
	}
	return true, nil
}

// Ready retrieves a sequentially increasing list of transactions starting at the
// provided nonce that is ready for processing. The returned transactions will be
// removed from the list.
//
// Note, all transactions with nonces lower than start will also be returned to
// prevent getting into and invalid state. This is not something that should ever
// happen but better to be self correcting than failing!
func (l *txList) Ready(start uint64) types.Transactions {
	return l.txs.Ready(start)
}

// Len returns the length of the transaction list.
func (l *txList) Len() int {
	return l.txs.Len()
}

// Empty returns whether the list of transactions is empty or not.
func (l *txList) Empty() bool {
	return l.Len() == 0
}

// Flatten creates a nonce-sorted slice of transactions based on the loosely
// sorted internal representation. The result of the sorting is cached in case
// it's requested again before any modifications are made to the contents.
/**
Flatten 函数：
基于松散排序的内部表现创建一个按照 nonce 排序的 tx slice。
如果在对内容进行任何修改之前再次请求，则对缓存的结果须是有序的。

即：对 tx list构建 构建一个 根据 nonce 从小到大的 排序的 cache，并返回 cache中的tx
 */
func (l *txList) Flatten() types.Transactions {
	return l.txs.Flatten()
}

// priceHeap is a heap.Interface implementation over transactions for retrieving
// price-sorted transactions to discard when the pool fills up.
type priceHeap []*types.Transaction

func (h priceHeap) Len() int      { return len(h) }
func (h priceHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

// 根据 gasPrice对比
func (h priceHeap) Less(i, j int) bool {
	// Sort primarily by price, returning the cheaper one
	switch h[i].GasPrice().Cmp(h[j].GasPrice()) {
	case -1:
		return true
	case 1:
		return false
	}
	// If the prices match, stabilize via nonces (high nonce is worse)
	return h[i].Nonce() > h[j].Nonce()
}

func (h *priceHeap) Push(x interface{}) {
	*h = append(*h, x.(*types.Transaction))
}

func (h *priceHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// txPricedList is a price-sorted heap to allow operating on transactions pool
// contents in a price-incrementing way.
/**
txPricedList是一个价格排序堆，允许以价格递增的方式对 tx池内容进行操作。
 */
type txPricedList struct {
	// 底层是一个存储所有交易的map txHash -> txInfo 【注意这里的 all 和 pool 中的 all是同一个引用， 而txPricedList又是以 price 字段保存在 pool中】
	all    *txLookup  // Pointer to the map of all transactions

	// 所有存储的交易的价格 (gasPrice)堆（里面就是tx数组）
	items  *priceHeap // Heap of prices of all the stored transactions

	// 过期价格点数（重堆积触发器）其实就是个计数器啦
	// 记录删除了对少个因过期而删除的 tx
	stales int        // Number of stale price points to (re-heap trigger)
}

// newTxPricedList creates a new price-sorted transaction heap.
func newTxPricedList(all *txLookup) *txPricedList {
	return &txPricedList{
		all:   all,
		items: new(priceHeap),
	}
}

// Put inserts a new transaction into the heap.
func (l *txPricedList) Put(tx *types.Transaction) {
	heap.Push(l.items, tx)
}

// Removed notifies the prices transaction list that an old transaction dropped
// from the pool. The list will just keep a counter of stale objects and update
// the heap if a large enough ratio of transactions go stale.
/**
旧的tx从池中删除并将 该删除通知 prices 池。
如果旧 tx占有的比例足够多，在 prices 列表将保留就对象的计数器，并更新 heap中的内容。
 */
func (l *txPricedList) Removed() {
	// Bump the stale counter, but exit if still too low (< 25%)
	// 根据一定规则跳跃对比过时的计数器的值，但如果仍然太低（<25％ (所有tx的数组)）则退出
	l.stales++
	if l.stales <= len(*l.items)/4 {
		return
	}
	// Seems we've reached a critical number of stale transactions, reheap
	// 似乎我们已经达到了过期的tx的临界数量，重新调整
	// 创建一个tx的数组，大小和 所有tx的 map一样大
	reheap := make(priceHeap, 0, l.all.Count())

	// 初始化计数器，初始化 tx的所有数组引用
	l.stales, l.items = 0, &reheap
	// 递归处理tx map中的所有 k-v
	l.all.Range(func(hash common.Hash, tx *types.Transaction) bool {
		// 把 tx map中的tx全部收集到 tx数组中
		*l.items = append(*l.items, tx)
		return true
	})
	// 根据所有tx 初始化成一个 最小堆
	heap.Init(l.items)
}

// Cap finds all the transactions below the given price threshold, drops them
// from the priced list and returns them for further removal from the entire pool.
func (l *txPricedList) Cap(threshold *big.Int, local *accountSet) types.Transactions {
	drop := make(types.Transactions, 0, 128) // Remote underpriced transactions to drop
	save := make(types.Transactions, 0, 64)  // Local underpriced transactions to keep

	for len(*l.items) > 0 {
		// Discard stale transactions if found during cleanup
		tx := heap.Pop(l.items).(*types.Transaction)
		if l.all.Get(tx.Hash()) == nil {
			l.stales--
			continue
		}
		// Stop the discards if we've reached the threshold
		if tx.GasPrice().Cmp(threshold) >= 0 {
			save = append(save, tx)
			break
		}
		// Non stale transaction found, discard unless local
		if local.containsTx(tx) {
			save = append(save, tx)
		} else {
			drop = append(drop, tx)
		}
	}
	for _, tx := range save {
		heap.Push(l.items, tx)
	}
	return drop
}

// Underpriced checks whether a transaction is cheaper than (or as cheap as) the
// lowest priced transaction currently being tracked.
/**
低价检查交易是否比当前跟踪的最低价交易便宜（或便宜）。
 */
func (l *txPricedList) Underpriced(tx *types.Transaction, local *accountSet) bool {
	// Local transactions cannot be underpriced
	// 本地交易不能低估
	// 先判断 tx中的from 是否属于 locals 中
	// 如果是 locals中的addr的交易则直接过掉
	if local.containsTx(tx) {
		return false
	}
	// Discard stale price points if found at the heap start
	// 如果在堆启动时找到过时的价格点，则丢弃
	// 逐个遍历当前addr的 tx list中的heap中的 tx
	// 如果已经在all中找不到了，则需要从当前heap中 移除
	for len(*l.items) > 0 {
		head := []*types.Transaction(*l.items)[0]
		if l.all.Get(head.Hash()) == nil {
			l.stales--
			heap.Pop(l.items)
			continue
		}
		break
	}
	// Check if the transaction is underpriced or not
	// 检查交易是否定价过低
	if len(*l.items) == 0 {
		// 这不可能发生，打印以捕获编程错误
		log.Error("Pricing query for empty pool") // This cannot happen, print to catch programming errors
		return false
	}
	cheapest := []*types.Transaction(*l.items)[0]
	// 最后用 items中的第一个tx的gasPrice 和当前 tx做一次对比,
	// 这里用第一个是有讲究的，因为后面的都会比第一个gasPrice 大
	// 所以如果当前tx 链 items中的第一个tx的gasPrice 还要小的话，那么就是不合法了
	return cheapest.GasPrice().Cmp(tx.GasPrice()) >= 0
}

// Discard finds a number of most underpriced transactions, removes them from the
// priced list and returns them for further removal from the entire pool.
/**
Discard 函数
找出 绝大多数定价过低的交易，将它们从 priced 列表中删除并返回它们 以便从整个池中进一步删除。
 */
func (l *txPricedList) Discard(count int, local *accountSet) types.Transactions {
	drop := make(types.Transactions, 0, count) // Remote underpriced transactions to drop  	远端的 低价tx将被抛弃
	save := make(types.Transactions, 0, 64)    // Local underpriced transactions to keep	本地的 低价tx将保留

	for len(*l.items) > 0 && count > 0 {
		// Discard stale transactions if found during cleanup
		// 如果在清理过程中找到 旧有 tx,则抛弃掉
		tx := heap.Pop(l.items).(*types.Transaction)
		if l.all.Get(tx.Hash()) == nil {
			l.stales--
			continue
		}
		// Non stale transaction found, discard unless local
		// 发现非陈旧tx，除非是本地的，否则丢弃
		if local.containsTx(tx) {
			save = append(save, tx)
		} else {
			drop = append(drop, tx)
			count--
		}
	}
	// 本地的tx，重置回 items 中
	for _, tx := range save {
		heap.Push(l.items, tx)
	}
	return drop
}
