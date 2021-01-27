// Copyright 2015 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

// Contains the block download scheduler to collect download tasks and schedule
// them in an ordered, and throttled way.

package downloader

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/types"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/metrics"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

var (
	blockCacheItems      = 8192             // Maximum number of blocks to cache before throttling the download
	blockCacheMemory     = 64 * 1024 * 1024 // Maximum amount of memory to use for block caching
	// 乘以近似基于过去的平均块大小 (用来计算 downloader 同步时,的内存占用大小)
	blockCacheSizeWeight = 0.1              // Multiplier to approximate the average block size based on past ones
)

var (
	errNoFetchesPending = errors.New("no fetches pending")
	errStaleDelivery    = errors.New("stale delivery")
)

// fetchRequest is a currently running data retrieval operation.
type fetchRequest struct {
	Peer    *peerConnection // Peer to which the request was sent
	From    uint64          // [eth/62] Requested chain element index (used for skeleton fills only)
	Headers []*types.Header // [eth/62] Requested headers, sorted by request order
	Time    time.Time       // Time when the request was made
}

// fetchResult is a struct collecting partial results from data fetchers until
// all outstanding pieces complete and the result as a whole can be processed.
//
// fetchResult 是一个结构，
// 它从数据获取器中收集部分结果，
// 直到所有未完成的部分完成并且整个结果可以被处理
type fetchResult struct {
	// 仍待处理的数据提取数量 <即: 这些数据还在需要被处理>
	Pending int         // Number of data fetches still pending
	// header的hash以防止重新计算
	Hash    common.Hash // Hash of the header to prevent recalculating

	// 该Hash 对应的 header
	Header       *types.Header
	// 其,相关的 uncles
	Uncles       []*types.Header

	// 该Hash 对应的block body 中的所有txs
	Transactions types.Transactions
	// 该Hash 对应的block body 中的所有receipts
	Receipts     types.Receipts
}

// queue represents hashes that are either need fetching or are being fetched
/**
todo queue: 代表  需要获取  或  正在获取  的hashes

todo queue 对象是 downloader 模块的一个内部对象，只有 Downloader 对象使用了它.

todo queue 对象是 downlaoder 模块的一个辅助对象，它的主要目的，是记录所需下载区块的各种信息，以及将分开下载的各区块信息（header，body，receipt等）组成完整的区块.

即: 正在被处理的block 相关的 部件集合/ 队列 等等杂七杂八的

在下载正式发起之前，以及数据真正下载之前，Downloader 对象会调用 queue 的一些方法，对其进行初始化，或将需要下载的数据信息告诉 queue

Downloader 对象会使用 queue 提供的一些信息来决定和判断数据的下载状态等信息

 */
type queue struct {
	// 同步模式决定要计划要提取的block的部件
	mode SyncMode // Synchronisation mode to decide on the block parts to schedule for fetching

	// Headers are "special", they download in batches, supported by a skeleton chain
	//
	// Headers是“特殊的”，它们是分批下载的，并由骨架链来决定
	//
	//
	//  - - - - - - - -  - - - - -  抓取 headers 相关  - - - - - - - -  - - - -  - -

	// 最后一个排队的header的Hash以验证顺序 (用来校验 chain 的顺序)
	headerHead      common.Hash                    // [eth/62] Hash of the last queued header to verify order

	// 待处理的 header 拉取task，将 起始索引映射到 骨架的headers上， 保存所有骨架点的 header， 以每一个 骨架点作为task的起始
	//
	// (骨架点Number -> 骨架点Header)
	//
	//
	// todo 而我们刚才提到过 skeleton 参数中的区块头是每一组区块中的最后一个区块，
	// todo 因此 queue.headerTaskPool 实际上是一个每一组区块中第一个区块的高度到最后一个区块的 header 的映射
	//
	headerTaskPool  map[uint64]*types.Header       // [eth/62] Pending header retrieval tasks, mapping starting indexes to skeleton headers

	// 为了拉取header填充骨架的骨架 的 headers 抓取 task 优先队列
	headerTaskQueue *prque.Prque                   // [eth/62] Priority queue of the skeleton indexes to fetch the filling headers for

	// 每个peer 的header batch的已知不可用的集合
	//
	// 记录着节点下载数据失败的信息，通过这个字段 queue.ReserveHeaders() 避免了让远程节点重复下载它曾经下载失败的数据.
	headerPeerMiss  map[string]map[uint64]struct{} // [eth/62] Set of per-peer header batches known to be unavailable

	// 正在进行中 的 抓取 header 的 req    (nodeId -> req)
	headerPendPool  map[string]*fetchRequest       // [eth/62] Currently pending header retrieval operations

	// 结果缓存累积完成的 header (这里的已完成指的是 同步拉取回来的headers,  不是指 已经处理完成的)
	headerResults   []*types.Header                // [eth/62] Result cache accumulating the completed headers

	// 已被处理的 header 数量
	headerProced    int                            // [eth/62] Number of headers already processed from the results

	// 结果缓存中第一个header的编号, 即: 当时构建骨架时的 起始点
	headerOffset    uint64                         // [eth/62] Number of the first header in the result cache

	// headers下载全部完成时通知的chan (即: headers 全部被下载完了)
	headerContCh    chan bool                      // [eth/62] Channel to notify when header download finishes

	// All data retrievals below are based on an already assembles header chain
	//
	//
	// - - - - -- - -  -    以下所有数据拉取均基于已组装的 header chain  - - - - - - -  - - - - -  - - - -
	//
	//

	//  - - - - - - - -  - -  抓取 bodies 相关的  - - - - - - - - -  - - - - -
	//
	// 待处理的 block（ body）拉取task，将 hashes 映射到 headers
	blockTaskPool  map[common.Hash]*types.Header // [eth/62] Pending block (body) retrieval tasks, mapping hashes to headers

	// 用来抓取 body 的 task 优先队列
	blockTaskQueue *prque.Prque                  // [eth/62] Priority queue of the headers to fetch the blocks (bodies) for

	// 正在进行中的 抓取 block 的 req实例  (nodeId -> req)
	blockPendPool  map[string]*fetchRequest      // [eth/62] Currently pending block (body) retrieval operations

	// 一组已完成抓取的block（body）的hash (去重用)
	blockDonePool  map[common.Hash]struct{}      // [eth/62] Set of the completed block (body) fetches

	// - - - - - - - - - - - -  抓取 receipts 相关的 - - - - --- - - - - - - - -  -
	//
	// 等待receipt拉取的task，将Hash映射到对用的header
	receiptTaskPool  map[common.Hash]*types.Header // [eth/63] Pending receipt retrieval tasks, mapping hashes to headers

	// 用来抓取 receipts 的 task  优先队列
	receiptTaskQueue *prque.Prque                  // [eth/63] Priority queue of the headers to fetch the receipts for

	// 正在进行中 的 抓取 receipt 的 req   (nodeId -> req)
	receiptPendPool  map[string]*fetchRequest      // [eth/63] Currently pending receipt retrieval operations

	// 一组已完成抓取的 receipt的hash
	receiptDonePool  map[common.Hash]struct{}      // [eth/63] Set of the completed receipt fetches

	// 已经被下载完成 但尚未被处理的 req (即: req回来了但是结果数据还未被及时处理)
	//
	// (header, body, receipt)等都被下载了的数据 ...
	resultCache  []*fetchResult     // Downloaded but not yet delivered fetch results

	// 区块链中第一个缓存的获取结果的偏移量
	resultOffset uint64             // Offset of the first cached fetch result in the block chain

	// block的近似大小（指数移动平均线）
	resultSize   common.StorageSize // Approximate size of a block (exponential moving average)

	lock   *sync.Mutex
	active *sync.Cond

	// 队列 关闭信号
	closed bool
}

// newQueue creates a new download queue for scheduling block retrieval.
func newQueue() *queue {
	lock := new(sync.Mutex)
	return &queue{
		headerPendPool:   make(map[string]*fetchRequest),
		headerContCh:     make(chan bool),
		blockTaskPool:    make(map[common.Hash]*types.Header),
		blockTaskQueue:   prque.New(),
		blockPendPool:    make(map[string]*fetchRequest),
		blockDonePool:    make(map[common.Hash]struct{}),
		receiptTaskPool:  make(map[common.Hash]*types.Header),
		receiptTaskQueue: prque.New(),
		receiptPendPool:  make(map[string]*fetchRequest),
		receiptDonePool:  make(map[common.Hash]struct{}),
		resultCache:      make([]*fetchResult, blockCacheItems),
		active:           sync.NewCond(lock),
		lock:             lock,
	}
}

// Reset clears out the queue contents.
//
func (q *queue) Reset() {
	q.lock.Lock()
	defer q.lock.Unlock()

	q.closed = false
	q.mode = FullSync

	q.headerHead = common.Hash{}
	q.headerPendPool = make(map[string]*fetchRequest)

	q.blockTaskPool = make(map[common.Hash]*types.Header)
	q.blockTaskQueue.Reset()
	q.blockPendPool = make(map[string]*fetchRequest)
	q.blockDonePool = make(map[common.Hash]struct{})

	q.receiptTaskPool = make(map[common.Hash]*types.Header)
	q.receiptTaskQueue.Reset()
	q.receiptPendPool = make(map[string]*fetchRequest)
	q.receiptDonePool = make(map[common.Hash]struct{})

	q.resultCache = make([]*fetchResult, blockCacheItems)
	q.resultOffset = 0
}

// Close marks the end of the sync, unblocking WaitResults.
// It may be called even if the queue is already closed.
//
// 标志着同步的结束，不阻塞 WaitResults.
// 即使队列已经关闭也可能被调用.
func (q *queue) Close() {
	q.lock.Lock()
	// 添加 close 标识
	q.closed = true
	q.lock.Unlock()
	q.active.Broadcast()
}




//  ----- -- --- ---- ---  pending 系列方法, 用来告诉调用者还有多少条数据需要下载  ----- -- --- ---- ---

// PendingHeaders retrieves the number of header requests pending for retrieval.
func (q *queue) PendingHeaders() int {
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.headerTaskQueue.Size()
}

// PendingBlocks retrieves the number of block (body) requests pending for retrieval.
func (q *queue) PendingBlocks() int {
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.blockTaskQueue.Size()
}

// PendingReceipts retrieves the number of block receipts pending for retrieval.
func (q *queue) PendingReceipts() int {
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.receiptTaskQueue.Size()
}






//
// - - - - - - - - - -  InFlight 系列方法, 用来告诉调用者当前是否有数据 正在被下载. - -  - - - - - -  - - - -
//


// InFlightHeaders retrieves whether there are header fetch requests currently
// in flight.
func (q *queue) InFlightHeaders() bool {
	q.lock.Lock()
	defer q.lock.Unlock()

	return len(q.headerPendPool) > 0
}

// InFlightBlocks retrieves whether there are block fetch requests currently in
// flight.
func (q *queue) InFlightBlocks() bool {
	q.lock.Lock()
	defer q.lock.Unlock()

	return len(q.blockPendPool) > 0
}

// InFlightReceipts retrieves whether there are receipt fetch requests currently
// in flight.
func (q *queue) InFlightReceipts() bool {
	q.lock.Lock()
	defer q.lock.Unlock()

	return len(q.receiptPendPool) > 0
}

// Idle returns if the queue is fully idle or has some data still inside.
func (q *queue) Idle() bool {
	q.lock.Lock()
	defer q.lock.Unlock()

	queued := q.blockTaskQueue.Size() + q.receiptTaskQueue.Size()
	pending := len(q.blockPendPool) + len(q.receiptPendPool)
	cached := len(q.blockDonePool) + len(q.receiptDonePool)

	return (queued + pending + cached) == 0
}


//
// - - - - - - -  - - -  ShouldThrottle 系列方法 - - - - - - - -  - - - -
//
// 用来告诉 调用者 是否该限制（或称为暂停）一下某类数据的下载， 其目的是为了防止下载过程中本地内存占用过大.
//
// 在 Downloader.fetchParts() 中向 某对端 peer 发起 获取数据请求之前，会进行这种判断.
//

// ShouldThrottleBlocks checks if the download should be throttled (active block (body)
// fetches exceed block cache).
func (q *queue) ShouldThrottleBlocks() bool {
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.resultSlots(q.blockPendPool, q.blockDonePool) <= 0
}

// ShouldThrottleReceipts checks if the download should be throttled (active receipt
// fetches exceed block cache).
func (q *queue) ShouldThrottleReceipts() bool {
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.resultSlots(q.receiptPendPool, q.receiptDonePool) <= 0
}

// resultSlots calculates the number of results slots available for requests
// whilst adhering to both the item and the memory limit too of the results
// cache.
func (q *queue) resultSlots(pendPool map[string]*fetchRequest, donePool map[common.Hash]struct{}) int {
	// Calculate the maximum length capped by the memory limit
	limit := len(q.resultCache)
	if common.StorageSize(len(q.resultCache))*q.resultSize > common.StorageSize(blockCacheMemory) {
		limit = int((common.StorageSize(blockCacheMemory) + q.resultSize - 1) / q.resultSize)
	}
	// Calculate the number of slots already finished
	finished := 0
	for _, result := range q.resultCache[:limit] {
		if result == nil {
			break
		}
		if _, ok := donePool[result.Hash]; ok {
			finished++
		}
	}
	// Calculate the number of slots currently downloading
	pending := 0
	for _, request := range pendPool {
		for _, header := range request.Headers {
			if header.Number.Uint64() < q.resultOffset+uint64(limit) {
				pending++
			}
		}
	}
	// Return the free slots to distribute
	return limit - finished - pending
}

// ScheduleSkeleton adds a batch of header retrieval tasks to the queue to fill
// up an already retrieved header skeleton.
//
//
// 用来在填充 skeleton 之前，使用 skeketon 的信息对 queue 对象进行初始化
//
//  入参:
//
//		from: 		要下载 block 的起始点
//		skeleton:	所有 骨架点上的 headers   (再次强调一下这些 header 是  每一组的最后一个 blockHeader)
//
//
func (q *queue) ScheduleSkeleton(from uint64, skeleton []*types.Header) {
	q.lock.Lock()
	defer q.lock.Unlock()

	//
	// - - - - - - -  对 queue 的 各个字段的初始化  - - - - - - - - -
	//

	// No skeleton retrieval can be in progress, fail hard if so (huge implementation bug)
	// 无法进行骨架 拉取，否则将导致失败（巨大的实现 bug）
	if q.headerResults != nil {
		panic("skeleton assembly already in progress")
	}
	// Schedule all the header retrieval tasks for the skeleton assembly
	//
	// 为了骨架装配而去拉取回来的所有 header的拉取task
	q.headerTaskPool = make(map[uint64]*types.Header)

	// 为了拉取header填充骨架的骨架索引优先队列
	//
	q.headerTaskQueue = prque.New()

	// 重置可用性以更正无效链
	// headerPeerMiss: 每个peer 的header batch的已知不可用的集合
	//
	q.headerPeerMiss = make(map[string]map[uint64]struct{}) // Reset availability to correct invalid chains

	// 结果缓存累积完成的 header
	//
	q.headerResults = make([]*types.Header, len(skeleton)*MaxHeaderFetch)

	// 初始化已被处理的 header 数量
	q.headerProced = 0

	// 结果缓存中第一个header的编号,   即:  当时构建骨架时的 起始点
	q.headerOffset = from

	// headers下载全部完成时通知的chan (即: headers 全部被下载完了)
	q.headerContCh = make(chan bool, 1)

	// skeleton中每一组区块的个数是 MaxHeaderFetch <192>，(从  from+191 开始拉取一批 headers, 最多拉 128 个headers, 每间隔 191 个blockNumber 拉取一个header)
	//
	// 因此循环中的 index 变量实际上是每一组区块中的第一个区块的高度（比如 10、20、30），
	// todo 而我们刚才提到过 skeleton 参数中的区块头是每一组区块中的最后一个区块，
	// todo 因此 queue.headerTaskPool 实际上是一个每一组区块中第一个区块的高度到最后一个区块的 header 的映射
	//
	for i, header := range skeleton {
		index := from + uint64(i*MaxHeaderFetch)

		q.headerTaskPool[index] = header
		q.headerTaskQueue.Push(index, -float32(index))
	}
}

// RetrieveHeaders retrieves the header chain assemble based on the scheduled
// skeleton.
//
//
//  在对 skeleton 进行填充 `downloader.fillHeaderSkeleton()` 完成后，
// 	queue.RetrieveHeaders() 用来获取整个 skeleton 中的所有 header (全部的headers)
func (q *queue) RetrieveHeaders() ([]*types.Header, int) {
	q.lock.Lock()
	defer q.lock.Unlock()

	// 返回: 结果缓存累积完成的 header  和 已被处理的 header 数量
	headers, proced := q.headerResults, q.headerProced

	// 返回之后， 清空缓存
	q.headerResults, q.headerProced = nil, 0

	return headers, proced
}




// Schedule adds a set of headers for the download queue for scheduling, returning
// the new headers encountered.
//
// 用来准备对一些 body 和 receipt 数据的下载.
//
//
//     todo  只在 Downloader.processHeaders() 中处理下载成功的 header 时，使用这些 header 调用 queue.Schedule() 方法，
// 			以便 queue 对象可以开始对这些 header 对应的 body 和 receipt 开始下载调度.
//
func (q *queue) Schedule(headers []*types.Header, from uint64) []*types.Header {  // todo  抓取 headers 对应的 body 和 receipts
	q.lock.Lock()
	defer q.lock.Unlock()

	// Insert all the headers prioritised by the contained block number
	inserts := make([]*types.Header, 0, len(headers))
	for _, header := range headers {

		// 一些有效性判断

		// Make sure chain order is honoured and preserved throughout
		hash := header.Hash()
		if header.Number == nil || header.Number.Uint64() != from {
			log.Warn("Header broke chain ordering", "number", header.Number, "hash", hash, "expected", from)
			break
		}
		if q.headerHead != (common.Hash{}) && q.headerHead != header.ParentHash {
			log.Warn("Header broke chain ancestry", "number", header.Number, "hash", hash)
			break
		}
		// Make sure no duplicate requests are executed
		if _, ok := q.blockTaskPool[hash]; ok {
			log.Warn("Header  already scheduled for block fetch", "number", header.Number, "hash", hash)
			continue
		}
		if _, ok := q.receiptTaskPool[hash]; ok {
			log.Warn("Header already scheduled for receipt fetch", "number", header.Number, "hash", hash)
			continue
		}
		// Queue the header for content retrieval
		//
		// 将信息写入 body 和 receipt 队列
		q.blockTaskPool[hash] = header
		q.blockTaskQueue.Push(header, -float32(header.Number.Uint64()))

		if q.mode == FastSync {
			q.receiptTaskPool[hash] = header
			q.receiptTaskQueue.Push(header, -float32(header.Number.Uint64()))
		}
		inserts = append(inserts, header)
		q.headerHead = hash
		from++
	}
	return inserts
}

// Results retrieves and permanently removes a batch of fetch results from
// the cache. the result slice will be empty if the queue has been closed.
//
// 用来获取当前的 headers、bodies 和 receipts（只在 fast 模式下） 都已下载成功的 block（并将这些 block 从 queue 内部移除）
//
//  todo 那么当一个区块的数据 (header、body 和 receipt) 都下载完成时，Downloader 对象就要获取这些区块并将其写入数据库了.
//  todo queue.Results() 就是用来返回所有目前已经下载完成的数据，它在 Downloader.processFullSyncContent 和 Downloader.processFastSyncContent 中被调用
//
func (q *queue) Results(block bool) []*fetchResult {
	q.lock.Lock()
	defer q.lock.Unlock()

	// Count the number of items available for processing
	//
	// countProcessableItems() 返回 queue.resultCache 中已经下载完成的数据的数量
	nproc := q.countProcessableItems()

	// 如果没有了需要处理的条目 且 queue 已经关闭
	for nproc == 0 && !q.closed {

		// block: 是否直接结束标识
		if !block {
			return nil
		}
		// 首先获取已经完全下载完成的数据的数量，如果为 0，则根据  block参数 的指示来决定是否进行等待.
		//
		// 如果 block参数 为 true 就会等待 queue.active 这个信号（还记得我们前面我们几次提过 queue.active 消息，说它可能在 queue.Results 中被等待吗）
		q.active.Wait()

		// 再次 尝试获取 需要处理的条目
		// (因为退出时,需要将没处理完的处理掉,那么可能这时候 缓存中需要被处理的items突然又有了)
		nproc = q.countProcessableItems()
	}

	// todo 在有数据的情况下，会将这些数据拷贝到待返回的 results 中 .

	// Since we have a batch limit, don't pull more into "dangling" memory
	//
	// 由于我们有批次限制，所以不要将更多信息放入“悬挂”的内存中
	// 每次处理的 条目数不能 大于 一次导入到链中的内容(txs, receipts)下载结果数
	if nproc > maxResultsProcess {
		nproc = maxResultsProcess
	}
	results := make([]*fetchResult, nproc)
	// 从缓存中copy出一部分条目进行处理
	copy(results, q.resultCache[:nproc])
	if len(results) > 0 {
		// Mark results as done before dropping them from the cache.
		//
		// 将结果标记为已完成，然后将其从缓存中删除
		// (先清除 已完成的去重集中的 hash)
		for _, result := range results {
			hash := result.Header.Hash()
			delete(q.blockDonePool, hash)
			delete(q.receiptDonePool, hash)
		}
		// Delete the results from the cache and clear the tail.
		//
		// 将已经拷贝到 results 中的数据从 resultCache 中清除，同时修正 resultOffset 的值
		copy(q.resultCache, q.resultCache[nproc:])
		// todo 这个for 我是真的看不懂啊
		for i := len(q.resultCache) - nproc; i < len(q.resultCache); i++ {
			q.resultCache[i] = nil
		}
		// Advance the expected block number of the first cache entry.
		//
		// 提前第一个缓存条目的预期块号
		q.resultOffset += uint64(nproc)

		// Recalculate the result item weights to prevent memory exhaustion
		//
		// 重新计算结果项的权重，以防止内存耗尽
		// 累加一个 result的大小
		for _, result := range results {
			size := result.Header.Size()
			for _, uncle := range result.Uncles {
				size += uncle.Size()
			}
			for _, receipt := range result.Receipts {
				size += receipt.Size()
			}
			for _, tx := range result.Transactions {
				size += tx.Size()
			}

			// sumSize = size*0.1 + (1-0.1) * sumSize  这公式是怎么的出来的啊!? 我叼啊~
			q.resultSize = common.StorageSize(blockCacheSizeWeight)*size + (1-common.StorageSize(blockCacheSizeWeight))*q.resultSize
		}
	}
	return results
}

// countProcessableItems counts the processable items.
//
// 返回 queue.resultCache 中已经下载完成的数据的数量
func (q *queue) countProcessableItems() int {

	// 遍历 缓存中的 已经被下载但尚未被处理的 req
	for i, result := range q.resultCache {

		// 这里的处理  很奇葩啊,我叼, result == nil 时,直接返回 for index (有问题)
		// 或者 当有 result 是pending的时候<仍待处理的数据提取数量>, 返回Pending中的数目? (有问题)
		if result == nil || result.Pending > 0 {
			return i
		}
	}

	// 返回违背处理的 所有 req数目
	return len(q.resultCache)
}

// ReserveHeaders reserves a set of headers for the given peer, skipping any
// previously failed batches.
//
// 这个方法只有在填充 skeleton 时 (即: downloader.fillHeaderSkeleton()中) 才会被用到，
// 		它的功能就是从 task 队列中选一个值最小的、且 指定对端 peer 没有失败过的 起始高度 height，构造一个 fetchRequest 结构并返回.
//
func (q *queue) ReserveHeaders(p *peerConnection, count int) *fetchRequest {
	q.lock.Lock()
	defer q.lock.Unlock()

	// Short circuit if the peer's already downloading something (sanity check to
	// not corrupt state)
	if _, ok := q.headerPendPool[p.id]; ok {   // 对端 peer 正在做 header 下载动作, 则 不处理了
		return nil
	}


	// Retrieve a batch of hashes, skipping previously failed ones
	//
	// 从 task queue 中选择本次请求的起始高度（跳过已经失败了的）
	send, skip := uint64(0), []uint64{}
	for send == 0 && !q.headerTaskQueue.Empty() {
		from, _ := q.headerTaskQueue.Pop()
		if q.headerPeerMiss[p.id] != nil {
			if _, ok := q.headerPeerMiss[p.id][from.(uint64)]; ok {
				skip = append(skip, from.(uint64))
				continue
			}
		}
		send = from.(uint64)
	}

	// Merge all the skipped batches back
	//
	// 将跳过的（失败的）任务重新写回 task queue
	for _, from := range skip {
		q.headerTaskQueue.Push(from, -float32(from))
	}
	// Assemble and return the block download request
	if send == 0 {
		return nil
	}

	// 新构造的 request 和 节点 id 写入 headerPendPool 中
	request := &fetchRequest{
		Peer: p,
		From: send,
		Time: time.Now(),
	}
	q.headerPendPool[p.id] = request
	return request
}


//
// - - - - - - -  - - - - -  reserve (预约) 系列方法 - - - - - - - - - -  - - - - -
//
// 通过构造一个 fetchRequest 结构并返回，向 调用者 提供 指定数量 的待下载的数据的信息（queue 内部会将这些数据标记为「正在下载」）.
//
// 调用者  使用返回的 fetchRequest 数据 向 对端peer  发起新的获取数据的 req
//



// ReserveBodies reserves a set of body fetches for the given peer, skipping any
// previously failed downloads. Beside the next batch of needed fetches, it also
// returns a flag whether empty blocks were queued requiring processing.
func (q *queue) ReserveBodies(p *peerConnection, count int) (*fetchRequest, bool, error) {
	isNoop := func(header *types.Header) bool {
		return header.TxHash == types.EmptyRootHash && header.UncleHash == types.EmptyUncleHash
	}
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.reserveHeaders(p, count, q.blockTaskPool, q.blockTaskQueue, q.blockPendPool, q.blockDonePool, isNoop)
}

// ReserveReceipts reserves a set of receipt fetches for the given peer, skipping
// any previously failed downloads. Beside the next batch of needed fetches, it
// also returns a flag whether empty receipts were queued requiring importing.
func (q *queue) ReserveReceipts(p *peerConnection, count int) (*fetchRequest, bool, error) {
	isNoop := func(header *types.Header) bool {
		return header.ReceiptHash == types.EmptyRootHash
	}
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.reserveHeaders(p, count, q.receiptTaskPool, q.receiptTaskQueue, q.receiptPendPool, q.receiptDonePool, isNoop)
}

// reserveHeaders reserves a set of data download operations for a given peer,
// skipping any previously failed ones. This method is a generic version used
// by the individual special reservation functions.
//
// Note, this method expects the queue lock to be already held for writing. The
// reason the lock is not obtained in here is because the parameters already need
// to access the queue, so they already need a lock anyway.
func (q *queue) reserveHeaders(p *peerConnection, count int, taskPool map[common.Hash]*types.Header, taskQueue *prque.Prque,
	pendPool map[string]*fetchRequest, donePool map[common.Hash]struct{}, isNoop func(*types.Header) bool) (*fetchRequest, bool, error) {
	// Short circuit if the pool has been depleted, or if the peer's already
	// downloading something (sanity check not to corrupt state)
	if taskQueue.Empty() {
		return nil, false, nil
	}
	if _, ok := pendPool[p.id]; ok {
		return nil, false, nil
	}
	// Calculate an upper limit on the items we might fetch (i.e. throttling)
	space := q.resultSlots(pendPool, donePool)

	// Retrieve a batch of tasks, skipping previously failed ones
	send := make([]*types.Header, 0, count)
	skip := make([]*types.Header, 0)

	progress := false
	for proc := 0; proc < space && len(send) < count && !taskQueue.Empty(); proc++ {
		header := taskQueue.PopItem().(*types.Header)
		hash := header.Hash()

		// If we're the first to request this task, initialise the result container
		index := int(header.Number.Int64() - int64(q.resultOffset))
		if index >= len(q.resultCache) || index < 0 {
			common.Report("index allocation went beyond available resultCache space")
			return nil, false, errInvalidChain
		}
		if q.resultCache[index] == nil {
			components := 1
			if q.mode == FastSync {
				components = 2
			}
			q.resultCache[index] = &fetchResult{
				Pending: components,
				Hash:    hash,
				Header:  header,
			}
		}
		// If this fetch task is a noop, skip this fetch operation
		if isNoop(header) {
			donePool[hash] = struct{}{}
			delete(taskPool, hash)

			space, proc = space-1, proc-1
			q.resultCache[index].Pending--
			progress = true
			continue
		}
		// Otherwise unless the peer is known not to have the data, add to the retrieve list
		if p.Lacks(hash) {
			skip = append(skip, header)
		} else {
			send = append(send, header)
		}
	}
	// Merge all the skipped headers back
	for _, header := range skip {
		taskQueue.Push(header, -float32(header.Number.Uint64()))
	}
	if progress {
		// Wake WaitResults, resultCache was modified
		q.active.Signal()
	}
	// Assemble and return the block download request
	if len(send) == 0 {
		return nil, progress, nil
	}
	request := &fetchRequest{
		Peer:    p,
		Headers: send,
		Time:    time.Now(),
	}
	pendPool[p.id] = request

	return request, progress, nil
}





//
// - - - - - - - - - -  - Cancel 系列方法  - - - - - - - - - - -  --
//
// 与 reserve 相反，用来撤消对 fetchRequest 结构中的数据的下载（queue 内部会将 这些数据重新从「正在下载」的状态更改为「等待下载」）
//

// CancelHeaders aborts a fetch request, returning all pending skeleton indexes to the queue.
func (q *queue) CancelHeaders(request *fetchRequest) {
	q.cancel(request, q.headerTaskQueue, q.headerPendPool)
}

// CancelBodies aborts a body fetch request, returning all pending headers to the
// task queue.
func (q *queue) CancelBodies(request *fetchRequest) {
	q.cancel(request, q.blockTaskQueue, q.blockPendPool)
}

// CancelReceipts aborts a body fetch request, returning all pending headers to
// the task queue.
func (q *queue) CancelReceipts(request *fetchRequest) {
	q.cancel(request, q.receiptTaskQueue, q.receiptPendPool)
}

// Cancel aborts a fetch request, returning all pending hashes to the task queue.
func (q *queue) cancel(request *fetchRequest, taskQueue *prque.Prque, pendPool map[string]*fetchRequest) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if request.From > 0 {
		taskQueue.Push(request.From, -float32(request.From))
	}
	for _, header := range request.Headers {
		taskQueue.Push(header, -float32(header.Number.Uint64()))
	}
	delete(pendPool, request.Peer.id)
}








// Revoke cancels all pending requests belonging to a given peer. This method is
// meant to be called during a peer drop to quickly reassign owned data fetches
// to remaining nodes.
func (q *queue) Revoke(peerID string) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if request, ok := q.blockPendPool[peerID]; ok {
		for _, header := range request.Headers {
			q.blockTaskQueue.Push(header, -float32(header.Number.Uint64()))
		}
		delete(q.blockPendPool, peerID)
	}
	if request, ok := q.receiptPendPool[peerID]; ok {
		for _, header := range request.Headers {
			q.receiptTaskQueue.Push(header, -float32(header.Number.Uint64()))
		}
		delete(q.receiptPendPool, peerID)
	}
}





//
// - - - - - - - - - - - - -  Expire 系列方法 - - - - - - - -  - - - -
//
// 通过在 参数中指定一个时间段，expire 用来告诉  调用者  下载时间已经超过指定时间的   (对端peer的 nodeId -> 超时的数据条数) pair
//



// ExpireHeaders checks for in flight requests that exceeded a timeout allowance,
// canceling them and returning the responsible peers for penalisation.
func (q *queue) ExpireHeaders(timeout time.Duration) map[string]int {
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.expire(timeout, q.headerPendPool, q.headerTaskQueue, headerTimeoutMeter)
}

// ExpireBodies checks for in flight block body requests that exceeded a timeout
// allowance, canceling them and returning the responsible peers for penalisation.
func (q *queue) ExpireBodies(timeout time.Duration) map[string]int {
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.expire(timeout, q.blockPendPool, q.blockTaskQueue, bodyTimeoutMeter)
}

// ExpireReceipts checks for in flight receipt requests that exceeded a timeout
// allowance, canceling them and returning the responsible peers for penalisation.
func (q *queue) ExpireReceipts(timeout time.Duration) map[string]int {
	q.lock.Lock()
	defer q.lock.Unlock()

	return q.expire(timeout, q.receiptPendPool, q.receiptTaskQueue, receiptTimeoutMeter)
}

// expire is the generic check that move expired tasks from a pending pool back
// into a task pool, returning all entities caught with expired tasks.
//
// Note, this method expects the queue lock to be already held. The
// reason the lock is not obtained in here is because the parameters already need
// to access the queue, so they already need a lock anyway.
func (q *queue) expire(timeout time.Duration, pendPool map[string]*fetchRequest, taskQueue *prque.Prque, timeoutMeter metrics.Meter) map[string]int {
	// Iterate over the expired requests and return each to the queue
	expiries := make(map[string]int)
	for id, request := range pendPool {
		if time.Since(request.Time) > timeout {
			// Update the metrics with the timeout
			timeoutMeter.Mark(1)

			// Return any non satisfied requests to the pool
			if request.From > 0 {
				taskQueue.Push(request.From, -float32(request.From))
			}
			for _, header := range request.Headers {
				taskQueue.Push(header, -float32(header.Number.Uint64()))
			}
			// Add the peer to the expiry report along the the number of failed requests
			expiries[id] = len(request.Headers)
		}
	}
	// Remove the expired requests from the pending pool
	for id := range expiries {
		delete(pendPool, id)
	}
	return expiries
}






//
// - - - - - - - - -  - - -  Deliver 系列方法 - - - - - - - - - - - - -
//
// 当有数据下载成功时，调用者会使用 deliver 功能用来通知 queue 对象.
//
// 主要给 ProtocolManager 使用,  传递 从对端 peer 下载的  headers、bodies、 receipts 三者 给 downloader处理 ...
//
//


// DeliverHeaders injects a header retrieval response into the header results
// cache. This method either accepts all headers it received, or none of them
// if they do not map correctly to the skeleton.
//
// If the headers are accepted, the method makes an attempt to deliver the set
// of ready headers to the processor to keep the pipeline full. However it will
// not block to prevent stalling other pending deliveries.
//
// deliver	英[dɪˈlɪvə(r)]  传送; 交付
//
//
// 只在 downloader.fillHeaderSkeleton() 中使用.
//
//
//
func (q *queue) DeliverHeaders(id string, headers []*types.Header, headerProcCh chan []*types.Header) (int, error) {


	//
	// 主要就是保存数据，以及通知 headerProcCh 有新的 header 可以处理了.
	//
	// 总体来说， queue.DeliverHeaders() 用来处理  [下载成功]  的 header 数据，
	// 		它会对数据进行检验和保存，并发送 channel 消息给 Downloader.processHeaders() 和 Downloader.fetchParts() 的 wakeCh 参数.

	q.lock.Lock()
	defer q.lock.Unlock()

	// Short circuit if the data was never requested
	request := q.headerPendPool[id]
	if request == nil {
		return 0, errNoFetchesPending
	}
	headerReqTimer.UpdateSince(request.Time)
	delete(q.headerPendPool, id)

	// Ensure headers can be mapped onto the skeleton chain
	target := q.headerTaskPool[request.From].Hash()

	accepted := len(headers) == MaxHeaderFetch
	if accepted {

		// 检查起始区块的高度 和 哈希
		if headers[0].Number.Uint64() != request.From {
			log.Trace("First header broke chain ordering", "peer", id, "number", headers[0].Number, "hash", headers[0].Hash(), request.From)
			accepted = false
		} else if headers[len(headers)-1].Hash() != target {
			log.Trace("Last header broke skeleton structure ", "peer", id, "number", headers[len(headers)-1].Number, "hash", headers[len(headers)-1].Hash(), "expected", target)
			accepted = false
		}
	}
	if accepted {
		for i, header := range headers[1:] {
			hash := header.Hash()

			// 检查高度的连接性
			if want := request.From + 1 + uint64(i); header.Number.Uint64() != want {
				log.Warn("Header broke chain ordering", "peer", id, "number", header.Number, "hash", hash, "expected", want)
				accepted = false
				break
			}
			// 检查哈希的连接性
			if headers[i].Hash() != header.ParentHash {
				log.Warn("Header broke chain ancestry", "peer", id, "number", header.Number, "hash", hash)
				accepted = false
				break
			}
		}
	}
	// If the batch of headers wasn't accepted, mark as unavailable
	if !accepted {
		log.Trace("Skeleton filling not accepted", "peer", id, "from", request.From)

		miss := q.headerPeerMiss[id]
		if miss == nil {
			q.headerPeerMiss[id] = make(map[uint64]struct{})
			miss = q.headerPeerMiss[id]
		}
		miss[request.From] = struct{}{}

		q.headerTaskQueue.Push(request.From, -float32(request.From))
		return 0, errors.New("delivery not accepted")
	}
	// Clean up a successful fetch and try to deliver any sub-results
	copy(q.headerResults[request.From-q.headerOffset:], headers)
	delete(q.headerTaskPool, request.From)

	ready := 0
	for q.headerProced+ready < len(q.headerResults) && q.headerResults[q.headerProced+ready] != nil {
		ready += MaxHeaderFetch
	}
	if ready > 0 {
		// Headers are ready for delivery, gather them and push forward (non blocking)
		process := make([]*types.Header, ready)
		copy(process, q.headerResults[q.headerProced:q.headerProced+ready])

		select {
		case headerProcCh <- process:   // todo 在 queue.DeliverHeaders() 中传递 一批 headers， downloader.processHeaders() 中有用
			log.Trace("Pre-scheduled new headers", "peer", id, "count", len(process), "from", process[0].Number)
			q.headerProced += len(process)
		default:
		}
	}
	// Check for termination and return
	//
	// 如果 queue.headerTaskPool 为空，说明 skeleton 中所有组都被下载完了，因此发送消息给 queue.headerContCh.
	//
	// 这个 channel 在 Downloader.fillHeaderSkeleton 中是作为 wakeCh 传给 Downloader.fetchParts() 的，用来通知 header 数据已经下载完成了.
	//
	if len(q.headerTaskPool) == 0 {
		q.headerContCh <- false
	}
	return len(headers), nil
}

// DeliverBodies injects a block body retrieval response into the results queue.
// The method returns the number of blocks bodies accepted from the delivery and
// also wakes any threads waiting for data delivery.
func (q *queue) DeliverBodies(id string, txLists [][]*types.Transaction, uncleLists [][]*types.Header) (int, error) {
	q.lock.Lock()
	defer q.lock.Unlock()

	reconstruct := func(header *types.Header, index int, result *fetchResult) error {
		if types.DeriveSha(types.Transactions(txLists[index])) != header.TxHash || types.CalcUncleHash(uncleLists[index]) != header.UncleHash {
			return errInvalidBody
		}
		result.Transactions = txLists[index]
		result.Uncles = uncleLists[index]
		return nil
	}
	return q.deliver(id, q.blockTaskPool, q.blockTaskQueue, q.blockPendPool, q.blockDonePool, bodyReqTimer, len(txLists), reconstruct)
}

// DeliverReceipts injects a receipt retrieval response into the results queue.
// The method returns the number of transaction receipts accepted from the delivery
// and also wakes any threads waiting for data delivery.
func (q *queue) DeliverReceipts(id string, receiptList [][]*types.Receipt) (int, error) {
	q.lock.Lock()
	defer q.lock.Unlock()

	reconstruct := func(header *types.Header, index int, result *fetchResult) error {
		if types.DeriveSha(types.Receipts(receiptList[index])) != header.ReceiptHash {
			return errInvalidReceipt
		}
		result.Receipts = receiptList[index]
		return nil
	}
	return q.deliver(id, q.receiptTaskPool, q.receiptTaskQueue, q.receiptPendPool, q.receiptDonePool, receiptReqTimer, len(receiptList), reconstruct)
}

// deliver injects a data retrieval response into the results queue.
//
// Note, this method expects the queue lock to be already held for writing. The
// reason the lock is not obtained in here is because the parameters already need
// to access the queue, so they already need a lock anyway.
func (q *queue) deliver(id string, taskPool map[common.Hash]*types.Header, taskQueue *prque.Prque,
	pendPool map[string]*fetchRequest, donePool map[common.Hash]struct{}, reqTimer metrics.Timer,
	results int, reconstruct func(header *types.Header, index int, result *fetchResult) error) (int, error) {

	// Short circuit if the data was never requested
	request := pendPool[id]
	if request == nil {
		return 0, errNoFetchesPending
	}
	reqTimer.UpdateSince(request.Time)
	delete(pendPool, id)

	// If no data items were retrieved, mark them as unavailable for the origin peer
	if results == 0 {
		for _, header := range request.Headers {
			request.Peer.MarkLacking(header.Hash())
		}
	}
	// Assemble each of the results with their headers and retrieved data parts
	var (
		accepted int
		failure  error
		useful   bool
	)
	for i, header := range request.Headers {
		// Short circuit assembly if no more fetch results are found
		if i >= results {
			break
		}
		// Reconstruct the next result if contents match up
		index := int(header.Number.Int64() - int64(q.resultOffset))
		if index >= len(q.resultCache) || index < 0 || q.resultCache[index] == nil {
			failure = errInvalidChain
			break
		}
		if err := reconstruct(header, i, q.resultCache[index]); err != nil {
			failure = err
			break
		}
		hash := header.Hash()

		donePool[hash] = struct{}{}
		q.resultCache[index].Pending--
		useful = true
		accepted++

		// Clean up a successful fetch
		request.Headers[i] = nil
		delete(taskPool, hash)
	}
	// Return all failed or missing fetches to the queue
	for _, header := range request.Headers {
		if header != nil {
			taskQueue.Push(header, -float32(header.Number.Uint64()))
		}
	}
	// Wake up WaitResults
	if accepted > 0 {
		q.active.Signal()
	}
	// If none of the data was good, it's a stale delivery
	switch {
	case failure == nil || failure == errInvalidChain:
		return accepted, failure
	case useful:
		return accepted, fmt.Errorf("partial failure: %v", failure)
	default:
		return accepted, errStaleDelivery
	}
}

// Prepare configures the result cache to allow accepting and caching inbound
// fetch results.
//
//`Prepare()`  配置  结果缓存 以允许 接受 和缓存 入站 同步结果
//
// 				下载开始之前，告诉 queue 对象将要下载的一系列区块的起始高度 和 下载模式（fast 或 full 模式）
//
func (q *queue) Prepare(offset uint64, mode SyncMode) {
	q.lock.Lock()
	defer q.lock.Unlock()

	// Prepare the queue for sync results    准备队列以获取同步结果
	if q.resultOffset < offset {
		q.resultOffset = offset
	}
	q.mode = mode
}
