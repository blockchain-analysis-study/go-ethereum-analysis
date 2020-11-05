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

// Package fetcher contains the block announcement based synchronisation.
package fetcher

import (
	"errors"
	"math/rand"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/consensus"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/log"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

const (
	arriveTimeout = 500 * time.Millisecond // Time allowance before an announced block is explicitly requested
	gatherSlack   = 100 * time.Millisecond // Interval used to collate almost-expired announces with fetches
	fetchTimeout  = 5 * time.Second        // Maximum allotted time to return an explicitly requested block
	maxUncleDist  = 7                      // Maximum allowed backward distance from the chain head   而如果这个区块不在主链上，即它是可能是某个区块的 uncle 区块，那么高度差超过 7
	maxQueueDist  = 32                     // Maximum allowed distance from the chain head to queue
	hashLimit     = 256                    // Maximum number of unique blocks a peer may have announced
	blockLimit    = 64                     // Maximum number of unique blocks a peer may have delivered
)

var (
	errTerminated = errors.New("terminated")
)

// blockRetrievalFn is a callback type for retrieving a block from the local chain.
type blockRetrievalFn func(common.Hash) *types.Block

// headerRequesterFn is a callback type for sending a header retrieval request.
type headerRequesterFn func(common.Hash) error

// bodyRequesterFn is a callback type for sending a body retrieval request.
type bodyRequesterFn func([]common.Hash) error

// headerVerifierFn is a callback type to verify a block's header for fast propagation.
type headerVerifierFn func(header *types.Header) error

// blockBroadcasterFn is a callback type for broadcasting a block to connected peers.
type blockBroadcasterFn func(block *types.Block, propagate bool)

// chainHeightFn is a callback type to retrieve the current chain height.
type chainHeightFn func() uint64

// chainInsertFn is a callback type to insert a batch of blocks into the local chain.
type chainInsertFn func(types.Blocks) (int, error)

// peerDropFn is a callback type for dropping a peer detected as malicious.
type peerDropFn func(id string)

// announce is the hash notification of the availability of a new block in the
// network.
//
//  用来往对端 peer 发起 block 抓取的 抓取通知信息
type announce struct {
	// blockHash
	hash   common.Hash   // Hash of the block being announced
	// blockNumber
	number uint64        // Number of the block being announced (0 = unknown | old protocol)
	// 部分重新组装的 block header（新协议）  <当 下载header 完成后, 用来回填的>
	header *types.Header // Header of the block partially reassembled (new protocol)
	// 通知的 时间戳  (会被各个阶段的 task.time 更新掉)
	time   time.Time     // Timestamp of the announcement

	origin string // Identifier of the peer originating the notification   (其实是 目标 peer 的 NodeId)

	fetchHeader headerRequesterFn // Fetcher function to retrieve the header of an announced block		 是 `p.RequestOneHeader()` 向对端 peer 发起 `GetBlockHeadersMsg` 消息
	fetchBodies bodyRequesterFn   // Fetcher function to retrieve the body of an announced block		 是 `p.RequestBodies()` 向对端 peer 发起  `GetBlockBodiesMsg` 消息
}

// headerFilterTask represents a batch of headers needing fetcher filtering.
type headerFilterTask struct {
	peer    string          // The source peer of block headers
	headers []*types.Header // Collection of headers to filter
	time    time.Time       // Arrival time of the headers
}

// bodyFilterTask represents a batch of block bodies (transactions and uncles)
// needing fetcher filtering.
type bodyFilterTask struct {
	peer         string                 // The source peer of block bodies
	transactions [][]*types.Transaction // Collection of transactions per block bodies
	uncles       [][]*types.Header      // Collection of uncles per block bodies
	time         time.Time              // Arrival time of the blocks' contents
}

// inject represents a schedules import operation.
//
// 用来将 接收到对端peer 的 block 插入到 当前本地 node 的chain 的 插入通知信息
type inject struct {
	origin string
	block  *types.Block
}

//  fetcher 模块和 downloader 模块所承担的任务是不同的.
// 			downloader 功能比较重，用来保证自己的 chain 和其它节点之间不会有太多差距
// 			fetcher 功能较轻，只会对 miner 新产生的 block 进行同步和广播
//
// Fetcher is responsible for accumulating block announcements from various peers
// and scheduling them for retrieval.
//
// Fetcher负责 累积来自 各个 对端 peer 的 block公告，并安排它们以进行处理.
//
// Fetcher 模块的功能:
// 				就是收集其他Peer通知它的区块信息：
// 				1）完整的 block
// 				2）区块Hash消息
// 		根据通知的消息，获取完整的区块，然后传递给eth模块把区块插入区块链.
//
// todo 即 Fecther 是专门处理 对端 peer  的 (pm *ProtocolManager) minedBroadcastLoop() 方法中 广播过来的完整 block 或者 blockHash
//
//     	如果是完整 block，就可以传递给eth插入区块
// 		如果只有 blockHash，则需要从其他的Peer获取此完整的区块，然后再传递给eth插入区块
//
type Fetcher struct {
	// Various event channels
	notify chan *announce  		// 用来向 目标对端 peer 抓取 某个 block 的 抓取通知信息 的通道
	inject chan *inject			// 用来将 接收到对端peer 的 block 插入到 当前本地 node 的chain 的 插入通知信息 的通道


	// 双 chan 实现到 通信双方 有来有回 ： req - resp 形式
	blockFilter  chan chan []*types.Block
	headerFilter chan chan *headerFilterTask
	bodyFilter   chan chan *bodyFilterTask

	done chan common.Hash    // 用来 接收 某个 blockHash 的 block 已经完成插入到 本地 chain的信号
	quit chan struct{}

	// Announce states  通知状态
	//
	// 每个 peer 对外发布  block 的计数以防止内存耗尽    map(nodeId  -> 计数器)
	announces  map[string]int              // Per peer announce counts to prevent memory exhaustion

	// 此阶段代表有节点宣称自己有了新产生的区块 (注意这个新产生的区块不一定是自己产生的，也可能是同步了其它节点新产生的区块),
	// Fetcher 对象将相关信息放到 Fetcher.announced 中
	//
	// 此阶段表示 等待下载.    todo 这里为什么是 切片, 因为 annonce 中有 对应 blockHash 的 对端peer的 nodeId  (这里是该 blockHash 的不同 对端peer 的抓取 通知信息)
	announced  map[common.Hash][]*announce // Announced blocks, scheduled for fetching

	// 此阶段代表之前「宣告」的 block 正在被下载  (blockHash => block的抓取通知)
	fetching   map[common.Hash]*announce   // Announced blocks, currently fetching

	// 此阶段代表区块的 header 已下载成功，现在等待下载 body
	fetched    map[common.Hash][]*announce // Blocks with headers fetched, scheduled for body retrieval

	// 此阶段代表 body 已经发起了下载，正在等待 body 下载成功   (blockHash => block的抓取通知)
	completing map[common.Hash]*announce   // Blocks with headers, currently body-completing

	// Block cache   <用于 准备 插入到本地 chain 的block (对端 peer 广播过来的 block)>
	//
	// 即将被插入到本地 chain 的 block 优先级队列 <由对端 peer 广播过来的 block>
	queue  *prque.Prque            // Queue containing the import operations (block number sorted)

	// 每个 peer 计数以防止内存耗尽     (nodeId => 计数器)
	queues map[string]int          // Per peer block counts to prevent memory exhaustion

	// 已经被插入到本地chain的 远端 block (用于放置重复插入本地 chain)    (blockHash => 该block的inject通知)
	queued map[common.Hash]*inject // Set of already queued blocks (to dedupe imports)

	// Callbacks
	//
	// 一些用于回调的 工具函数指针
	getBlock       blockRetrievalFn   // Retrieves a block from the local chain						 是 `blockchain.GetBlockByHash()`
	verifyHeader   headerVerifierFn   // Checks if a block's headers have a valid proof of work		 最终是 `engine.VerifyHeader()`
	broadcastBlock blockBroadcasterFn // Broadcasts a block to connected peers						 是 `manager.BroadcastBlock()`
	chainHeight    chainHeightFn      // Retrieves the current chain's height						 最终是 `blockchain.CurrentBlock().NumberU64()`
	insertChain    chainInsertFn      // Injects a batch of blocks into the chain					 最终是 `blockchain.InsertChain()`

	// 将该对端peer 从本地 ProtocolManager.peerSet 和 Downloader.peerSet 中移除   `ProtocolManager.removePeer()` 函数指针
	dropPeer       peerDropFn         // Drops a peer for misbehaving

	// Testing hooks
	announceChangeHook func(common.Hash, bool) // Method to call upon adding or deleting a hash from the announce list
	queueChangeHook    func(common.Hash, bool) // Method to call upon adding or deleting a block from the import queue
	fetchingHook       func([]common.Hash)     // Method to call upon starting a block (eth/61) or header (eth/62) fetch
	completingHook     func([]common.Hash)     // Method to call upon starting a block body fetch (eth/62)
	importedHook       func(*types.Block)      // Method to call upon successful block import (both eth/61 and eth/62)
}

// New creates a block fetcher to retrieve blocks based on hash announcements.
//
// 只有一个地方调用:
//
//   eth\handler.go 的 NewProtocolManager()  <可以知道 fecther 只针对 全节点的 full  和 fast 模式>
//
func New(getBlock blockRetrievalFn, verifyHeader headerVerifierFn, broadcastBlock blockBroadcasterFn, chainHeight chainHeightFn, insertChain chainInsertFn, dropPeer peerDropFn) *Fetcher {
	return &Fetcher{
		notify:         make(chan *announce),
		inject:         make(chan *inject),
		blockFilter:    make(chan chan []*types.Block),
		headerFilter:   make(chan chan *headerFilterTask),
		bodyFilter:     make(chan chan *bodyFilterTask),
		done:           make(chan common.Hash),
		quit:           make(chan struct{}),
		announces:      make(map[string]int),
		announced:      make(map[common.Hash][]*announce),
		fetching:       make(map[common.Hash]*announce),
		fetched:        make(map[common.Hash][]*announce),
		completing:     make(map[common.Hash]*announce),
		queue:          prque.New(),
		queues:         make(map[string]int),
		queued:         make(map[common.Hash]*inject),

		// 这几个都是 函数指针
		getBlock:       getBlock,			// 是 `blockchain.GetBlockByHash()`
		verifyHeader:   verifyHeader,		// 最终是 `engine.VerifyHeader()`
		broadcastBlock: broadcastBlock,		// 是 `manager.BroadcastBlock()`
		chainHeight:    chainHeight,		// 最终是 `blockchain.CurrentBlock().NumberU64()`
		insertChain:    insertChain,  		// 最终是 `blockchain.InsertChain()`
		dropPeer:       dropPeer,			// 是 `manager.removePeer()`
	}
}

// Start boots up the announcement based synchroniser, accepting and processing
// hash notifications and block fetches until termination requested.
func (f *Fetcher) Start() {
	go f.loop()
}

// Stop terminates the announcement based synchroniser, canceling all pending
// operations.
func (f *Fetcher) Stop() {
	close(f.quit)
}

// Notify announces the fetcher of the potential availability of a new block in
// the network.
//
// 根据 blockHash 发起 (往对端 peer 抓取目标 block 的通知信息)
//
// 在 ProtocolManager.handleMsg() 的  `case msg.Code == NewBlockMsg` 中被调用
func (f *Fetcher) Notify(peer string, hash common.Hash, number uint64, time time.Time,
	headerFetcher headerRequesterFn, bodyFetcher bodyRequesterFn) error {

	// 封装一个 往对端peer抓取block的通知
	block := &announce{
		hash:        hash,
		number:      number,
		time:        time,
		origin:      peer,  			// 这个其实是 对端peer 的 NodeId
		fetchHeader: headerFetcher,		// 是 `p.RequestOneHeader()` 向对端 peer 发起 `GetBlockHeadersMsg` 消息
		fetchBodies: bodyFetcher,		// 是 `p.RequestBodies()` 向对端 peer 发起  `GetBlockBodiesMsg` 消息
	}

	select {
	case f.notify <- block:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// Enqueue tries to fill gaps the the fetcher's future import queue.
//
// 用来对 对端peer  发来的 block 做本地chain插入准备
//
// 在 ProtocolManager.handleMsg() 的  `case msg.Code == NewBlockMsg` 中被调用
func (f *Fetcher) Enqueue(peer string, block *types.Block) error {
	op := &inject{
		origin: peer,
		block:  block,
	}
	select {
	case f.inject <- op:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// FilterHeaders extracts all the headers that were explicitly requested by the fetcher,
// returning those that should be handled differently.
//
// 用来对接收到 对端peer 发来的blockHeader 做处理
//
//  在 ProtocolManager.handleMsg() 的  `case msg.Code == BlockHeadersMsg` 中被调用
func (f *Fetcher) FilterHeaders(peer string, headers []*types.Header, time time.Time) []*types.Header {
	log.Trace("Filtering headers", "peer", peer, "headers", len(headers))

	// Send the filter channel to the fetcher
	filter := make(chan *headerFilterTask)


	// 先发一个通信用的 channel <filter通道> 给 headerFilter通道
	select {
	case f.headerFilter <- filter:
	case <-f.quit:
		return nil
	}


	// Request the filtering of the header list
	//
	// 将要过滤的 header 发送给 filter通道
	select {
	case filter <- &headerFilterTask{peer: peer, headers: headers, time: time}: // 封装成一个task  {对端peer, 对端peer发来的一串 headers, 当前时间}
	case <-f.quit:
		return nil
	}


	// Retrieve the headers remaining after filtering  检索过滤后剩余的标题
	//
	// 再从 filter 中获取过滤结果   todo (这里收到的是, 经过 header 过滤后, 得到的一串 之前未知Hash 的)
	select {
	case task := <-filter:
		return task.headers
	case <-f.quit:
		return nil
	}
}

// FilterBodies extracts all the block bodies that were explicitly requested by
// the fetcher, returning those that should be handled differently.
func (f *Fetcher) FilterBodies(peer string, transactions [][]*types.Transaction, uncles [][]*types.Header, time time.Time) ([][]*types.Transaction, [][]*types.Header) {
	log.Trace("Filtering bodies", "peer", peer, "txs", len(transactions), "uncles", len(uncles))

	// Send the filter channel to the fetcher
	filter := make(chan *bodyFilterTask)

	select {
	case f.bodyFilter <- filter:
	case <-f.quit:
		return nil, nil
	}
	// Request the filtering of the body list
	select {
	case filter <- &bodyFilterTask{peer: peer, transactions: transactions, uncles: uncles, time: time}:
	case <-f.quit:
		return nil, nil
	}
	// Retrieve the bodies remaining after filtering
	select {
	case task := <-filter:
		return task.transactions, task.uncles
	case <-f.quit:
		return nil, nil
	}
}

// Loop is the main fetcher loop, checking and processing various notification
// events.
func (f *Fetcher) loop() {   // todo Fetcher 的守护进程. 一直处理 Fetcher 的逻辑
	// Iterate the block fetching until a quit is requested    循环 获取 block，直到 请求退出

	fetchTimer := time.NewTimer(0)         	// (fetchTimer 的功能就是 定期发起请求获取 block 的 header)
	completeTimer := time.NewTimer(0)		// ()

	for {
		// Clean up any expired block fetches
		//
		// 清理所有过期的 block 的 抓取
		for hash, announce := range f.fetching {
			if time.Since(announce.time) > fetchTimeout {
				f.forgetHash(hash)  // 删除该 blockHash 的 抓取通知 annonces
			}
		}
		// Import any queued blocks that could potentially fit   导入任何可能适合的排队 block
		//
		// 先处理 被缓存的, 但是可以插入到本地 chain 中的, 由对端peer 广播过来的 block

		height := f.chainHeight()  // 获取当前本地 chain 的 currentHeight
		for !f.queue.Empty() {
			op := f.queue.PopItem().(*inject)		// 优先队列中取出 number 最小的 block
			hash := op.block.Hash()
			if f.queueChangeHook != nil {
				f.queueChangeHook(hash, false)
			}
			// If too high up the chain or phase, continue later  todo 如果该 block 的number 比当前 chain 的最高块高很多 <未来block>， 放回优先队列, 后面再处理
			number := op.block.NumberU64()   // 获取 该 block的 number
			if number > height+1 {
				f.queue.Push(op, -float32(number))
				if f.queueChangeHook != nil {
					f.queueChangeHook(hash, true)
				}
				break
			}
			// Otherwise if fresh and still unknown, try and import
			// todo 如果 当前 block 块高比 本地chain最高块 远远的 小 <当前chain早就过了这个number了>  或者  该block已经存在 chain上, 跳过该block, 继续处理下一个block
			if number+maxUncleDist < height || f.getBlock(hash) != nil {
				f.forgetBlock(hash)
				continue
			}
			f.insert(op.origin, op.block)  // 将该 block 插入本地 chain todo 这里最终调用的是 `blockchain.InsertChain(blocks)`
		}
		// Wait for an outside event to occur
		select {
		case <-f.quit:
			// Fetcher terminating, abort all operations
			return

		// todo 接收到 需要向目标对端 peer 抓取 某个 block 的 通知信息.
		case notification := <-f.notify:
			// A block was announced, make sure the peer isn't DOSing us
			propAnnounceInMeter.Mark(1)

			// 判断这个节点已经通知的、但是还未下载成功的哈希的数量
			count := f.announces[notification.origin] + 1
			if count > hashLimit {
				log.Debug("Peer exceeded outstanding announces", "peer", notification.origin, "limit", hashLimit)
				propAnnounceDOSMeter.Mark(1)
				break
			}

			// 确保当前通知的这个 block 不会太旧（比本地区块高度小 maxUncleDist）
			// 或 太新（比本地区块高度大 maxQueueDist）
			//
			// If we have a valid block number, check that it's potentially useful
			if notification.number > 0 {
				if dist := int64(notification.number) - int64(f.chainHeight()); dist < -maxUncleDist || dist > maxQueueDist {
					log.Debug("Peer discarded announcement", "peer", notification.origin, "number", notification.number, "hash", notification.hash, "distance", dist)
					propAnnounceDropMeter.Mark(1)
					break
				}
			}
			// All is well, schedule the announce if block's not yet downloading
			//
			// 一切都很好，如果 对应的当前block 尚未 被下载，请安排发布
			//
			// 确保当前通知的 block 还 未开始下载
			if _, ok := f.fetching[notification.hash]; ok {
				break
			}
			if _, ok := f.completing[notification.hash]; ok {
				break
			}

			// 这里首先更新的了节点的 待下载数量 (这个值用来保证不会缓存太多某个节点的未下载 block)
			f.announces[notification.origin] = count
			f.announced[notification.hash] = append(f.announced[notification.hash], notification)
			if f.announceChangeHook != nil && len(f.announced[notification.hash]) == 1 {
				f.announceChangeHook(notification.hash, true)
			}

			// 如果 Fetcher.announced 中只有刚才新加入的这一个 block 信息，那么调用 Fetcher.rescheduleFetch 重新设置变量 fetchTimer 的周期
			if len(f.announced) == 1 {
				f.rescheduleFetch(fetchTimer)
			}

		// todo 收到 需要将远端发过来的 block 插入本地 chain 的  插入通知
		case op := <-f.inject:
			// A direct block insertion was requested, try and fill any pending gaps
			//
			// 请求直接插入 block，尝试填补所有未解决的空白
			propBroadcastInMeter.Mark(1)
			f.enqueue(op.origin, op.block)  // todo 先缓存其 block 用于 异步的 插入 本地 chain中

		// todo 某个 blockHash 的block 已经完成了 插入到 本地chain中
		case hash := <-f.done:
			// A pending import finished, remove all traces of the notification
			f.forgetHash(hash)			// 删除该 blockHash 的 抓取通知 annonces
			f.forgetBlock(hash)			// 删除该 blockHash 的 插入通知 inject

		// todo 定时调度,  header 的抓取 (从对端peer下载)
		case <-fetchTimer.C:

			// 通知 以后的 block 信息，其状态从「通知」变成了「下载中」是在 fetchTimer 这个消息的处理代码中完成的

			// At least one block's timer ran out, check for needing retrieval  至少一个块的计时器用完了，检查是否需要检索
			request := make(map[string][]common.Hash)   // (对端peer 的 nodeId => 需要下载的 block的Hash)


			// 选择 要下载的 block ，从 announced 转移到 fetching 中，
			// 并将 要下载的 block 的Hash 填充到 request 中
			for hash, announces := range f.announced {
				if time.Since(announces[0].time) > arriveTimeout-gatherSlack { // todo 注意「可以下载的」条件是区块通知的时间已经过去了 arriveTimeout-gatherSlack  <500 ms - 100 ms> 这么长时间

					// Pick a random peer to retrieve from, reset all others  todo 选择一个随机 peer 从中检索，重设所有其他
					announce := announces[rand.Intn(len(announces))]
					f.forgetHash(hash)  // 删除该 blockHash 的 抓取通知 annonces

					// If the block still didn't arrive, queue for fetching   如果该块仍未到达，则排队进行提取
					if f.getBlock(hash) == nil {   // 如果该 blockHash 对应的 block 不在本地chain上
						request[announce.origin] = append(request[announce.origin], hash)  // 将该 blockHash 下载请求 追加到对应的 peer 的req上
						f.fetching[hash] = announce  // 从 announced 转移到 fetching 中
					}
				}
			}


			// Send out all block header requests  发送所有 block header 请求
			for peer, hashes := range request {
				log.Trace("Fetching scheduled headers", "peer", peer, "list", hashes)

				// Create a closure of the fetch and schedule in on a new thread  创建 一个 闭包 的抓取任务 并在新线程上 调度
				fetchHeader, hashes := f.fetching[hashes[0]].fetchHeader, hashes
				go func() {
					if f.fetchingHook != nil {
						f.fetchingHook(hashes)
					}

					// 逐个的向 该对端peer 上抓取 各个 blockHash 的  对应的 blockHeader
					for _, hash := range hashes {
						headerFetchMeter.Mark(1)

						// todo 调用 `p.RequestOneHeader()` 向对端 peer 发起 `GetBlockHeadersMsg` 消息
						fetchHeader(hash) // Suboptimal, but protocol doesn't allow batch header retrievals
					}
				}()
			}
			// Schedule the next fetch if blocks are still pending   重新设置下次的下载发起时间
			//
			// 如果还有 blocks 还在 被处理阻塞中, 那么我们更新 Fecther 的下一轮定时调度.
			f.rescheduleFetch(fetchTimer)


		// todo 定时调度,  body 的抓取 (从对端peer下载)
		case <-completeTimer.C:


			// At least one header's timer ran out, retrieve everything
			request := make(map[string][]common.Hash)


			// 从 Fetcher.fetched 中选取将要下载 body 的是信息放入 request 中
			for hash, announces := range f.fetched {


				// Pick a random peer to retrieve from, reset all others  选择一个 随机 对端peer 从中检索，重设所有其他
				announce := announces[rand.Intn(len(announces))]
				f.forgetHash(hash)  // 删除该 blockHash 的 抓取通知 annonces

				// If the block still didn't arrive, queue for completion  如果该区块 不在本地chain
				if f.getBlock(hash) == nil {
					request[announce.origin] = append(request[announce.origin], hash)
					f.completing[hash] = announce
				}
			}


			// Send out all block body requests
			//
			// 逐个遍历 需要 抓取 body 的 req
			for peer, hashes := range request {
				log.Trace("Fetching scheduled bodies", "peer", peer, "list", hashes)

				// Create a closure of the fetch and schedule in on a new thread
				if f.completingHook != nil {
					f.completingHook(hashes)
				}
				bodyFetchMeter.Mark(int64(len(hashes)))
				go f.completing[hashes[0]].fetchBodies(hashes)  // todo 异步调用 `p.RequestBodies()` 向对端 peer 发起  `GetBlockBodiesMsg` 消息
			}
			// Schedule the next fetch if blocks are still pending
			f.rescheduleComplete(completeTimer)   // 和 Fetcher.rescheduleFetch() 类似 的调用处理

		// todo 接收一个专门用来处理  header 的 chan
		case filter := <-f.headerFilter:
			// Headers arrived from a remote peer. Extract those that were explicitly
			// requested by the fetcher, and return everything else so it's delivered
			// to other parts of the system.
			var task *headerFilterTask

			// 监听 专门用来处理 header 的chan
			select {

			// 接收到 对一串headers 的做过滤的  任务
			case task = <-filter:
			case <-f.quit:
				return
			}
			headerFilterInMeter.Mark(int64(len(task.headers)))

			// Split the batch of headers into unknown ones (to return to the caller),
			// known incomplete ones (requiring body retrievals) and completed blocks.
			//
			// 将一批 header 拆分为 未知的header（以返回到调用方），已知的不完整的 header（需要正文检索）和  完整的block
			//
			// 				unknown 代表「未知」: 		这些区块根本不是 Fetcher 对象发起下载的
			// 				incomplete:					代表是 Fetcher 发起下载的区块，但这里只有 header 数据，还需少 body 数据
			// 				complete: 					也代表是 Fetcher 发起的区块，并且这个区块已经不缺数据可以直接导入本地数据库了
			//
			// 		complete 状态的数据都是空块，因为空区块的 body 为空，不需要下载。
			//
			// 未知的,  已知不完整的, 已经完成的
			unknown, incomplete, complete := []*types.Header{}, []*announce{}, []*types.Block{}

			// 逐个处理这一批 headers
			for _, header := range task.headers {


				hash := header.Hash()

				// 判断是否是我们   正在下载的 header  (是, 则 开始处理  <因为只有 下载中的 header 的hash 才在 fecthing 里面啊>)
				//
				// Filter fetcher-requested headers from other synchronisation algorithms   过滤来自其他同步算法的提取器 请求的 header
				if announce := f.fetching[hash]; announce != nil && announce.origin == task.peer && f.fetched[hash] == nil && f.completing[hash] == nil && f.queued[hash] == nil {
					// If the delivered header does not match the promised number, drop the announcer
					if header.Number.Uint64() != announce.number {
						log.Trace("Invalid block number fetched", "peer", announce.origin, "hash", header.Hash(), "announced", announce.number, "provided", header.Number)
						f.dropPeer(announce.origin)  // 将该对端peer 从本地 ProtocolManager.peerSet 和 Downloader.peerSet 中移除   `ProtocolManager.removePeer()` 函数指针
						f.forgetHash(hash)  // 删除该 blockHash 的 抓取通知 annonces
						continue
					}
					// Only keep if not imported by other means  仅保留 (如果未通过其他方式导入)
					//
					// 如果 此block 在本地 不存在
					if f.getBlock(hash) == nil {
						announce.header = header
						announce.time = task.time


						// If the block is empty (header only), short circuit into the final import queue   如果该块为空 (仅标题), 则将其直接返回到最终导入队列中
						//
						// 判断是否是空区块
						// 对于空区块，直接加入到 Fetcher.completing 中
						if header.TxHash == types.DeriveSha(types.Transactions{}) && header.UncleHash == types.CalcUncleHash([]*types.Header{}) {
							log.Trace("Block empty, skipping body retrieval", "peer", announce.origin, "number", header.Number, "hash", header.Hash())

							block := types.NewBlockWithHeader(header)
							block.ReceivedAt = task.time

							complete = append(complete, block) 	// 追加到 complete 队列
							f.completing[hash] = announce		// 追加到 已完成 body 下载阶段中
							continue
						}
						// Otherwise add to the list of blocks needing completion   否则添加到需要完成的块列表中
						//
						// 非空区块，保存在 incomplete 中
						incomplete = append(incomplete, announce)

					// 如果 此block 在本地 已经存在
					} else {
						log.Trace("Block already imported, discarding header", "peer", announce.origin, "number", header.Number, "hash", header.Hash())
						f.forgetHash(hash)  // 删除该 blockHash 的 抓取通知 annonces
					}

				// 不在 正在下载中 的, 属于 未知block
				} else {
					// Fetcher doesn't know about it, add to the return list  Fetcher不知道，请添加到返回列表中
					//
					// 如果 header 是我们发起下载的，则还会判断本地是否已经存在这个区块了，因为在 Fetcher 发起下载的过程中，downloader 模块可能已经将其下载完成了
					//
					// 所以不管, 都返回给 downloader 去处理 unknown
					unknown = append(unknown, header)
				}
			}

			headerFilterOutMeter.Mark(int64(len(unknown)))

			select {

			// 将 未知的 Hash 的继续封装成新的 header 过滤任务 发回去
			case filter <- &headerFilterTask{headers: unknown, time: task.time}:
			case <-f.quit:
				return
			}
			// Schedule the retrieved headers for body completion    安排检索到的 header 以完成 body 的下载
			for _, announce := range incomplete {
				hash := announce.header.Hash()
				if _, ok := f.completing[hash]; ok {  // 跳过已经完成 body 下载的
					continue
				}

				// 追加 到切片中 (每个annonce 中有 当前blockHash 和不同的 对端peer 的nodeId, 所以用切片, 类似 f.announced )
				f.fetched[hash] = append(f.fetched[hash], announce)  // 从 fecthing 转到 fecthed 中 (但是这里没从 fecthing中删除,  在其他逻辑中会被删除的, 不慌 ...)

				// 类似的, 如果只有一个 需要下载 body 的Hash了, 那就刷新 completeTimer 定时器
				if len(f.fetched) == 1 {
					f.rescheduleComplete(completeTimer)  //  Fetcher.rescheduleComplete() 重置 completeTimer 定时器. 这一方法与 Fetcher.rescheduleFetch() 类似
				}
			}
			// Schedule the header-only blocks for import   安排仅 只有 header 没有body 的空block 进行 插入本地 chain
			for _, block := range complete {
				if announce := f.completing[block.Hash()]; announce != nil {
					f.enqueue(announce.origin, block)  // todo 先缓存其 block 用于 异步的 插入 本地 chain中
				}
			}


		// todo 接收一个专门用来处理  body 的 chan
		case filter := <-f.bodyFilter:

			// Block bodies arrived, extract any explicitly requested blocks, return the rest
			var task *bodyFilterTask
			select {
			case task = <-filter:
			case <-f.quit:
				return
			}
			bodyFilterInMeter.Mark(int64(len(task.transactions)))

			blocks := []*types.Block{}
			for i := 0; i < len(task.transactions) && i < len(task.uncles); i++ {
				// Match up a body to any possible completion request
				matched := false

				for hash, announce := range f.completing {
					if f.queued[hash] == nil {
						txnHash := types.DeriveSha(types.Transactions(task.transactions[i]))
						uncleHash := types.CalcUncleHash(task.uncles[i])

						if txnHash == announce.header.TxHash && uncleHash == announce.header.UncleHash && announce.origin == task.peer {
							// Mark the body matched, reassemble if still unknown
							matched = true

							if f.getBlock(hash) == nil {
								block := types.NewBlockWithHeader(announce.header).WithBody(task.transactions[i], task.uncles[i])
								block.ReceivedAt = task.time

								blocks = append(blocks, block)
							} else {
								f.forgetHash(hash)  // 删除该 blockHash 的 抓取通知 annonces
							}
						}
					}
				}
				if matched {
					task.transactions = append(task.transactions[:i], task.transactions[i+1:]...)
					task.uncles = append(task.uncles[:i], task.uncles[i+1:]...)
					i--
					continue
				}
			}

			bodyFilterOutMeter.Mark(int64(len(task.transactions)))
			select {
			case filter <- task:
			case <-f.quit:
				return
			}
			// Schedule the retrieved blocks for ordered import
			for _, block := range blocks {
				if announce := f.completing[block.Hash()]; announce != nil {
					f.enqueue(announce.origin, block)  // todo 先缓存其 block 用于 异步的 插入 本地 chain中
				}
			}
		}
	}
}

// rescheduleFetch resets the specified fetch timer to the next announce timeout.
//
// rescheduleFetch() 将指定的获取计时器重置为下一个 发布超时   todo 为了重新设置 fetchTimer 这个变量的周期
func (f *Fetcher) rescheduleFetch(fetch *time.Timer) {

	// todo 首先从 Fetcher.announced 中找出通知的区块中，通知时间距当前最近的时间（也即最晚通知的时间），然后利用这个时间重置 fetch 这个参数.
	//
	// 意思是：在最近一个次通知过去 arriveTimeout 这么长时间以后，再触发 fetch 这个 timer
	//
	// Fetcher.rescheduleFetch 中设置的时间，就是要在区块通知过去 arriveTimeout - time.Since(earliest) 这么长时间以后，再去发起下载请求.
	//
	// todo 原因: 因为刚产生的区块并不稳定，有可能过了一会它变成了一个【废block】，也有可能变成了别人的【叔block】，稍等片刻再去处理时可能这些变化已经完成，
	// 			从而避免自己对这些变化进行处理.

	// Short circuit if no blocks are announced
	if len(f.announced) == 0 {  // 如果没有 需要被下载的block 抓去通知信息 <根据blockHash去下载>
		return
	}
	// Otherwise find the earliest expiring announcement
	earliest := time.Now()
	for _, announces := range f.announced {
		if earliest.After(announces[0].time) {
			earliest = announces[0].time
		}
	}
	fetch.Reset(arriveTimeout - time.Since(earliest))  // 500ms - 最早到达的block的 time  (500ms 上下这样才去重新 抓取下 blockHeader)
}

// rescheduleComplete resets the specified completion timer to the next fetch timeout.
func (f *Fetcher) rescheduleComplete(complete *time.Timer) {  //  Fetcher.rescheduleComplete() 重置 completeTimer 定时器. 这一方法与 Fetcher.rescheduleFetch() 类似
	// Short circuit if no headers are fetched
	if len(f.fetched) == 0 {
		return
	}
	// Otherwise find the earliest expiring announcement
	earliest := time.Now()
	for _, announces := range f.fetched {
		if earliest.After(announces[0].time) {
			earliest = announces[0].time
		}
	}
	complete.Reset(gatherSlack - time.Since(earliest))
}

// enqueue schedules a new future import operation, if the block to be imported
// has not yet been seen.
func (f *Fetcher) enqueue(peer string, block *types.Block) {   // todo 先缓存其 block 用于 异步的 插入 本地 chain中
	hash := block.Hash()

	// Ensure the peer isn't DOSing us
	count := f.queues[peer] + 1  // 记录 对端peer 往当前 peer 发过几次 block 插入广播
	if count > blockLimit {
		log.Debug("Discarded propagated block, exceeded allowance", "peer", peer, "number", block.Number(), "hash", hash, "limit", blockLimit)
		propBroadcastDOSMeter.Mark(1)
		f.forgetHash(hash)  // 删除该 blockHash 的 抓取通知 annonces
		return
	}
	// Discard any past or too distant blocks  丢弃 所有过去 或 距离太远 的 blocks
	if dist := int64(block.NumberU64()) - int64(f.chainHeight()); dist < -maxUncleDist || dist > maxQueueDist {
		log.Debug("Discarded propagated block, too far away", "peer", peer, "number", block.Number(), "hash", hash, "distance", dist)
		propBroadcastDropMeter.Mark(1)
		f.forgetHash(hash)  // 删除该 blockHash 的 抓取通知 annonces
		return
	}
	// Schedule the block for future importing
	//
	// todo 先缓存其 block 用于 异步的 插入 本地 chain中
	if _, ok := f.queued[hash]; !ok {
		op := &inject{
			origin: peer,
			block:  block,
		}
		f.queues[peer] = count
		f.queued[hash] = op
		f.queue.Push(op, -float32(block.NumberU64()))
		if f.queueChangeHook != nil {
			f.queueChangeHook(op.block.Hash(), true)
		}
		log.Debug("Queued propagated block", "peer", peer, "number", block.Number(), "hash", hash, "queued", f.queue.Size())
	}
}

// insert spawns a new goroutine to run a block insertion into the chain. If the
// block's number is at the same height as the current import phase, it updates
// the phase states accordingly.
//
// `insert()` 会产生一个新的goroutine，以将 block 插入到 chain中.
// 			 如果 block 的 number 与 当前导入阶段的 number相同，则会相应地更新阶段状态.
func (f *Fetcher) insert(peer string, block *types.Block) {
	hash := block.Hash()

	// 启动一个 异步任务 将 block 插入本地 chain
	// Run the import on a new thread
	log.Debug("Importing propagated block", "peer", peer, "number", block.Number(), "hash", hash)
	go func() {
		defer func() { f.done <- hash }()

		// If the parent's unknown, abort insertion
		parent := f.getBlock(block.ParentHash())
		if parent == nil {
			log.Debug("Unknown parent of propagated block", "peer", peer, "number", block.Number(), "hash", hash, "parent", block.ParentHash())
			return
		}
		// Quickly validate the header and propagate the block if it passes
		switch err := f.verifyHeader(block.Header()); err {  // todo 校验该 block 的合法性 <重放block>
		case nil:
			// All ok, quickly propagate to our peers
			propBroadcastOutTimer.UpdateSince(block.ReceivedAt)
			go f.broadcastBlock(block, true)

		case consensus.ErrFutureBlock:
			// Weird future block, don't fail, but neither propagate

		default:
			// Something went very wrong, drop the peer
			log.Debug("Propagated block verification failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
			f.dropPeer(peer)  // 将该对端peer 从本地 ProtocolManager.peerSet 和 Downloader.peerSet 中移除   `ProtocolManager.removePeer()` 函数指针
			return
		}
		// Run the actual import and log any issues
		if _, err := f.insertChain(types.Blocks{block}); err != nil {  // 将该 block  插入 chain 中 todo 这里最终调用的是 `blockchain.InsertChain(blocks)`
			log.Debug("Propagated block import failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
			return
		}
		// If import succeeded, broadcast the block
		propAnnounceOutTimer.UpdateSince(block.ReceivedAt)
		go f.broadcastBlock(block, false)    // todo 并且将 block 广播给 其他和当前 peer 节点的 对端peer

		// Invoke the testing hook if needed
		if f.importedHook != nil {
			f.importedHook(block)
		}
	}()
}

// forgetHash removes all traces of a block announcement from the fetcher's
// internal state.
//
func (f *Fetcher) forgetHash(hash common.Hash) {  // 删除该 blockHash 的 抓取通知 annonces
	// Remove all pending announces and decrement DOS counters
	for _, announce := range f.announced[hash] {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
	}
	delete(f.announced, hash)
	if f.announceChangeHook != nil {
		f.announceChangeHook(hash, false)
	}
	// Remove any pending fetches and decrement the DOS counters
	if announce := f.fetching[hash]; announce != nil {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
		delete(f.fetching, hash)
	}

	// Remove any pending completion requests and decrement the DOS counters
	for _, announce := range f.fetched[hash] {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
	}
	delete(f.fetched, hash)

	// Remove any pending completions and decrement the DOS counters
	if announce := f.completing[hash]; announce != nil {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
		delete(f.completing, hash)
	}
}

// forgetBlock removes all traces of a queued block from the fetcher's internal
// state.
func (f *Fetcher) forgetBlock(hash common.Hash) {  // 删除该 blockHash 的 插入通知 inject
	if insert := f.queued[hash]; insert != nil {
		f.queues[insert.origin]--
		if f.queues[insert.origin] == 0 {
			delete(f.queues, insert.origin)
		}
		delete(f.queued, hash)
	}
}
