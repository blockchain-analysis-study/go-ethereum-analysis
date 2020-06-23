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

package core

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core/state"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/event"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/metrics"
	"github.com/go-ethereum-analysis/params"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

const (
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
)

var (
	// ErrInvalidSender is returned if the transaction contains an invalid signature.
	ErrInvalidSender = errors.New("invalid sender")

	// ErrNonceTooLow is returned if the nonce of a transaction is lower than the
	// one present in the local chain.
	ErrNonceTooLow = errors.New("nonce too low")

	// ErrUnderpriced is returned if a transaction's gas price is below the minimum
	// configured for the transaction pool.
	ErrUnderpriced = errors.New("transaction underpriced")

	// ErrReplaceUnderpriced is returned if a transaction is attempted to be replaced
	// with a different one without the required price bump.
	ErrReplaceUnderpriced = errors.New("replacement transaction underpriced")

	// ErrInsufficientFunds is returned if the total cost of executing a transaction
	// is higher than the balance of the user's account.
	ErrInsufficientFunds = errors.New("insufficient funds for gas * price + value")

	// ErrIntrinsicGas is returned if the transaction is specified to use less gas
	// than required to start the invocation.
	ErrIntrinsicGas = errors.New("intrinsic gas too low")

	// ErrGasLimit is returned if a transaction's requested gas limit exceeds the
	// maximum allowance of the current block.
	ErrGasLimit = errors.New("exceeds block gas limit")

	// ErrNegativeValue is a sanity error to ensure noone is able to specify a
	// transaction with a negative value.
	ErrNegativeValue = errors.New("negative value")

	// ErrOversizedData is returned if the input data of a transaction is greater
	// than some meaningful limit a user might use. This is not a consensus error
	// making the transaction invalid, rather a DOS protection.
	ErrOversizedData = errors.New("oversized data")
)

var (

	// 检查可收回交易的时间间隔 (清除 作废交易的 时间间隔)
	evictionInterval    = time.Minute     // Time interval to check for evictable transactions
	// 报告事务池统计信息的时间间隔 (定期 上报交易池统计数据的 时间间隔)
	statsReportInterval = 8 * time.Second // Time interval to report transaction pool stats
)

var (
	// Metrics for the pending pool
	pendingDiscardCounter   = metrics.NewRegisteredCounter("txpool/pending/discard", nil)
	pendingReplaceCounter   = metrics.NewRegisteredCounter("txpool/pending/replace", nil)
	pendingRateLimitCounter = metrics.NewRegisteredCounter("txpool/pending/ratelimit", nil) // Dropped due to rate limiting
	pendingNofundsCounter   = metrics.NewRegisteredCounter("txpool/pending/nofunds", nil)   // Dropped due to out-of-funds

	// Metrics for the queued pool
	queuedDiscardCounter   = metrics.NewRegisteredCounter("txpool/queued/discard", nil)
	queuedReplaceCounter   = metrics.NewRegisteredCounter("txpool/queued/replace", nil)
	queuedRateLimitCounter = metrics.NewRegisteredCounter("txpool/queued/ratelimit", nil) // Dropped due to rate limiting
	queuedNofundsCounter   = metrics.NewRegisteredCounter("txpool/queued/nofunds", nil)   // Dropped due to out-of-funds

	// General tx metrics
	invalidTxCounter     = metrics.NewRegisteredCounter("txpool/invalid", nil)
	underpricedTxCounter = metrics.NewRegisteredCounter("txpool/underpriced", nil)
)

// TxStatus is the current status of a transaction as seen by the pool.
type TxStatus uint

const (
	TxStatusUnknown TxStatus = iota
	TxStatusQueued
	TxStatusPending
	TxStatusIncluded
)

// blockChain provides the state of blockchain and current gas limit to do
// some pre checks in tx pool and event subscribers.
type blockChain interface {
	CurrentBlock() *types.Block
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(root common.Hash) (*state.StateDB, error)

	SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription
}

// TxPoolConfig are the configuration parameters of the transaction pool.
type TxPoolConfig struct {

	// 本地账户集
	Locals    []common.Address // Addresses that should be treated by default as local

	// 是否应禁用本地事务处理 true: 禁用, false: 不禁用
	NoLocals  bool             // Whether local transaction handling should be disabled

	// 幸免节点重启的本地事务日志
	Journal   string           // Journal of local transactions to survive node restarts
	// 重新生成本地交易日志的时间间隔
	Rejournal time.Duration    // Time interval to regenerate the local transaction journal

	// 强制接受 txpool 的最低汽油价格
	PriceLimit uint64 // Minimum gas price to enforce for acceptance into the pool


	// 替换现有交易的最低价格暴涨百分比（nonce） todo 主要是指, nonce 相同时, 我们替换 txpool 中tx时用的 新tx的price 相对于老tx的price 比例
	PriceBump  uint64 // Minimum price bump percentage to replace an already existing transaction (nonce)

	// 每个帐户保证的可执行交易 slots 的数量
	AccountSlots uint64 // Number of executable transaction slots guaranteed per account

	// 所有帐户的最大可执行交易插槽数 (pending 中的最大可装载 tx 数目)
	GlobalSlots  uint64 // Maximum number of executable transaction slots for all accounts

	// 每个帐户允许的最大非执行交易位数量
	AccountQueue uint64 // Maximum number of non-executable transaction slots permitted per account

	// 所有帐户的最大不可执行交易位数量 (queue 中的最大可装载 tx 数目)
	GlobalQueue  uint64 // Maximum number of non-executable transaction slots for all accounts

	// 不可执行事务排队的最长时间 todo (tx超时时间, 默认为 3小时)
	Lifetime time.Duration // Maximum amount of time non-executable transaction are queued
}

// DefaultTxPoolConfig contains the default configurations for the transaction
// pool.
var DefaultTxPoolConfig = TxPoolConfig{
	Journal:   "transactions.rlp",
	Rejournal: time.Hour,

	PriceLimit: 1,
	PriceBump:  10,


	// 控制 txpool 大小的4个参数
	/**
	TODO: 缓冲区溢出（交易超过阈值）的三种情况：

	a) all溢出， Count(all) > GlobalSlots + GlobalQueue
	b) pending溢出, Count(pending) > GlobalSlots
	c) queue溢出, Count(queue) > GlobalQueue

	todo: 第一种情况起因一般是有新的交易入池，
	todo: 后两种情况起因除了新交易入池外，还有可能是删除交易或交易替换引起的两者之间的动态调整

	TODO: 对应的处理策略：

	1) all溢出。新交易如果是Unpriced，拒绝；否则删除旧交易，插入新交易
	2) pending溢出。建立一个关于账户交易数的优先队列，对超过交易数限额AccountSlots的账户进行惩罚，按照图5所示策略剔除交易，降低交易池负载
	3) queue溢出。删除滞留在queue中最旧的交易。

	首先，建立一个超限额账户的优先队列；取出交易最多的两个账户（第一多和第二多），从交易第一多的账户开始删除交易，直到与第二多相等，
	如果pending仍溢出，从优先队列中取出下一个账户（第三多），重复前面的过程。
	最后，如果优先队列为空，pending仍溢出，那么按照账户的取出顺序，每次删除一笔交易，直到pending内交易量小于GlobalSlots阈值

	TODO: 交易过滤

	超时过滤
	gas最大过滤，GasLimit
	gasPrice过滤
	Local白名单


	TODO: local交易会被登记入pool.locals，类似一个白名单，`添加交易的时候不对gasPrice进行检查`。缓冲区执行交易剔除相关策略时，不删除在pools.locals中登记账户的交易

	使用本地命令行,且有keystore 在本地的账户发起的tx,即为 local txs
	 */

	// todo: 前两个与pending缓冲区有关
	AccountSlots: 16,
	GlobalSlots:  4096,
	// todo:  后两个用来限制queue缓冲区大小
	AccountQueue: 64,
	GlobalQueue:  1024,

	Lifetime: 3 * time.Hour,
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
func (config *TxPoolConfig) sanitize() TxPoolConfig {
	conf := *config
	if conf.Rejournal < time.Second {
		log.Warn("Sanitizing invalid txpool journal time", "provided", conf.Rejournal, "updated", time.Second)
		conf.Rejournal = time.Second
	}
	if conf.PriceLimit < 1 {
		log.Warn("Sanitizing invalid txpool price limit", "provided", conf.PriceLimit, "updated", DefaultTxPoolConfig.PriceLimit)
		conf.PriceLimit = DefaultTxPoolConfig.PriceLimit
	}
	if conf.PriceBump < 1 {
		log.Warn("Sanitizing invalid txpool price bump", "provided", conf.PriceBump, "updated", DefaultTxPoolConfig.PriceBump)
		conf.PriceBump = DefaultTxPoolConfig.PriceBump
	}
	return conf
}

// TxPool contains all currently known transactions. Transactions
// enter the pool when they are received from the network or submitted
// locally. They exit the pool when they are included in the blockchain.
//
// The pool separates processable transactions (which can be applied to the
// current state) and future transactions. Transactions move between those
// two states over time as they are received and processed.
type TxPool struct {
	config       TxPoolConfig
	chainconfig  *params.ChainConfig

	// 链 引用
	chain        blockChain

	// 当前 节点的 txpool 中的 gasPrice 阈值
	gasPrice     *big.Int

	// 一个 event用来做广播交易的, p2p处有用
	txFeed       event.Feed

	// 用来做统计的
	scope        event.SubscriptionScope

	// 接收 新Head 事件
	chainHeadCh  chan ChainHeadEvent
	// 用来订阅 chainHeadCh
	chainHeadSub event.Subscription

	// 当前节点上的 签名实例
	signer       types.Signer

	// 读写锁
	mu           sync.RWMutex

	// 当前 bc 中的最新 state (不一定是 落链的 block 哦)
	currentState  *state.StateDB      // Current state in the blockchain head

	// pending state 跟踪 虚拟 nonces ??
	pendingState  *state.ManagedState // Pending state tracking virtual nonces

	// tx上限的当前 gas 限额
	currentMaxGas uint64              // Current gas limit for transaction caps

	// 账户 白名单
	locals  *accountSet // Set of local transaction to exempt from eviction rules

	// 用于将本地tx备份到磁盘
	journal *txJournal  // Journal of local transaction to back up to disk


	/**
	TODO
	pending中的交易可被立即处理并打包，
	queue中的交易是nonce-gap交易，当nonce-gap消除后，会被迁移到pending缓存中
	 */

	// 存放可以被执行的 tx
	pending map[common.Address]*txList   // All currently processable transactions
	// 存放目前还不能执行的 tx (新tx先进这里)
	queue   map[common.Address]*txList   // Queued but non-processable transactions
	// 每个已知帐户的最后一次心跳 (用于记录 tx 超时??)
	beats   map[common.Address]time.Time // Last heartbeat from each known account
	// 存放当前txpool中 所有 tx
	all     *txLookup                    // All transactions to allow lookups
	// 所有的tx 都在 price中被排序
	// 这个吊毛里面也有一个all 和当前all是同一个引用 查看：NewTxPool()
	priced  *txPricedList                // All transactions sorted by price

	wg sync.WaitGroup // for shutdown sync

	// 是否为家园版本的 标识位
	homestead bool
}

// NewTxPool creates a new transaction pool to gather, sort and filter inbound
// transactions from the network.
func NewTxPool(config TxPoolConfig, chainconfig *params.ChainConfig, chain blockChain) *TxPool {
	// Sanitize the input to ensure no vulnerable gas prices are set
	config = (&config).sanitize()

	// Create the transaction pool with its initial settings
	pool := &TxPool{
		config:      config,
		chainconfig: chainconfig,
		chain:       chain,
		signer:      types.NewEIP155Signer(chainconfig.ChainID),
		pending:     make(map[common.Address]*txList),
		queue:       make(map[common.Address]*txList),
		beats:       make(map[common.Address]time.Time),
		all:         newTxLookup(),
		chainHeadCh: make(chan ChainHeadEvent, chainHeadChanSize),
		gasPrice:    new(big.Int).SetUint64(config.PriceLimit),
	}
	pool.locals = newAccountSet(pool.signer)

	// 获取 本地账户地址
	for _, addr := range config.Locals {
		log.Info("Setting new local account", "address", addr)
		pool.locals.add(addr)
	}
	pool.priced = newTxPricedList(pool.all)

	// 整顿下 txpool
	pool.reset(nil, chain.CurrentBlock().Header())

	// If local transactions and journaling is enabled, load from disk
	//
	// 如果启用了本地事务和日记功能，请从磁盘加载
	if !config.NoLocals && config.Journal != "" {
		pool.journal = newTxJournal(config.Journal)

		// 解析出 disk 中的本地 txs, 使用 pool.AddLocals() 追加到 tx 中
		if err := pool.journal.load(pool.AddLocals); err != nil {
			log.Warn("Failed to load transaction journal", "err", err)
		}

		// 重置 journal
		if err := pool.journal.rotate(pool.local()); err != nil {
			log.Warn("Failed to rotate transaction journal", "err", err)
		}
	}
	// Subscribe events from blockchain
	//
	// 订阅 新head事件
	pool.chainHeadSub = pool.chain.SubscribeChainHeadEvent(pool.chainHeadCh)

	// Start the event loop and return
	//
	// 启动事件循环并返回
	pool.wg.Add(1)
	/** todo 【注意】这个协程一直在后台跑的，一直在处理着 tx pool 中的tx */
	go pool.loop()

	return pool
}

// loop is the transaction pool's main event loop, waiting for and reacting to
// outside blockchain events as well as for various reporting and transaction
// eviction events.
/**
todo loop函数：
   是 tx pool 的主要事件循环，等待并响应外部区块链事件以及各种报告和 tx 删除事件。
 */
func (pool *TxPool) loop() {
	defer pool.wg.Done()

	// Start the stats reporting and transaction eviction tickers
	// 启动统计报告和非法交易移除的代码
	//
	// TODO
	//  prevPending: 上一次统计时 pending 中的tx数
	//  prevQueued: 上一次统计时 queue 中的tx数
	//  prevStales: 上一次统计时 因过期而删除的tx数
	var prevPending, prevQueued, prevStales int


	/**
	TODO
		事件处理
		交易池在符合条件下，会处理以下事件：
	todo
		report：   			统计交易池中pending和queue中交易数量（default 8s）
		evict：    			交易失效检查事件（1min），从queue中剔除3个小时前的交易，（类似挂单，超时删除）
		journal：  			本地交易日志（缓存pending和queue队列中属于本地的交易，白名单交易，默认存储于transactions.rlp)
		chainHeadEvent：	收到新块后交易池的处理，调用 reset()

	*/




	/**
	TODO
		每 8 秒钟定时器 (统计报告)
	 */
	report := time.NewTicker(statsReportInterval)
	defer report.Stop()

	/**
	TODO
		1 分钟定时器 (移除 非法区块) evict: 逐出
		从queue中剔除3个小时前的交易
	 */
	evict := time.NewTicker(evictionInterval)
	defer evict.Stop()
	/**
	TODO
		默认为 1 h 定时器 (刷入磁盘)
	 */
	journal := time.NewTicker(pool.config.Rejournal)
	defer journal.Stop()

	// Track the previous head headers for transaction reorgs （reorgs：reorganization）
	// todo 跟踪先前的header以进行 tx重组
	head := pool.chain.CurrentBlock()

	// Keep waiting for and reacting to the various events
	for {
		select {

		// TODO
		// Handle ChainHeadEvent
		// 处理 ChainHeadEvent
		case ev := <-pool.chainHeadCh:
			if ev.Block != nil {
				pool.mu.Lock()
				// 判断是否是 家园版本
				if pool.chainconfig.IsHomestead(ev.Block.Number()) {
					pool.homestead = true
				}

				/**
				todo 【重中之重】
				根据当前 链上的最高块，和被广播过来的 新最高块
				决定是否重组 tx pool
				 */
				pool.reset(head.Header(), ev.Block.Header())
				// 将同步过来的新的最高块 赋值到 head 指针上
				head = ev.Block

				pool.mu.Unlock()
			}
		// Be unsubscribed due to system stopped
		// 如果是由于系统停止则取消订阅
		case <-pool.chainHeadSub.Err():
			return

		// Handle stats reporting ticks
		// 处理报告统计数据的定时器
		case <-report.C:
			pool.mu.RLock()
			// 返回 pending 和 queue 中的数量
			pending, queued := pool.stats()
			// 获取 过期而被删除的tx 数目
			stales := pool.priced.stales
			pool.mu.RUnlock()

			if pending != prevPending || queued != prevQueued || stales != prevStales {
				log.Debug("Transaction pool status report", "executable", pending, "queued", queued, "stales", stales)
				// 重置 全局的 技术中转变量
				prevPending, prevQueued, prevStales = pending, queued, stales
			}


		// Handle inactive account transaction eviction
		// 定时移除非活动帐户的tx 处理
		//
		// TODO 定期清除交易池
		case <-evict.C:
			pool.mu.Lock()
			// todo 每分钟 定时扫描 queue中的tx
			for addr := range pool.queue {
				// Skip local transactions from the eviction mechanism (eviction mechanism: 驱逐机制)
				// todo 从驱逐机制中跳过本地交易
				if pool.locals.contains(addr) {
					continue
				}
				// Any non-locals old enough should be removed
				// 任何足够旧 (过时的)的非本地 addr 的 tx都应该被删除  (Lifetime: 默认 3小时)
				// 如果当前账户的 tx 的 beat 是 Lifetime 之前的
				// 需要全部移除
				if time.Since(pool.beats[addr]) > pool.config.Lifetime {
					// todo Flatten: 对 tx list 构建 构建一个 根据 nonce 从小到大的 排序的 cache，并返回 cache中的tx
					for _, tx := range pool.queue[addr].Flatten() {
						pool.removeTx(tx.Hash(), true)
					}
				}
			}
			pool.mu.Unlock()

		// Handle local transaction journal rotation
		//
		// 处理本地交易日记帐轮换
		case <-journal.C:
			if pool.journal != nil {
				pool.mu.Lock()
				if err := pool.journal.rotate(pool.local()); err != nil {
					log.Warn("Failed to rotate local tx journal", "err", err)
				}
				pool.mu.Unlock()
			}
		}
	}
}

// lockedReset is a wrapper around reset to allow calling it in a thread safe
// manner. This method is only ever used in the tester!
func (pool *TxPool) lockedReset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.reset(oldHead, newHead)
}

// reset retrieves the current state of the blockchain and ensures the content
// of the transaction pool is valid with regard to the chain state.
/**
todo 【重中之重】
reset 函数：
检索区块链的当前状态，并确当前 tx pool 的状态在 chain 状态中有效。
 */
func (pool *TxPool) reset(oldHead, newHead *types.Header) {
	// If we're reorging an old state, reinject all dropped transactions
	//
	// todo
	//		如果我们要 重组 旧状态，请重新注入所有被丢弃的 tx
	// todo
	// 		这个是新旧 tx集中的差集
	var reinject types.Transactions

	// 条件为：
	// 旧的head 不为空，且不是 新Head 的 parent
	if oldHead != nil && oldHead.Hash() != newHead.ParentHash {
		// If the reorg is too deep, avoid doing it (will happen during fast sync)
		//如果重组的 链过于太深，则取消这样的操作 (可能会在 fast sync 模式下发生的情况)
		oldNum := oldHead.Number.Uint64()
		newNum := newHead.Number.Uint64()

		// 算出两者的 区块差值 (如果超过了 64 个块高，则跳过 重组)
		if depth := uint64(math.Abs(float64(oldNum) - float64(newNum))); depth > 64 {
			log.Debug("Skipping deep transaction reorg", "depth", depth)
		} else {
			// Reorg seems shallow enough to pull in all transactions into memory
			// 重组如果比较浅，则将所有 tx 都存入内存中

			// discarded: 收集被丢弃的 tx (丢弃集)
			// included: 收集被保留的 tx (保留集)
			var discarded, included types.Transactions

			// todo 分别获取 旧的和新的最高块
			var (
				rem = pool.chain.GetBlock(oldHead.Hash(), oldHead.Number.Uint64())
				add = pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
			)
			/**
			todo
				往前 重组
			 */
			// 如果 旧的最高块 > 新的最高块
			// 则，说明链 往前重组
			// 需要将该旧块的所有 tx收集到 丢弃集
			for rem.NumberU64() > add.NumberU64() {
				discarded = append(discarded, rem.Transactions()...)
				// 往前找下一个旧有块
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
			}

			/**
			todo
				往后 重组
			 */
			// new block num > old block num
			for add.NumberU64() > rem.NumberU64() {
				included = append(included, add.Transactions()...)
				// 根据 new block 往前 pre new block
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}

			// todo 最终不管是往前找还是往后找
			// 		代码到了这一步 rem 和 add 的块高已经为一样了
			// TODO 如果 块高一样但是Hash 不一样，
			// 		说明分叉了, 则,双方都继续往前找
			// 		直到找到 块高和 Hash都一样为止
			for rem.Hash() != add.Hash() {
				// 把旧有的块的tx都收集到 丢弃集中
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
				// 把新块的tx都收集到 保留集中
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			// todo 最后对比 求差集 (在旧中，而不在新中的 tx)
			reinject = types.TxDifference(discarded, included)
		}
	}
	// Initialize the internal state to the current head
	//
	// 获取当前链上的 最高块的最新 state
	if newHead == nil {
		newHead = pool.chain.CurrentBlock().Header() // Special case during testing   测试期间的特殊情况
	}
	statedb, err := pool.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset txpool state", "err", err)
		return
	}

	// todo 更新 txpool 记录的state 状态
	// 		更新 pool的 currentState 和 pendingState 为 当前链上最高块的 state
	// 		及更新pool中记录的当前 maxGas (用当前链上最高块的 GasLimit)
	pool.currentState = statedb
	pool.pendingState = state.ManageState(statedb)
	pool.currentMaxGas = newHead.GasLimit

	// Inject any transactions discarded due to reorgs
	//
	// todo
	// 	注入因reorgs而丢弃的任何 txs
	// 	重新注入 因为 重组而丢弃的tx (也就是之前 的  reinject (差集) 中的 tx)
	log.Debug("Reinjecting stale transactions", "count", len(reinject))
	/**
	todo
		【关键】
		对所有 reinject 中的tx进行重新签名
	 */
	senderCacher.recover(pool.signer, reinject)
	/**
	todo
		【关键】
		重新将tx 加入到 queue 或者 pending中
	 */
	pool.addTxsLocked(reinject, false)

	// validate the pool of pending transactions, this will remove
	// any transactions that have been included in the block or
	// have been invalidated because of another transaction (e.g.
	// higher gas price)
	/**
	验证待处理交易池(pending队列)，
	这将删除已包含在块中或由于另一交易而无效的任何交易（例如，更高的 gasPrice）
	 */
	pool.demoteUnexecutables()

	// Update all accounts to the latest known pending nonce
	// 将所有帐户更新为最新的已知待处理的nonce
	// 即：遍历 pending，逐个处理 addr的 tx list
	for addr, list := range pool.pending {
		// 对 tx list构建 构建一个 根据 nonce 从小到大的 排序的 cache，并返回 cache中的tx
		// 即：获取按照 nonce 排好序的tx
		txs := list.Flatten() // Heavy but will be cached and is needed by the miner anyway   虽然很重但是会被缓存，而且无论如何都需要矿工
		// 预先对nonce 做 +1 处理 (其实这个是 对下一次发过来的 tx 所需要的值，在这里预先设定了)
		pool.pendingState.SetNonce(addr, txs[len(txs)-1].Nonce()+1)
	}
	// Check the queue and move transactions over to the pending if possible
	// or remove those that have become invalid
	/** 检查 queue 队列 并尽可能将tx 移至 pending 队列，或删除已失效的 tx */
	pool.promoteExecutables(nil)
}

// Stop terminates the transaction pool.
func (pool *TxPool) Stop() {
	// Unsubscribe all subscriptions registered from txpool
	pool.scope.Close()

	// Unsubscribe subscriptions registered from blockchain
	pool.chainHeadSub.Unsubscribe()
	pool.wg.Wait()

	if pool.journal != nil {
		pool.journal.close()
	}
	log.Info("Transaction pool stopped")
}

// SubscribeNewTxsEvent registers a subscription of NewTxsEvent and
// starts sending event to the given channel.
func (pool *TxPool) SubscribeNewTxsEvent(ch chan<- NewTxsEvent) event.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

// GasPrice returns the current gas price enforced by the transaction pool.
func (pool *TxPool) GasPrice() *big.Int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return new(big.Int).Set(pool.gasPrice)
}

// SetGasPrice updates the minimum price required by the transaction pool for a
// new transaction, and drops all transactions below this threshold.
func (pool *TxPool) SetGasPrice(price *big.Int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.gasPrice = price
	for _, tx := range pool.priced.Cap(price, pool.locals) {
		pool.removeTx(tx.Hash(), false)
	}
	log.Info("Transaction pool price threshold updated", "price", price)
}

// State returns the virtual managed state of the transaction pool.
func (pool *TxPool) State() *state.ManagedState {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.pendingState
}

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.stats()
}

// stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
/**
stats函数：
检索当前池的统计信息，即pending的数量和 queue（非可执行）中的 tx 的数量。
 */
func (pool *TxPool) stats() (int, int) {
	pending := 0
	for _, list := range pool.pending {
		pending += list.Len()
	}
	queued := 0
	for _, list := range pool.queue {
		queued += list.Len()
	}
	return pending, queued
}

// Content retrieves the data content of the transaction pool, returning all the
// pending as well as queued transactions, grouped by account and sorted by nonce.
func (pool *TxPool) Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	queued := make(map[common.Address]types.Transactions)
	for addr, list := range pool.queue {
		queued[addr] = list.Flatten()
	}
	return pending, queued
}

// Pending retrieves all currently processable transactions, groupped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) Pending() (map[common.Address]types.Transactions, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	return pending, nil
}

// Locals retrieves the accounts currently considered local by the pool.
func (pool *TxPool) Locals() []common.Address {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.locals.flatten()
}

// local retrieves all currently known local transactions, groupped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) local() map[common.Address]types.Transactions {
	txs := make(map[common.Address]types.Transactions)
	for addr := range pool.locals.accounts {
		if pending := pool.pending[addr]; pending != nil {
			txs[addr] = append(txs[addr], pending.Flatten()...)
		}
		if queued := pool.queue[addr]; queued != nil {
			txs[addr] = append(txs[addr], queued.Flatten()...)
		}
	}
	return txs
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
func (pool *TxPool) validateTx(tx *types.Transaction, local bool) error {
	// Heuristic limit, reject transactions over 32KB to prevent DOS attacks
	//
	// 启发式限制，拒绝超过32KB的事务以防止DOS攻击
	if tx.Size() > 32*1024 {
		return ErrOversizedData
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur if you create a transaction using the RPC.
	//
	// 交易不能为负。 使用RLP解码的事务可能永远不会发生这种情况，
	// 但是如果您使用RPC创建事务，则可能会发生这种情况。
	//
	if tx.Value().Sign() < 0 {
		return ErrNegativeValue
	}
	// Ensure the transaction doesn't exceed the current block limit gas.
	//
	// 确保交易不超过当前的限制气体限额。
	if pool.currentMaxGas < tx.Gas() {
		return ErrGasLimit
	}
	// Make sure the transaction is signed properly
	from, err := types.Sender(pool.signer, tx)
	if err != nil {
		return ErrInvalidSender
	}
	// Drop non-local transactions under our own minimal accepted gas price
	local = local || pool.locals.contains(from) // account may be local even if the transaction arrived from the network
	if !local && pool.gasPrice.Cmp(tx.GasPrice()) > 0 {
		return ErrUnderpriced
	}
	// Ensure the transaction adheres to nonce ordering
	if pool.currentState.GetNonce(from) > tx.Nonce() {
		return ErrNonceTooLow
	}
	// Transactor should have enough funds to cover the costs
	// cost == V + GP * GL
	if pool.currentState.GetBalance(from).Cmp(tx.Cost()) < 0 {
		return ErrInsufficientFunds
	}
	intrGas, err := IntrinsicGas(tx.Data(), tx.To() == nil, pool.homestead)
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return ErrIntrinsicGas
	}
	return nil
}

// add validates a transaction and inserts it into the non-executable queue for
// later pending promotion and execution. If the transaction is a replacement for
// an already pending or queued one, it overwrites the previous and returns this
// so outer code doesn't uselessly call promote.
//
// If a newly added transaction is marked as local, its sending account will be
// whitelisted, preventing any associated transaction from being dropped out of
// the pool due to pricing constraints.
/**
add函数：
验证tx并将其插入到非可执行队列 queue中，
以便以后升级到 pending中去执行。
如果tx是已经在挂起或排队的tx的替代品，
即，tx之前就已经存在 pending或者queue中，
它将覆盖前一个一样的tx并返回之前的值，
因此外部代码不会无用地调用提升。

如果新添加的事务被标记为本地，
则其发送帐户将被列入白名单，
从而防止由于价格限制而将任何关联的 tx 从池中删除。

TODO :
	交易的来源包括p2p广播和本地节点rpc接收。当txpool接收到交易后，会对每笔交易进行一连串严格的检查

余额
nonce
交易Gas
签名
交易大小
交易value，等等
 */
func (pool *TxPool) add(tx *types.Transaction, local bool) (bool, error) {
	// If the transaction is already known, discard it
	// 如果交易已知，则将其丢弃
	hash := tx.Hash()
	if pool.all.Get(hash) != nil {
		log.Trace("Discarding already known transaction", "hash", hash)
		return false, fmt.Errorf("known transaction: %x", hash)
	}
	// If the transaction fails basic validation, discard it
	// 如果tx未通过基本验证，则将其丢弃
	if err := pool.validateTx(tx, local); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
		invalidTxCounter.Inc(1)
		return false, err
	}
	// If the transaction pool is full, discard underpriced transactions
	//
	// todo
	// 	如果 txpool 已满，则丢弃定价过低的tx
	// 	这里是查看 all 中的tx 数目哦 (GlobalSlots: 4096, 代表 pending中的最大数; GlobalQueue: 1024，代表 queue中的最大数)
	if uint64(pool.all.Count()) >= pool.config.GlobalSlots+pool.config.GlobalQueue {

		// If the new transaction is underpriced, don't accept it
		//
		// TODO 【重中之重】
		// 	如果新 tx 价格过低，则不接受
		// 	(本地 tx 不校验 price)
		if !local && pool.priced.Underpriced(tx, pool.locals) {
			log.Trace("Discarding underpriced transaction", "hash", hash, "price", tx.GasPrice())
			underpricedTxCounter.Inc(1)
			return false, ErrUnderpriced
		}
		// New transaction is better than our worse ones, make room for it
		//
		// todo
		// 	新交易比我们的交易更好，为它腾出空间 (移除 部分 远端tx, 保留本地tx)
		// 	all的总数 - (4096 + 1024 - 1)
		drop := pool.priced.Discard(pool.all.Count()-int(pool.config.GlobalSlots+pool.config.GlobalQueue-1), pool.locals)
		for _, tx := range drop {
			log.Trace("Discarding freshly underpriced transaction", "hash", tx.Hash(), "price", tx.GasPrice())
			underpricedTxCounter.Inc(1)

			// 从 txpool 的各个队列中 移除 tx
			pool.removeTx(tx.Hash(), false)
		}
	}


	// If the transaction is replacing an already pending one, do directly
	//
	//如果tx正在替换已经挂起的交易，请直接执行
	from, _ := types.Sender(pool.signer, tx) // already validated
	// 拿出当前 addr 的pending list
	// 并判断当前 tx 是否已经在 pending中了
	if list := pool.pending[from]; list != nil && list.Overlaps(tx) {

		// Nonce already pending, check if required price bump is met
		//
		// todo  【重中之重】
		// 		这里做  nonce 相同的 tx 替换  (替换指的是  替换 pending 中的tx)
		// 		Nonce已经挂起，检查是否满足所需的价格暴涨
		// 		PriceBump （默认为： 10）
		inserted, old := list.Add(tx, pool.config.PriceBump)
		// 如果新的tx 没有替换相同nonce 的旧tx，则直接抛弃
		if !inserted {
			// 统计计数 +1
			pendingDiscardCounter.Inc(1)
			return false, ErrReplaceUnderpriced
		}

		// New transaction is better, replace old one
		//
		// 如果 pending中，新的tx覆盖了旧的tx，这时候需要删除掉 all和priced中就交易相关的信息
		if old != nil {
			pool.all.Remove(old.Hash())
			pool.priced.Removed()
			pendingReplaceCounter.Inc(1)
		}
		// 并且在 all和 priced中追加 新tx信息
		pool.all.Add(tx)
		pool.priced.Put(tx)
		// 将属于本地账户的tx写入磁盘
		pool.journalTx(from, tx)

		log.Trace("Pooled new executable transaction", "hash", hash, "from", from, "to", tx.To())

		// We've directly injected a replacement transaction, notify subsystems
		// 广播 tx
		/** 【注意】只有是pending中的tx变化才会 广播事件哦 */
		go pool.txFeed.Send(NewTxsEvent{types.Transactions{tx}})

		// 返回，pending中是否有旧的 tx被新的tx覆盖
		return old != nil, nil
	}

	// New transaction isn't replacing a pending one, push into queue
	//
	// 如果新的tx没有去覆盖 pending中的 tx，则直接追加到queue中 todo 是 新tx
	replace, err := pool.enqueueTx(hash, tx)
	if err != nil {
		return false, err
	}


	// Mark local addresses and journal local transactions
	// todo 标识 本地addr 和本地 tx
	if local {
		// 把新的addr 追加到locals中
		if !pool.locals.contains(from) {
			log.Info("Setting new local account", "address", from)
			pool.locals.add(from)
		}
	}
	//  todo 将属于本地账户的tx写入磁盘
	pool.journalTx(from, tx)

	log.Trace("Pooled new future transaction", "hash", hash, "from", from, "to", tx.To())
	return replace, nil
}

// enqueueTx inserts a new transaction into the non-executable transaction queue.
//
// Note, this method assumes the pool lock is held!
/**
enqueueTx函数：
将新 tx插入到非可执行tx队列 queue中。

todo:  Pending —> Queue
 */
func (pool *TxPool) enqueueTx(hash common.Hash, tx *types.Transaction) (bool, error) {
	// Try to insert the transaction into the future queue
	//
	// 尝试的添加tx到 future queue中
	from, _ := types.Sender(pool.signer, tx) // already validated
	if pool.queue[from] == nil {
		pool.queue[from] = newTxList(false)
	}
	inserted, old := pool.queue[from].Add(tx, pool.config.PriceBump)
	// 是否替换了 queue中相同nonce 的就有 tx
	if !inserted {
		// An older transaction was better, discard this
		queuedDiscardCounter.Inc(1)
		return false, ErrReplaceUnderpriced
	}
	// Discard any previous transaction and mark this
	// 从all和priced中移除之前旧有的 tx
	if old != nil {
		pool.all.Remove(old.Hash())
		pool.priced.Removed()
		queuedReplaceCounter.Inc(1)
	}
	// 将新的tx追加到 all 和priced中
	if pool.all.Get(hash) == nil {
		pool.all.Add(tx)
		pool.priced.Put(tx)
	}
	// 返回是否替换 就有tx的标识位
	return old != nil, nil
}

// journalTx adds the specified transaction to the local disk journal if it is
// deemed to have been sent from a local account.
/**
ournalTx 函数：
如果认为指定的tx是从本地帐户发送的，则将指定的 tx添加到本地磁盘日志中。
 */
func (pool *TxPool) journalTx(from common.Address, tx *types.Transaction) {
	// Only journal if it's enabled and the transaction is local
	// 只写日志，如果它已启用且交易是本地的
	if pool.journal == nil || !pool.locals.contains(from) {
		return
	}
	if err := pool.journal.insert(tx); err != nil {
		log.Warn("Failed to journal local transaction", "err", err)
	}
}

// promoteTx adds a transaction to the pending (processable) list of transactions
// and returns whether it was inserted or an older was better.
//
// Note, this method assumes the pool lock is held!
/**
【注意】 这个超重要
promoteTx函数：
将一个tx添加到pending队列中，并返回它是否 新插入的 还是覆盖了就有的 标识位。

注意，此方法假定 池锁是一直被持有状态的！

todo:  Queue —> Pending
 */
func (pool *TxPool) promoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) bool {
	// Try to insert the transaction into the pending queue
	// 试着将一个 tx插入到 pending 队列
	if pool.pending[addr] == nil {
		pool.pending[addr] = newTxList(true)
	}
	list := pool.pending[addr]

	inserted, old := list.Add(tx, pool.config.PriceBump)
	if !inserted {
		// An older transaction was better, discard this
		pool.all.Remove(hash)
		pool.priced.Removed()

		pendingDiscardCounter.Inc(1)
		return false
	}
	// Otherwise discard any previous transaction and mark this
	if old != nil {
		pool.all.Remove(old.Hash())
		pool.priced.Removed()

		pendingReplaceCounter.Inc(1)
	}
	// Failsafe to work around direct pending inserts (tests)
	if pool.all.Get(hash) == nil {
		pool.all.Add(tx)
		pool.priced.Put(tx)
	}
	// Set the potentially new pending nonce and notify any subsystems of the new tx
	pool.beats[addr] = time.Now()
	pool.pendingState.SetNonce(addr, tx.Nonce()+1)

	return true
}

// AddLocal enqueues a single transaction into the pool if it is valid, marking
// the sender as a local one in the mean time, ensuring it goes around the local
// pricing constraints.
func (pool *TxPool) AddLocal(tx *types.Transaction) error {
	return pool.addTx(tx, !pool.config.NoLocals)
}

// AddRemote enqueues a single transaction into the pool if it is valid. If the
// sender is not among the locally tracked ones, full pricing constraints will
// apply.
//
// 添加 [单个] 远端 tx
// 即: p2p 广播过来的 tx
// 如果有效，AddRemote会将单个事务排队入池。 如果sender不在本地跟踪的发件人之内，则将适用全部价格限制。
// 即: 远端交易是需要校验 gasPrice 的
func (pool *TxPool) AddRemote(tx *types.Transaction) error {
	return pool.addTx(tx, false)
}

// AddLocals enqueues a batch of transactions into the pool if they are valid,
// marking the senders as a local ones in the mean time, ensuring they go around
// the local pricing constraints.
//
// 如果有效，`AddLocals`会将一批交易排队入池，同时将 senders 为本地交易，todo 以确保它们绕过 本地 gasPrice 约束
func (pool *TxPool) AddLocals(txs []*types.Transaction) []error {
	return pool.addTxs(txs, !pool.config.NoLocals)
}

// AddRemotes enqueues a batch of transactions into the pool if they are valid.
// If the senders are not among the locally tracked ones, full pricing constraints
// will apply.
//
// 如果有效，`AddRemotes`将一批事务排队入池。 如果 senders 不在本地跟踪的发件人之内，则将适用全部价格限制。
//
// 逻辑 和  `AddRemote` 一样
func (pool *TxPool) AddRemotes(txs []*types.Transaction) []error {
	return pool.addTxs(txs, false)
}

// addTx enqueues a single transaction into the pool if it is valid.
/**
【注意】
对单个tx进行校验，通过后追加到pool中
 */
func (pool *TxPool) addTx(tx *types.Transaction, local bool) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Try to inject the transaction and update any state
	//
	// 尝试去把当前tx 注入到pool中，并且更新相关状态信息 【对tx的校验在这个方法中哦】
	// todo replace 表示 pending/queue 中是否有相同nonce值的旧有 tx被新的tx覆盖
	replace, err := pool.add(tx, local)
	if err != nil {
		return err
	}
	// If we added a new transaction, run promotion checks and return
	// 如果我们已经添加了一个新交易 (及不是替换pending/queue中的旧有的tx )，那么调用 promoteExecutables (提升可执行) 检查且返回结果
	if !replace {
		from, _ := types.Sender(pool.signer, tx) // already validated  tx在这里已经是被校验过的了
		// 提升 tx 的位置 (说白了就是 经过校验之后 从 queue中 转移到 pending 中)
		pool.promoteExecutables([]common.Address{from})
	}
	return nil
}

// addTxs attempts to queue a batch of transactions if they are valid.
func (pool *TxPool) addTxs(txs []*types.Transaction, local bool) []error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.addTxsLocked(txs, local)
}

// addTxsLocked attempts to queue a batch of transactions if they are valid,
// whilst assuming the transaction pool lock is already held.
//
// todo addTxsLocked:
// 		尝试将一批 tx（如果有效）加入队列中，同时假定 txpool 锁已被持有。
func (pool *TxPool) addTxsLocked(txs []*types.Transaction, local bool) []error {

	// Add the batch of transaction, tracking the accepted ones
	//
	// 添加交易批次，跟踪已接受的交易
	dirty := make(map[common.Address]struct{})
	errs := make([]error, len(txs))

	for i, tx := range txs {

		var replace bool
		if replace, errs[i] = pool.add(tx, local); errs[i] == nil && !replace {
			from, _ := types.Sender(pool.signer, tx) // already validated
			dirty[from] = struct{}{}
		}
	}
	// Only reprocess the internal state if something was actually added
	//
	// 如果确实添加了某些内容，则仅重新处理内部状态
	if len(dirty) > 0 {
		addrs := make([]common.Address, 0, len(dirty))
		for addr := range dirty {
			addrs = append(addrs, addr)
		}

		// 执行 tx 升级
		pool.promoteExecutables(addrs)
	}
	return errs
}

// Status returns the status (unknown/pending/queued) of a batch of transactions
// identified by their hashes.
func (pool *TxPool) Status(hashes []common.Hash) []TxStatus {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	status := make([]TxStatus, len(hashes))
	for i, hash := range hashes {
		if tx := pool.all.Get(hash); tx != nil {
			from, _ := types.Sender(pool.signer, tx) // already validated
			if pool.pending[from] != nil && pool.pending[from].txs.items[tx.Nonce()] != nil {
				status[i] = TxStatusPending
			} else {
				status[i] = TxStatusQueued
			}
		}
	}
	return status
}

// Get returns a transaction if it is contained in the pool
// and nil otherwise.
func (pool *TxPool) Get(hash common.Hash) *types.Transaction {
	return pool.all.Get(hash)
}

// removeTx removes a single transaction from the queue, moving all subsequent
// transactions back to the future queue.
// removeTx函数：
// 从 pending 队列中删除单个tx，将所有连串的tx移回到 future queue 中。
//
// todo 将pending中的 nonce-gap 的tx 从pending移除到 queue中
func (pool *TxPool) removeTx(hash common.Hash, outofbound bool) {
	// Fetch the transaction we wish to delete
	// todo 获取我们要删除的交易 （从all中获取）
	tx := pool.all.Get(hash)
	if tx == nil { // 如果已经不存在 all 中了，则直接结束 该func calling
		return
	}

	// 已在插入期间验证过了 从tx 中恢复 from
	addr, _ := types.Sender(pool.signer, tx) // already validated during insertion

	// Remove it from the list of known transactions
	/**
	todo 【一】
	todo 从 all 队列中移除该tx
	 */
	pool.all.Remove(hash)
	// 是否超越了 边界
	if outofbound {
		// 是， 则自判断调整 最小堆
		pool.priced.Removed()
	}
	// Remove the transaction from the pending lists and reset the account nonce
	/**
	todo 【二】
	todo 从 pending 列表中删除该 tx 并重置该帐户nonce
	 */
	if pending := pool.pending[addr]; pending != nil {
		/**
		todo 从 pending中移除 tx
			removed：tx是否被移除标识
			invalids：nonce比 removed 中的tx还大的 tx (间接被从 pending中移除的)
		 */
		if removed, invalids := pending.Remove(tx); removed {
			// If no more pending transactions are left, remove the list
			//
			//如果该 addr 的 pending tx list 为空，则删除掉该 tx list
			if pending.Empty() {
				// pending 队列中移除
				delete(pool.pending, addr)
				// 心跳队列中移除
				delete(pool.beats, addr)
			}
			// Postpone any invalidated transactions
			//
			// 将 invalids 中的交易追加到 queue 队列中
			for _, tx := range invalids {
				pool.enqueueTx(tx.Hash(), tx)
			}

			// Update the account nonce if needed
			//
			// 如果需要的话，则更新该addr 在state中的 nonce
			// 条件： 当前state 中该addr 的nonce > 当前 tx 的 nonce，
			// 则需要用当前 tx的nonce 重置 state的nonce
			if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
				pool.pendingState.SetNonce(addr, nonce)
			}

			return
		}
	}
	// Transaction is in the future queue
	/**
	todo 【三】
	todo 最后再一次 确保把queue中的当前tx 移除掉
	 */
	if future := pool.queue[addr]; future != nil {
		future.Remove(tx)
		if future.Empty() {
			delete(pool.queue, addr)
		}
	}
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
/**
promoteExecutables函数：
【这个是和 demoteUnexecutables 函数对立的一个函数】
将已经可以处理的 tx 从 future队列移动到 pending 队列中。
在此过程中，将删除所有无效的事务（低nonce，低余额）。
 */
func (pool *TxPool) promoteExecutables(accounts []common.Address) {
	// Track the promoted transactions to broadcast them at once
	// 跟踪 promoted（可以被提升转移的）的交易以立即广播它们
	// 说白了，就是收集 所有已经被 提升的tx (就是被转移到 pending中)
	var promoted []*types.Transaction

	// Gather all the accounts potentially needing updates
	// 收集可能需要更新的所有帐户
	if accounts == nil {
		accounts = make([]common.Address, 0, len(pool.queue))
		// 遍历 queue 队列，收集所有 addr (tx  from)，因为 tx 一开始进来的就是在 queue 中
		for addr := range pool.queue {
			accounts = append(accounts, addr)
		}
	}
	// Iterate over all accounts and promote any executable transactions
	// 迭代所有 被收集起来的addr 和 promoted（可以被提升转移的）任何可执行 tx
	for _, addr := range accounts {
		/**
		【注意】：先拿出当前账户在queue 中的 tx list
		 */
		list := pool.queue[addr]
		if list == nil {
			continue // 防止有些人操作不存在的 账户
		}
		// Drop all transactions that are deemed too old (low nonce)
		// 删除所有被认为太旧的交易（低nonce）
		// 遍历所有 Forward 出来的 被删除的 tx
		for _, tx := range list.Forward(pool.currentState.GetNonce(addr)) {
			hash := tx.Hash()
			log.Trace("Removed old queued transaction", "hash", hash)
			// 根据 Hash 从all中清除
			pool.all.Remove(hash)
			// 自判断方法，根据最新的 tx map 构建新的 tx 最小堆
			pool.priced.Removed()
		}
		// Drop all transactions that are too costly (low balance or out of gas)
		// 删除所有成本过高的交易（低余额或 gas 不足；这里的成本过高，是指 超出了账户自身所能承受与的价格）
		// 过滤掉非法的交易
		// 入参为：当前账户的 余额 和当前pool中规定的 MaxGas
		drops, _ := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		// 遍历 由于不够支付 金额或者gas而被删除掉的txs
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable queued transaction", "hash", hash)

			// 将对应的tx从 all(存储所有交易的池)中移除
			pool.all.Remove(hash)
			// 自判断去调整最小堆
			pool.priced.Removed()
			queuedNofundsCounter.Inc(1) // 无需管，就是一个统计的
		}
		// Gather all executable transactions and promote them
		// 获取所有可以被执行的(通过了各种校验的 tx) 去提升他们的身份(即转移到 pending队列中)
		for _, tx := range list.Ready(pool.pendingState.GetNonce(addr)) {
			hash := tx.Hash()
			/**
			【注意】 这个超重要
			 */
			if pool.promoteTx(addr, hash, tx) {
				log.Trace("Promoting queued transaction", "hash", hash)
				// 收集被提升到 pending 中的tx
				promoted = append(promoted, tx)
			}
		}
		// Drop all transactions over the allowed limit
		// 删除超出允许限制 (单个账户的 tx 数量硬限制)的 tx
		// 如果当前账户不在 locals 里面，则才做的操作
		// 注意：list 是queue中的一个指针哦
		if !pool.locals.contains(addr) {
			// 默认的 AccountQueue是 64
			for _, tx := range list.Cap(int(pool.config.AccountQueue)) {
				hash := tx.Hash()
				// 将对应的tx从 all(存储所有交易的池)中移除
				pool.all.Remove(hash)
				// 自判断去调整最小堆
				pool.priced.Removed()
				// 计数统计
				queuedRateLimitCounter.Inc(1)
				log.Trace("Removed cap-exceeding queued transaction", "hash", hash)
			}
		}

		// Delete the entire queue entry if it became empty.
		// 如果整个 tx list 变空，则将其从 queue中移除删除它。queue 是个 map [addr]list
		if list.Empty() {
			delete(pool.queue, addr)
		}
	}
	// Notify subsystem for new promoted transactions.
	// 通知子系统 （下游的事件 订阅者,如 peermanager 和 worker）以获取新的 tx
	if len(promoted) > 0 {
		/** 【注意】只有是pending中的tx变化才会 广播事件哦 */
		go pool.txFeed.Send(NewTxsEvent{promoted})
	}
	/**
	【处理 pending 队列】
	 */
	// If the pending limit is overflown, start equalizing allowances
	// 如果 pending 队列超出限制，则开始 做调整
	// 记录pending中所有账户所有交易数量 (总交易数量)
	pending := uint64(0)
	for _, list := range pool.pending {
		// 逐个累加各个账户的 tx list的长度
		pending += uint64(list.Len())
	}
	// 默认 GlobalSlots 为 4096
	// 如果总tx 超过了 4096笔
	if pending > pool.config.GlobalSlots {
		// 先记录下当前pending中的总 tx数目
		pendingBeforeCap := pending
		// Assemble a spam order to penalize large transactors first
		// 组装一个 优先级队列，用于删除超出的tx
		spammers := prque.New()
		// 遍历 pending
		for addr, list := range pool.pending {
			// Only evict transactions from high rollers
			// 只会删除 list长度大的
			// 如果addr 不在locals中
			// 且 其tx list 长度大于 AccountSlots
			// （AccountSlots 默认为 16）
			if !pool.locals.contains(addr) && uint64(list.Len()) > pool.config.AccountSlots {
				// 将 addr 及tx list len 作为优先级 加入 优先级队列
				spammers.Push(addr, float32(list.Len()))
			}
		}
		// Gradually drop transactions from offenders
		// 逐个删除 不符合的 tx
		// 收集 优先级队列中拿出来的 addr
		offenders := []common.Address{}

		// 如果 pending 还是大于 GlobalSlots (默认：4096)
		// 且优先级队列 不为空
		// 则按照优先级 pop出addr 来逐个处理
		for pending > pool.config.GlobalSlots && !spammers.Empty() {
			// Retrieve the next offender if not local address
			// 从优先级队列中取出不属于在 locals中的adrr （上面把 不属于locals中的addr 放进优先级队列的）
			offender, _ := spammers.Pop()
			// 收集起来
			offenders = append(offenders, offender.(common.Address))

			// Equalize balances until all the same or below threshold
			// 调整余额直到所有相同或低于阈值
			if len(offenders) > 1 {
				// Calculate the equalization threshold for all current offenders
				// 计算所有当前违规者 （addr）的均衡阈值
				threshold := pool.pending[offender.(common.Address)].Len()

				// Iteratively reduce all offenders until below limit or threshold reached
				// 迭代地减少所有违规者，直到达到限制或阈值
				// 如果 pending 的数目 仍然 大于 GlobalSlots (默认： 4096)
				// 且 offenders 数组中倒数第二个addr 对应的tx list len 大于 当前处理的addr (offender, _ := spammers.Pop() 中弹出来的)
				// 说白了，就是当前addr 的上一个addr 的tx list len 大于 当前 tx list len
				for pending > pool.config.GlobalSlots && pool.pending[offenders[len(offenders)-2]].Len() > threshold {
					// 遍历 处理offenders 数组中的所有 tx list
					for i := 0; i < len(offenders)-1; i++ {
						list := pool.pending[offenders[i]]
						// 处理当前addr 的tx list
						for _, tx := range list.Cap(list.Len() - 1) {
							// Drop the transaction from the global pools too
							// 从全局的 all 池子中删除掉 该tx， 并自判断调整 最小堆
							hash := tx.Hash()
							pool.all.Remove(hash)
							pool.priced.Removed()

							// Update the account nonce to the dropped transaction
							// 用删除掉的tx的nonce去更新 当前addr 的stateDB中的 nonce
							if nonce := tx.Nonce(); pool.pendingState.GetNonce(offenders[i]) > nonce {
								pool.pendingState.SetNonce(offenders[i], nonce)
							}
							log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
						}
						// 我擦 为甚在 for tx 外面 -- ？
						pending--
					}
				}
			}
		}
		// If still above threshold, reduce to limit or min allowance
		// 如果仍然高于 阈值，减少到限制或最小限额
		if pending > pool.config.GlobalSlots && len(offenders) > 0 {
			// 继续重复上面的操作
			for pending > pool.config.GlobalSlots && uint64(pool.pending[offenders[len(offenders)-1]].Len()) > pool.config.AccountSlots {
				for _, addr := range offenders {
					list := pool.pending[addr]
					for _, tx := range list.Cap(list.Len() - 1) {
						// Drop the transaction from the global pools too
						hash := tx.Hash()
						pool.all.Remove(hash)
						pool.priced.Removed()

						// Update the account nonce to the dropped transaction
						if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
							pool.pendingState.SetNonce(addr, nonce)
						}
						log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
					}
					pending--
				}
			}
		}
		// 最后计数
		pendingRateLimitCounter.Inc(int64(pendingBeforeCap - pending))
	}
	/**
	【处理 queue 队列】
	 */
	// If we've queued more transactions than the hard limit, drop oldest ones
	// 如果我们排队了比硬限制更多的交易，则删除最旧的交易 (这里是处理 queue 队列)
	queued := uint64(0)
	for _, list := range pool.queue {
		queued += uint64(list.Len())
	}
	// 如果挡圈 queue 中的 tx list len 大于 GlobalQueue
	// GlobalQueue 默认 1024
	if queued > pool.config.GlobalQueue {
		// Sort all accounts with queued transactions by heartbeat
		// 按心跳排序所有具有排队事务的帐户
		/**  用来记录一个tx被滞留在 queue中的时间 */
		addresses := make(addressesByHeartbeat, 0, len(pool.queue))

		// 遍历queue 收集所有不在locals中的 addr
		for addr := range pool.queue {
			if !pool.locals.contains(addr) { // don't drop locals
				addresses = append(addresses, addressByHeartbeat{addr, pool.beats[addr]})
			}
		}
		// 随便排了个序
		sort.Sort(addresses)

		// Drop transactions until the total is below the limit or only locals remain
		// 删除交易，直到总数低于限额或仅 剩余 locals中的addr保留在 queue中
		// 如果 queue中的所有交易 > GlobalQueue （默认： 1024）且 收集queue中非locals 的addr 的数组还有addr
		for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
			// 先取最后一个 addr 及其对应的 tx list
			addr := addresses[len(addresses)-1]
			list := pool.queue[addr.address]

			// 保留剩余的
			addresses = addresses[:len(addresses)-1]

			// Drop all transactions if they are less than the overflow
			// 如果它们小于溢出，则删除所有事务
			/**
			如果当前 addr 的 tx list 数量小于 当前溢出的值 (drop := queued - pool.config.GlobalQueue)
			则，需要把这些 tx 移除
			 */
			if size := uint64(list.Len()); size <= drop {
				// 奖items 中的tx 排好序且做cache，并返回 items 中的tx
				for _, tx := range list.Flatten() {
					// 入参 outofbound，是否超越了边界
					pool.removeTx(tx.Hash(), true)
				}
				// 统计
				drop -= size
				queuedRateLimitCounter.Inc(int64(size))
				continue
			}
			// Otherwise drop only last few transactions
			// 否则只丢弃最后几笔交易
			txs := list.Flatten()
			for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
				pool.removeTx(txs[i].Hash(), true)
				drop--
				queuedRateLimitCounter.Inc(1)
			}
		}
	}
}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
/**
demoteUnexecutables 函数：
【这个是和 promoteExecutables 函数对立的一个函数】
从池 executable/ pending队列中删除无效和已被处理的tx，
并且任何变为不可执行的后续事务都将移回到 future queue [就是 queue中] 中。
 */
func (pool *TxPool) demoteUnexecutables() {
	// Iterate over all accounts and demote any non-executable transactions
	// 遍历 所有pending中的tx，把不可执行的全部降级
	for addr, list := range pool.pending {
		nonce := pool.currentState.GetNonce(addr)

		/** TODO 处理 nonce too low 的交易 */
		// Drop all transactions that are deemed too old (low nonce)
		for _, tx := range list.Forward(nonce) {
			hash := tx.Hash()
			log.Trace("Removed old pending transaction", "hash", hash)
			pool.all.Remove(hash)
			pool.priced.Removed()
		}


		/** TODO 处理 余额不足的 交易 */
		// Drop all transactions that are too costly (low balance or out of gas), and queue any invalids back for later
		// 删除所有成本过高的交易（低余额或 gas 不足；这里的成本过高，是指 超出了账户自身所能承受与的价格）
		// 并且将任何 失效的 （这里的失效是指 返回的：invalids 也就是收到 drops 的影响而 移除的 tx ）tx 组装到queue中以备日后使用
		// 入参为当前账户的 余额 和 pool的 MaxGas
		//
		// todo drops: 需要从all 中移除的 txs
		// todo invalids: 需要从 pending中转移到 queue 中的 txs
		drops, invalids := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		// 遍历 由于不够支付 金额或者gas而被删除掉的txs
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable pending transaction", "hash", hash)
			// 将对应的tx从 all(存储所有交易的池)中移除
			pool.all.Remove(hash)
			// 自判断去调整最小堆
			pool.priced.Removed()
			pendingNofundsCounter.Inc(1)
		}
		// 遍历所有 收到drops 影响的 tx
		for _, tx := range invalids {
			hash := tx.Hash()
			log.Trace("Demoting pending transaction", "hash", hash)
			// 重新转移到 queue 中
			pool.enqueueTx(hash, tx)
		}
		// If there's a gap in front, alert (should never happen) and postpone all transactions
		// 如果前面有差距，请提醒（这种情况应该绝不会发生）并推迟所有tx
		// 就是说，如果当前 addr 的pending中的 tx list 不为空，
		// 且根据当前 state中该账户的 nonce 去该 tx list 中找不到对应的 tx 时
		if list.Len() > 0 && list.txs.Get(nonce) == nil {
			// 返回当前list 中所有大于 硬限制 threshold (这里的 threshold 指的是 list的items中所存储的 tx数量) 的tx
			// 这里传0 说白了，就是要拿之前在 items (被维护在 items 中 (items：nonce -> tx)的所有 tx)
			// 全部都拿出来，丢到 queue 中
			for _, tx := range list.Cap(0) {
				hash := tx.Hash()
				log.Error("Demoting invalidated transaction", "hash", hash)
				pool.enqueueTx(hash, tx)
			}
		}
		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			delete(pool.pending, addr)
			delete(pool.beats, addr)
		}
	}
}

// addressByHeartbeat is an account address tagged with its last activity timestamp.
// addressByHeartbeat 是一个标记有上一个活动时间戳的帐户地址。
/** 用来记录一个tx 被滞留在 queue中的时间 */
type addressByHeartbeat struct {
	address   common.Address
	heartbeat time.Time
}

type addressesByHeartbeat []addressByHeartbeat

func (a addressesByHeartbeat) Len() int           { return len(a) }
func (a addressesByHeartbeat) Less(i, j int) bool { return a[i].heartbeat.Before(a[j].heartbeat) }
func (a addressesByHeartbeat) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// accountSet is simply a set of addresses to check for existence, and a signer
// capable of deriving addresses from transactions.
type accountSet struct {
	accounts map[common.Address]struct{}
	signer   types.Signer
	cache    *[]common.Address
}

// newAccountSet creates a new address set with an associated signer for sender
// derivations.
func newAccountSet(signer types.Signer) *accountSet {
	return &accountSet{
		accounts: make(map[common.Address]struct{}),
		signer:   signer,
	}
}

// contains checks if a given address is contained within the set.
// 检查集合中是否包含给定地址
func (as *accountSet) contains(addr common.Address) bool {
	_, exist := as.accounts[addr]
	return exist
}

// containsTx checks if the sender of a given tx is within the set. If the sender
// cannot be derived, this method returns false.
/**
containsTx 函数：
检查给定tx的发送方是否在locals集合内。 如果sender无非恢复 tx 中的 from，则此方法直接返回false。
 */
func (as *accountSet) containsTx(tx *types.Transaction) bool {
	if addr, err := types.Sender(as.signer, tx); err == nil {
		// 判断 tx的发起者是否属于 locals中
		return as.contains(addr)
	}
	return false
}

// add inserts a new address into the set to track.
func (as *accountSet) add(addr common.Address) {
	as.accounts[addr] = struct{}{}
	as.cache = nil
}

// flatten returns the list of addresses within this set, also caching it for later
// reuse. The returned slice should not be changed!
func (as *accountSet) flatten() []common.Address {
	if as.cache == nil {
		accounts := make([]common.Address, 0, len(as.accounts))
		for account := range as.accounts {
			accounts = append(accounts, account)
		}
		as.cache = &accounts
	}
	return *as.cache
}

// txLookup is used internally by TxPool to track transactions while allowing lookup without
// mutex contention.
//
// Note, although this type is properly protected against concurrent access, it
// is **not** a type that should ever be mutated or even exposed outside of the
// transaction pool, since its internal state is tightly coupled with the pools
// internal mechanisms. The sole purpose of the type is to permit out-of-bound
// peeking into the pool in TxPool.Get without having to acquire the widely scoped
// TxPool.mu mutex.
type txLookup struct {
	all  map[common.Hash]*types.Transaction
	lock sync.RWMutex
}

// newTxLookup returns a new txLookup structure.
func newTxLookup() *txLookup {
	return &txLookup{
		all: make(map[common.Hash]*types.Transaction),
	}
}

// Range calls f on each key and value present in the map.
// 遍历map中的 k-v 并逐个调用 入参函数 f()
func (t *txLookup) Range(f func(hash common.Hash, tx *types.Transaction) bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	for key, value := range t.all {
		// 只要有一个调用失败，就中断
		if !f(key, value) {
			break
		}
	}
}

// Get returns a transaction if it exists in the lookup, or nil if not found.
func (t *txLookup) Get(hash common.Hash) *types.Transaction {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.all[hash]
}

// Count returns the current number of items in the lookup.
func (t *txLookup) Count() int {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return len(t.all)
}

// Add adds a transaction to the lookup.
func (t *txLookup) Add(tx *types.Transaction) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.all[tx.Hash()] = tx
}

// Remove removes a transaction from the lookup.
func (t *txLookup) Remove(hash common.Hash) {
	t.lock.Lock()
	defer t.lock.Unlock()

	delete(t.all, hash)
}
