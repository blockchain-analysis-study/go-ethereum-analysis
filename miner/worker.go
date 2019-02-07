// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"go-ethereum/common"
	"go-ethereum/consensus"
	"go-ethereum/consensus/misc"
	"go-ethereum/core"
	"go-ethereum/core/state"
	"go-ethereum/core/types"
	"go-ethereum/core/vm"
	"go-ethereum/event"
	"go-ethereum/log"
	"go-ethereum/params"
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	/** resultQueueSize是监听密封结果的通道大小 */
	resultQueueSize = 10

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	/**
	txChanSize是侦听NewTxsEvent的通道大小。
	该数字是从tx池的大小引用的。
	*/
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	/** chainHeadChanSize是侦听ChainHeadEvent的通道的大小。 */
	chainHeadChanSize = 10

	// chainSideChanSize is the size of channel listening to ChainSideEvent.
	/**  chainSideChanSize是侦听ChainSideEvent的通道的大小。*/
	chainSideChanSize = 10

	// resubmitAdjustChanSize is the size of resubmitting interval adjustment channel.
	/** resubmitAdjustChanSize是重新提交间隔调整通道的大小  */
	resubmitAdjustChanSize = 10

	// miningLogAtDepth is the number of confirmations before logging successful mining.
	/** miningLogAtDepth是记录成功挖掘之前的确认数。 */
	miningLogAtDepth = 5

	// minRecommitInterval is the minimal time interval to recreate the mining block with
	// any newly arrived transactions.
	/**
	minRecommitInterval 是使用任何新到达的事务重新创建挖掘块的最小时间间隔。
	*/
	minRecommitInterval = 1 * time.Second

	// maxRecommitInterval is the maximum time interval to recreate the mining block with
	// any newly arrived transactions.
	/**
	maxRecommitInterval是使用任何新到达的事务重新创建挖掘块的最大时间间隔。
	 */
	maxRecommitInterval = 15 * time.Second

	// intervalAdjustRatio is the impact a single interval adjustment has on sealing work
	// resubmitting interval.
	/**
	intervalAdjustRatio是单个间隔调整对密封工作重新提交间隔的影响。
	 */
	intervalAdjustRatio = 0.1

	// intervalAdjustBias is applied during the new resubmit interval calculation in favor of
	// increasing upper limit or decreasing lower limit so that the limit can be reachable.
	/**
	在新的重新提交间隔计算期间应用intervalAdjustBias，有利于增加上限或减少下限，以便可以访问限制。
	 */
	intervalAdjustBias = 200 * 1000.0 * 1000.0
)

// environment is the worker's current environment and holds all of the current state information.
/**
environment是 worker 的当前环境并保存所有当前state信息。
 */
type environment struct {
	/** 当前签名者 */
	signer types.Signer

	/** 在此处应用 state 更改 */
	state     *state.StateDB // apply state changes here
	/** 祖先集（用于检查叔叔父有效性） */
	ancestors mapset.Set     // ancestor set (used for checking uncle parent validity)
	/** 家庭集（用于检查叔叔无效） */
	family    mapset.Set     // family set (used for checking uncle invalidity)
	/** 叔叔集 */
	uncles    mapset.Set     // uncle set
	/** tx在循环中计数 */
	tcount    int            // tx count in cycle
	/** 用于包装tx的可用 gas */
	gasPool   *core.GasPool  // available gas used to pack transactions

	/** 当前正在打包的 block header */
	header   *types.Header
	/** 当前正在打包的 block 的tx 集 */
	txs      []*types.Transaction
	/** 当前正在打包的 block 的收据集 */
	receipts []*types.Receipt
}

// task contains all information for consensus engine sealing and result submitting.
/**
task 包含共识引擎 打包 和结果提交的所有信息。
 */
type task struct {
	// 收据集
	receipts  []*types.Receipt
	// 当前 state
	state     *state.StateDB
	// 当前block
	block     *types.Block
	// 当前打包的 时间戳
	createdAt time.Time
}

const (
	/**
	三个 标识位
	 */

	commitInterruptNone int32 = iota
	commitInterruptNewHead
	commitInterruptResubmit
)

// newWorkReq represents a request for new sealing work submitting with relative interrupt notifier.
// newWorkReq 表示使用相对中断通知程序提交新密封工作的请求
type newWorkReq struct {
	// 打断标识
	interrupt *int32
	// 非空标识
	noempty   bool
}

// intervalAdjust represents a resubmitting interval adjustment.
/**
intervalAdjust 表示重新提交间隔调整。
 */
type intervalAdjust struct {
	// 比率
	ratio float64
	// 是否增加标识
	inc   bool
}

// worker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
/**
worker 是负责向共识引擎提交新工作的主要对象
并收集密封效果。
 */
type worker struct {
	/** 这是 eth.chainConfig */
	config *params.ChainConfig
	// 共识引擎
	engine consensus.Engine
	// 全局的 Ethereum 实例
	eth    Backend
	// 全局的 chain 实例
	chain  *core.BlockChain

	// Subscriptions
	/** 各类订阅事件相关 */
	// 事件 (已经过时，后续可能都用 feed) 引用了 Ethereum 实例的
	mux          *event.TypeMux
	/** tx */
	// 接收 tx 事件结构的 chan
	txsCh        chan core.NewTxsEvent
	// 订阅 tx 事件结构的 sub
	txsSub       event.Subscription

	/** chainHead */
	// 接收 chainHead 事件结构的 chan
	chainHeadCh  chan core.ChainHeadEvent
	// 订阅 chainHead 事件结构的 sub
	chainHeadSub event.Subscription

	/** chainSide */
	// 接收 chainSide 事件结构的 chan
	chainSideCh  chan core.ChainSideEvent
	// 订阅 chainHead 事件结构的 sub
	chainSideSub event.Subscription

	// Channels
	/** 各类任务相关的 chan  */
	// 处理 一个新的 工作信号请求 的 chan
	// 在 go newWorkLoop() 中写入
	// 在 go mainLoop() 中读取
	newWorkCh          chan *newWorkReq

	// 处理一个 作业任务 task 的 chan
	// 在 go mainLoop() 中，在 commitNewWork 在 commit 中被写入
	// 在 go taskLoop() 中，被读取
	taskCh             chan *task

	// 处理一个 出块结果的 chan
	// 在 seal 中被写入
	// 在 worker.close() 及 go resultLoop() 中被接收
	resultCh           chan *task

	// 处理一个 挖矿开始信号的 chan
	// 在 start() 及 newWorker() 中写入
	// 在 go newWorkLoop 中被读取
	startCh            chan struct{}
	// 处理一个 挖矿退出的信号的 chan
	exitCh             chan struct{}

	// 一个接收调整出块间隔的 chan
	resubmitIntervalCh chan time.Duration
	// 一个接收 出块调整 实体的 chan
	resubmitAdjustCh   chan *intervalAdjust

	/** 当前运行周期的环境 */
	current        *environment                 // An environment for current running cycle.
	/** 一组侧块作为可能的叔叔块。 */
	possibleUncles map[common.Hash]*types.Block // A set of side blocks as the possible uncle blocks.
	/** 一组本地挖掘的块正在等待规范性确认。 */
	unconfirmed    *unconfirmedBlocks           // A set of locally mined blocks pending canonicalness confirmations.

	/** 读写锁用于保护coinbase和额外的字段 */
	mu       sync.RWMutex // The lock used to protect the coinbase and extra fields
	/** 矿工地址 */
	coinbase common.Address
	/** 拓展字段 (将会被填充到 block 的extra 字段中) */
	extra    []byte

	/** 读写锁用于保护块快照和 state 快照 */
	snapshotMu    sync.RWMutex // The lock used to protect the block snapshot and state snapshot

	// block 的快照
	snapshotBlock *types.Block
	// state 的快照
	snapshotState *state.StateDB

	// atomic status counters
	/** 原子状态计数器 */
	// 指示共识引擎是否正在运行的指示符。
	running int32 // The indicator whether the consensus engine is running or not.
	// 自上次提交打包工作以来的新到达的交易次数。
	newTxs  int32 // New arrival transaction count since last sealing work submitting.

	// Test hooks
	/** 一些测试相关的钩子 func 下面四个方法，目前只有在test中有被赋值 而已*/
	// 接收新打包任务时调用的方法。
	newTaskHook  func(*task)                        // Method to call upon receiving a new sealing task.
	// 决定是否跳过打包动作的方法。
	skipSealHook func(*task) bool                   // Method to decide whether skipping the sealing.
	// 在推送完整打包任务之前调用的方法
	fullTaskHook func()                             // Method to call before pushing the full sealing task.
	// 调用更新重新提交间隔的方法。
	resubmitHook func(time.Duration, time.Duration) // Method to call upon updating resubmitting interval.
}

/**
初始化一个 新的 worker 实例
 */
func newWorker(config *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, recommit time.Duration) *worker {
	worker := &worker{
		/** 这是 eth.chainConfig */
		config:             config,
		// 共识引擎
		engine:             engine,
		// 全局的 Ethereum 实例
		eth:                eth,
		// 事件 mux
		mux:                mux,
		// 全局的 chain 实例
		chain:              eth.BlockChain(),

		// 存放可能的 叔叔块
		possibleUncles:     make(map[common.Hash]*types.Block),
		// 返回一个 unconfirmedBlocks 结构，用于存放 未确认块
		unconfirmed:        newUnconfirmedBlocks(eth.BlockChain(), miningLogAtDepth),

		/** 处理 tx 的 chan 默认：4096 */
		txsCh:              make(chan core.NewTxsEvent, txChanSize),
		/** 处理 chainHead 的 chan 默认：10 */
		chainHeadCh:        make(chan core.ChainHeadEvent, chainHeadChanSize),
		/** 处理 chainSide 的 chan 默认：10 */
		chainSideCh:        make(chan core.ChainSideEvent, chainSideChanSize),
		// 处理 新工作请求的 chan
		newWorkCh:          make(chan *newWorkReq),
		// 处理 打包任务的 chan
		taskCh:             make(chan *task),
		// 处理 新的 block 完成打包结果的 chan
		resultCh:           make(chan *task, resultQueueSize),
		// 退出挖矿信号的 chan
		exitCh:             make(chan struct{}),
		// 开始 挖矿信号 的 chan
		startCh:            make(chan struct{}, 1),
		// 挖矿间隔调整 时间
		resubmitIntervalCh: make(chan time.Duration),
		// 挖矿间隔调整 实体
		resubmitAdjustCh:   make(chan *intervalAdjust, resubmitAdjustChanSize),
	}
	// Subscribe NewTxsEvent for tx pool
	// 从tx pool 订阅NewTxsEvent
	worker.txsSub = eth.TxPool().SubscribeNewTxsEvent(worker.txsCh)
	// Subscribe events for blockchain
	// 从 chain 上 订阅 chainHeadEvent 和 chainSideEvent
	worker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)
	worker.chainSideSub = eth.BlockChain().SubscribeChainSideEvent(worker.chainSideCh)

	// Sanitize recommit interval if the user-specified one is too short.
	// 如果用户指定的间隔太短，则清理重新发送间隔。
	if recommit < minRecommitInterval {
		log.Warn("Sanitizing miner recommit interval", "provided", recommit, "updated", minRecommitInterval)
		recommit = minRecommitInterval
	}

	/**
	【注意】
	这四个 协程才是处理挖矿的重中之重
	 */

	/** 处理 newWorkLoop 封装的 newWorkReq 及 chainSide (叔叔块事件) 及 tx 事件 */
	go worker.mainLoop()

	/** 最开始的 协程，监听 start 信号，写入 newWorkerReq  */
	go worker.newWorkLoop(recommit)
	go worker.resultLoop()
	go worker.taskLoop()

	// Submit first work to initialize pending state.
	// 提交第一份工作以初始化待处理 state 。
	worker.startCh <- struct{}{}

	// 返回 worker 实例
	return worker
}

// setEtherbase sets the etherbase used to initialize the block coinbase field.
// 设置 coinbase
func (w *worker) setEtherbase(addr common.Address) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coinbase = addr
}

// setExtra sets the content used to initialize the block extra field.
// setExtra函数：
// 设置用于初始化块额外字段的内容。
func (w *worker) setExtra(extra []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = extra
}

// setRecommitInterval updates the interval for miner sealing work recommitting.
// setRecommitInterval 函数：
// 更新矿工打包工作重新启动的间隔。
func (w *worker) setRecommitInterval(interval time.Duration) {
	w.resubmitIntervalCh <- interval
}

// pending returns the pending state and corresponding block.
func (w *worker) pending() (*types.Block, *state.StateDB) {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	if w.snapshotState == nil {
		return nil, nil
	}
	return w.snapshotBlock, w.snapshotState.Copy()
}

// pendingBlock returns pending block.
// 返回正在 pending 的 block
func (w *worker) pendingBlock() *types.Block {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock
}

// start sets the running status as 1 and triggers new work submitting.
// 开始设置 挖矿信号
func (w *worker) start() {
	atomic.StoreInt32(&w.running, 1)
	w.startCh <- struct{}{}
}

// stop sets the running status as 0.
// 将 挖矿表示我设置为 0
func (w *worker) stop() {
	atomic.StoreInt32(&w.running, 0)
}

// isRunning returns an indicator whether worker is running or not.
// 是否在挖矿标识位
func (w *worker) isRunning() bool {
	return atomic.LoadInt32(&w.running) == 1
}

// close terminates all background threads maintained by the worker and cleans up buffered channels.
// Note the worker does not support being closed multiple times.
func (w *worker) close() {
	close(w.exitCh)
	// Clean up buffered channels
	for empty := false; !empty; {
		select {
		case <-w.resultCh:
		default:
			empty = true
		}
	}
}

// newWorkLoop is a standalone goroutine to submit new mining work upon received events.
/**
newWorkLoop 函数是一个独立的goroutine，可以根据收到的事件提交新的挖掘工作。
*/
func (w *worker) newWorkLoop(recommit time.Duration) {
	var (
		// 中断标识位
		interrupt   *int32
		// 用户指定的最小重新提交间隔。
		minRecommit = recommit // minimal resubmit interval specified by user.
	)

	/** 初始化一个定时器， 原始值为 0 秒 */
	timer := time.NewTimer(0)
	// 丢弃初始刻度
	<-timer.C // discard the initial tick

	// commit aborts in-flight transaction execution with given signal and resubmits a new one.
	/**
	commit 函数 使用给定信号中止正在进行的 tx 执行，并重新提交一个新的。
	 */
	commit := func(noempty bool, s int32) {
		// noempty: 非空标识
		// s: 用于作比较的 时间戳

		if interrupt != nil {
			// 如果 中断标识位 不为 nil 则，更新 该标识位的值为 s (妈的，真不知道这句是做什么用的)
			atomic.StoreInt32(interrupt, s)
		}

		// 一个新的 中断标识位 ？
		interrupt = new(int32)
		/** 创建一个 新的作业请求实例，写入通道中 */
		w.newWorkCh <- &newWorkReq{interrupt: interrupt, noempty: noempty}

		/**
		根据外部入参的 时间戳 重置 定时器
		*/
		timer.Reset(recommit)
		// 重置 新到达的tx 数目
		atomic.StoreInt32(&w.newTxs, 0)
	}
	// recalcRecommit recalculates the resubmitting interval upon feedback.
	/**
	recalcRecommit 函数 根据反馈重新计算重新提交的时间间隔。
	 */
	recalcRecommit := func(target float64, inc bool) {
		/**
		target: 预期的阈值 ？？
		inc: 是否自增标识位 ？？
		 */
		var (
			// 先获取之前的 重置时间戳
			prev = float64(recommit.Nanoseconds())
			// 之后的重置时间戳
			next float64
		)

		// 是否需要自增
		if inc {
			// next = prev * 0.9 + 0.1 * （target + 20000,0000）
			next = prev*(1-intervalAdjustRatio) + intervalAdjustRatio*(target+intervalAdjustBias)
			// Recap if interval is larger than the maximum time interval
			// 如果间隔大于最大时间间隔，则 重新定义下(用最大时间赋值)
			if next > float64(maxRecommitInterval.Nanoseconds()) {
				next = float64(maxRecommitInterval.Nanoseconds())
			}
		} else {
			// next = prev * 0.9 + 0.1 * (target - 20000,0000)
			next = prev*(1-intervalAdjustRatio) + intervalAdjustRatio*(target-intervalAdjustBias)
			// Recap if interval is less than the user specified minimum
			// 如果间隔小于用户指定的最小值，则 重新定一下(用最小时间赋值)
			if next < float64(minRecommit.Nanoseconds()) {
				next = float64(minRecommit.Nanoseconds())
			}
		}
		/** 用 next 重新赋值 recommit  */
		recommit = time.Duration(int64(next))
	}

	/** 死循环处理 */
	for {
		select {
		// 如果接收到 启动挖矿信号
		case <-w.startCh:
			// 提交一个新的 作业请求
			commit(false, commitInterruptNewHead)

		// 如果接收到一个 chainHead 事件
		case <-w.chainHeadCh:
			// 提交一个新的 作业请求
			commit(false, commitInterruptNewHead)

		// 如果接收到定时信号
		case <-timer.C:
			// If mining is running resubmit a new work cycle periodically to pull in
			// higher priced transactions. Disable this overhead for pending blocks.
			/**
			如果采矿正在运行，则定期重新提交新的工作周期以提取更高价格的交易。 禁用挂起块的此开销。
			 */
			 // 如果 正在挖矿 && (不是Clique || Clique.Period > 0)
			if w.isRunning() && (w.config.Clique == nil || w.config.Clique.Period > 0) {
				// Short circuit if no new transaction arrives.
				// 如果没有新的交易到达则短路 (直接结束)。
				if atomic.LoadInt32(&w.newTxs) == 0 {
					// 重置 定时器
					timer.Reset(recommit)
					continue
				}
				// 提交已和新的 作业请求
				commit(true, commitInterruptResubmit)
			}

		// 如果接收到一个新的 间隔调整信号
		case interval := <-w.resubmitIntervalCh:
			// Adjust resubmit interval explicitly by user.
			// 用户明确调整重新提交间隔。
			// 最小不得小于 1 s
			if interval < minRecommitInterval {
				log.Warn("Sanitizing miner recommit interval", "provided", interval, "updated", minRecommitInterval)
				interval = minRecommitInterval
			}
			log.Info("Miner recommit interval update", "from", minRecommit, "to", interval)

			// 重置 minRecommit 及 recommit 变量
			minRecommit, recommit = interval, interval

			// 这个先不必理会，(目前只在 test 中有赋值)
			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		// 接收到 一个出块调整实体信号
		case adjust := <-w.resubmitAdjustCh:
			// Adjust resubmit interval by feedback.
			// 通过反馈调整重新提交间隔
			// 增
			if adjust.inc {
				before := recommit
				recalcRecommit(float64(recommit.Nanoseconds())/adjust.ratio, true)
				log.Trace("Increase miner recommit interval", "from", before, "to", recommit)
			} else {
				// 减
				before := recommit
				recalcRecommit(float64(minRecommit.Nanoseconds()), false)
				log.Trace("Decrease miner recommit interval", "from", before, "to", recommit)
			}
			// 这个先不必理会，(目前只在 test 中有赋值)
			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}
		// 接收到退出信号
		case <-w.exitCh:
			return
		}
	}
}

// mainLoop is a standalone goroutine to regenerate the sealing task based on the received event.
/**
mainLoop 函数是一个独立的goroutine，用于根据收到的事件重新生成 打包任务。
 */
func (w *worker) mainLoop() {
	// 取消订阅 tx sub
	defer w.txsSub.Unsubscribe()
	// 取消订阅 chainHead sub
	defer w.chainHeadSub.Unsubscribe() // 注意： chainHead 事件 在 go newWorkLoop() 中被处理
	// 取消订阅 chainSide sub
	defer w.chainSideSub.Unsubscribe()

	for {
		select {
		/**
		接收到一个新的 作业请求 (来源于 go newWorkLoop())
		 */
		case req := <-w.newWorkCh:
			// 去构造一个打包作业的task
			w.commitNewWork(req.interrupt, req.noempty)

		/**
		接收到一个 chainSide 事件 (接收到一个新叔块)
		 */
		case ev := <-w.chainSideCh:
			// 如果接收到的是一个可能的 叔叔块，则忽略
			if _, exist := w.possibleUncles[ev.Block.Hash()]; exist {
				continue
			}
			// Add side block to possible uncle block set.
			// 将side block添加到可能的uncle块集。
			w.possibleUncles[ev.Block.Hash()] = ev.Block
			// If our mining block contains less than 2 uncle blocks,
			// add the new uncle block if valid and regenerate a mining block.
			/**
			【注意】这里就说 ghost 的处理 ？？？
			如果我们的采矿区块包含少于2个叔叔区块，
			如果有效则添加新的uncle块并重新生成一个挖掘块。
			 */
			 // 如果 正在挖矿 && 当前块不为 nil && 当前块的 uncle 数目 < 2
			if w.isRunning() && w.current != nil && w.current.uncles.Cardinality() < 2 {
				start := time.Now()

				// 提交一个 uncle block by current block
				if err := w.commitUncle(w.current, ev.Block.Header()); err == nil {
					var uncles []*types.Header
					/** 遍历当前 block的 uncle 的 headers */
					// 逐个的收集起来
					w.current.uncles.Each(func(item interface{}) bool {
						hash, ok := item.(common.Hash)
						if !ok {
							return false
						}
						uncle, exist := w.possibleUncles[hash]
						if !exist {
							return false
						}
						uncles = append(uncles, uncle.Header())
						return false
					})
					// 提交打包作业的最后操作
					w.commit(uncles, nil, true, start)
				}
			}

		/**
		接收到 有新的 tx 事件
		 */
		case ev := <-w.txsCh:
			// Apply transactions to the pending state if we're not mining.
			//
			// Note all transactions received may not be continuous with transactions
			// already included in the current mining block. These transactions will
			// be automatically eliminated.
			/**
			如果我们不挖矿，则将交易应用于 pending 状态。

			请注意，收到的所有 tx 可能与当前挖掘块中已包含的 tx 不连续。 这些交易将自动消除。
			 */
			 // 如果不挖矿 && 当前 block 不为 nil
			if !w.isRunning() && w.current != nil {
				w.mu.RLock()
				// 这里之所以赋值 coinbase 给一个临时变量，因为可能某个时刻我们回去更改 coinbase
				// 所以这里获取到的是一个 快照
				coinbase := w.coinbase
				w.mu.RUnlock()

				// 创建一个 中转的map 缓存对应账户的 txs
				txs := make(map[common.Address]types.Transactions)
				for _, tx := range ev.Txs {
					// 根据 singer 和 tx 解出 from
					acc, _ := types.Sender(w.current.signer, tx)
					txs[acc] = append(txs[acc], tx)
				}

				// 入参一个 签名器 和 某些账户及其相关的 tx集
				// 返回 tx相关的一些内容
				txset := types.NewTransactionsByPriceAndNonce(w.current.signer, txs)
				/** 去执行 tx */
				w.commitTransactions(txset, coinbase, nil)
				// 记录快照信息
				w.updateSnapshot()
			} else {
				// If we're mining, but nothing is being processed, wake on new transactions
				/**
				如果我们正在挖矿，但没有任何处理，请在新交易中醒来
				 */
				 // 如果 Clique 不为 nil && Clique.Period == 0
				if w.config.Clique != nil && w.config.Clique.Period == 0 {
					/** 提交一个新的 挖矿任务 */
					w.commitNewWork(nil, false)
				}
			}

			// 更新 newTxs 的新到来 tx 的数量计数
			atomic.AddInt32(&w.newTxs, int32(len(ev.Txs)))

		// System stopped
		/**
		下面全部是 关于 系统停止的处理
		 */

		// 接收到 退出信号
		case <-w.exitCh:
			return
		// tx sub 中有err抛出
		case <-w.txsSub.Err():
			return
		// chainHead sub 中有err抛出
		case <-w.chainHeadSub.Err():
			return
		// chainSide 中有err抛出
		case <-w.chainSideSub.Err():
			return
		}
	}
}

// seal pushes a sealing task to consensus engine and submits the result.
/**
seal 函数
将 打包任务推送到共识引擎并提交打包的结果到 resultCh 。
 */
func (w *worker) seal(t *task, stop <-chan struct{}) {
	var (
		err error
		res *task
	)

	if w.skipSealHook != nil && w.skipSealHook(t) {
		return
	}

	/**
	这里才是真正的 打包 block
	并接受范湖的完整 block
	 */
	if t.block, err = w.engine.Seal(w.chain, t.block, stop); t.block != nil {
		log.Info("Successfully sealed new block", "number", t.block.Number(), "hash", t.block.Hash(),
			"elapsed", common.PrettyDuration(time.Since(t.createdAt)))
		res = t
	} else {
		if err != nil {
			log.Warn("Block sealing failed", "err", err)
		}
		res = nil
	}
	select {
	// 将 包含有 新打包的 block 的res 发送至 resultCh 中
	case w.resultCh <- res:
	case <-w.exitCh:
	}
}

// taskLoop is a standalone goroutine to fetch sealing task from the generator and
// push them to consensus engine.
/**
taskLoop 函数
是一个独立的goroutine，用于从生成器获取 打包 task 并将它们推送到共识引擎。
 */
func (w *worker) taskLoop() {
	var (
		// 一个加收 停止信号的 chan
		stopCh chan struct{}

		// 不完整 块的 hash
		prev   common.Hash
	)

	// interrupt aborts the in-flight sealing task.
	// interrupt 函数：中止正在处理中的 打包任务。
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}


	for {
		select {

		// 接受到 task
		case task := <-w.taskCh:
			// 不必理会，只有在 test 中有赋值
			if w.newTaskHook != nil {
				w.newTaskHook(task)
			}
			// Reject duplicate sealing work due to resubmitting.
			// 由于重新提交而拒绝重复 打包工作。
			// 如果当前 块Hash == prev 则，忽略
			if task.block.HashNoNonce() == prev {
				continue
			}

			// 调用 终止函数
			interrupt()

			// 停止 信号 chan
			stopCh = make(chan struct{})
			// 打包之前的 不完整的 block Hash
			prev = task.block.HashNoNonce()

			/** 调用 打包函数 */
			go w.seal(task, stopCh)

		// 接收到 退出信号
		case <-w.exitCh:
			// 调用中转 函数
			interrupt()
			return
		}
	}
}

// resultLoop is a standalone goroutine to handle sealing result submitting
// and flush relative data to the database.
/***
resultLoop 函数：
是一个独立的goroutine，用于处理 打包结果提交和将相关数据刷新到 底层数据库。
 */
func (w *worker) resultLoop() {
	for {
		select {
		case result := <-w.resultCh:
			// Short circuit when receiving empty result.
			if result == nil {
				continue
			}
			// Short circuit when receiving duplicate result caused by resubmitting.
			block := result.block
			if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
				continue
			}
			// Update the block hash in all logs since it is now available and not when the
			// receipt/log of individual transactions were created.
			for _, r := range result.receipts {
				for _, l := range r.Logs {
					l.BlockHash = block.Hash()
				}
			}
			for _, log := range result.state.Logs() {
				log.BlockHash = block.Hash()
			}
			// Commit block and state to database.
			stat, err := w.chain.WriteBlockWithState(block, result.receipts, result.state)
			if err != nil {
				log.Error("Failed writing block to chain", "err", err)
				continue
			}
			// Broadcast the block and announce chain insertion event
			w.mux.Post(core.NewMinedBlockEvent{Block: block})
			var (
				events []interface{}
				logs   = result.state.Logs()
			)
			switch stat {
			case core.CanonStatTy:
				events = append(events, core.ChainEvent{Block: block, Hash: block.Hash(), Logs: logs})
				events = append(events, core.ChainHeadEvent{Block: block})
			case core.SideStatTy:
				events = append(events, core.ChainSideEvent{Block: block})
			}
			w.chain.PostChainEvents(events, logs)

			// Insert the block into the set of pending ones to resultLoop for confirmations
			w.unconfirmed.Insert(block.NumberU64(), block.Hash())

		case <-w.exitCh:
			return
		}
	}
}

// makeCurrent creates a new environment for the current cycle.
func (w *worker) makeCurrent(parent *types.Block, header *types.Header) error {
	state, err := w.chain.StateAt(parent.Root())
	if err != nil {
		return err
	}
	env := &environment{
		signer:    types.NewEIP155Signer(w.config.ChainID),
		state:     state,
		ancestors: mapset.NewSet(),
		family:    mapset.NewSet(),
		uncles:    mapset.NewSet(),
		header:    header,
	}

	// when 08 is processed ancestors contain 07 (quick block)
	for _, ancestor := range w.chain.GetBlocksFromHash(parent.Hash(), 7) {
		for _, uncle := range ancestor.Uncles() {
			env.family.Add(uncle.Hash())
		}
		env.family.Add(ancestor.Hash())
		env.ancestors.Add(ancestor.Hash())
	}

	// Keep track of transactions which return errors so they can be removed
	env.tcount = 0
	w.current = env
	return nil
}

// commitUncle adds the given block to uncle block set, returns error if failed to add.
// commitUncle 函数将给定的块添加到uncle块集，如果添加失败则返回错误。
func (w *worker) commitUncle(env *environment, uncle *types.Header) error {
	hash := uncle.Hash()
	// 判断当前 block 的uncle set 中是否已经存在该 uncle hash
	if env.uncles.Contains(hash) {
		return fmt.Errorf("uncle not unique")
	}
	// 判断当前block 的祖先和 该可能的uncle block 的祖先是否一致
	if !env.ancestors.Contains(uncle.ParentHash) {
		return fmt.Errorf("uncle's parent unknown (%x)", uncle.ParentHash[0:4])
	}
	// 判断该uncle block 是否有效，是否属于该家庭的成员之一
	if env.family.Contains(hash) {
		return fmt.Errorf("uncle already in family (%x)", hash)
	}
	/** 将，该可能的 uncle block 追加到当前块的uncle set 中 */
	env.uncles.Add(uncle.Hash())
	return nil
}

// updateSnapshot updates pending snapshot block and state.
// Note this function assumes the current variable is thread safe.
func (w *worker) updateSnapshot() {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	var uncles []*types.Header
	w.current.uncles.Each(func(item interface{}) bool {
		hash, ok := item.(common.Hash)
		if !ok {
			return false
		}
		uncle, exist := w.possibleUncles[hash]
		if !exist {
			return false
		}
		uncles = append(uncles, uncle.Header())
		return false
	})

	w.snapshotBlock = types.NewBlock(
		w.current.header,
		w.current.txs,
		uncles,
		w.current.receipts,
	)

	w.snapshotState = w.current.state.Copy()
}

func (w *worker) commitTransaction(tx *types.Transaction, coinbase common.Address) ([]*types.Log, error) {
	snap := w.current.state.Snapshot()

	receipt, _, err := core.ApplyTransaction(w.config, w.chain, &coinbase, w.current.gasPool, w.current.state, w.current.header, tx, &w.current.header.GasUsed, vm.Config{})
	if err != nil {
		w.current.state.RevertToSnapshot(snap)
		return nil, err
	}
	w.current.txs = append(w.current.txs, tx)
	w.current.receipts = append(w.current.receipts, receipt)

	return receipt.Logs, nil
}

func (w *worker) commitTransactions(txs *types.TransactionsByPriceAndNonce, coinbase common.Address, interrupt *int32) bool {
	// Short circuit if current is nil
	if w.current == nil {
		return true
	}

	if w.current.gasPool == nil {
		w.current.gasPool = new(core.GasPool).AddGas(w.current.header.GasLimit)
	}

	var coalescedLogs []*types.Log

	for {
		// In the following three cases, we will interrupt the execution of the transaction.
		// (1) new head block event arrival, the interrupt signal is 1
		// (2) worker start or restart, the interrupt signal is 1
		// (3) worker recreate the mining block with any newly arrived transactions, the interrupt signal is 2.
		// For the first two cases, the semi-finished work will be discarded.
		// For the third case, the semi-finished work will be submitted to the consensus engine.
		if interrupt != nil && atomic.LoadInt32(interrupt) != commitInterruptNone {
			// Notify resubmit loop to increase resubmitting interval due to too frequent commits.
			if atomic.LoadInt32(interrupt) == commitInterruptResubmit {
				ratio := float64(w.current.header.GasLimit-w.current.gasPool.Gas()) / float64(w.current.header.GasLimit)
				if ratio < 0.1 {
					ratio = 0.1
				}
				w.resubmitAdjustCh <- &intervalAdjust{
					ratio: ratio,
					inc:   true,
				}
			}
			return atomic.LoadInt32(interrupt) == commitInterruptNewHead
		}
		// If we don't have enough gas for any further transactions then we're done
		if w.current.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", w.current.gasPool, "want", params.TxGas)
			break
		}
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek()
		if tx == nil {
			break
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		//
		// We use the eip155 signer regardless of the current hf.
		from, _ := types.Sender(w.current.signer, tx)
		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.config.IsEIP155(w.current.header.Number) {
			log.Trace("Ignoring reply protected transaction", "hash", tx.Hash(), "eip155", w.config.EIP155Block)

			txs.Pop()
			continue
		}
		// Start executing the transaction
		w.current.state.Prepare(tx.Hash(), common.Hash{}, w.current.tcount)

		logs, err := w.commitTransaction(tx, coinbase)
		switch err {
		case core.ErrGasLimitReached:
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			txs.Pop()

		case core.ErrNonceTooLow:
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case core.ErrNonceTooHigh:
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			txs.Pop()

		case nil:
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			w.current.tcount++
			txs.Shift()

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
		}
	}

	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are mining. The reason is that
		// when we are mining, the worker will regenerate a mining block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		go w.mux.Post(core.PendingLogsEvent{Logs: cpy})
	}
	// Notify resubmit loop to decrease resubmitting interval if current interval is larger
	// than the user-specified one.
	if interrupt != nil {
		w.resubmitAdjustCh <- &intervalAdjust{inc: false}
	}
	return false
}

// commitNewWork generates several new sealing tasks based on the parent block.
/**
commitNewWork 函数
基于父块生成几个新的 打包 task。

这里面回去执行 tx 且 调用 w.commit()
 */
func (w *worker) commitNewWork(interrupt *int32, noempty bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	tstart := time.Now()
	parent := w.chain.CurrentBlock()

	tstamp := tstart.Unix()
	if parent.Time().Cmp(new(big.Int).SetInt64(tstamp)) >= 0 {
		tstamp = parent.Time().Int64() + 1
	}
	// this will ensure we're not going off too far in the future
	if now := time.Now().Unix(); tstamp > now+1 {
		wait := time.Duration(tstamp-now) * time.Second
		log.Info("Mining too far in the future", "wait", common.PrettyDuration(wait))
		time.Sleep(wait)
	}

	num := parent.Number()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1),
		GasLimit:   core.CalcGasLimit(parent),
		Extra:      w.extra,
		Time:       big.NewInt(tstamp),
	}
	// Only set the coinbase if our consensus engine is running (avoid spurious block rewards)
	if w.isRunning() {
		if w.coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return
		}
		header.Coinbase = w.coinbase
	}
	if err := w.engine.Prepare(w.chain, header); err != nil {
		log.Error("Failed to prepare header for mining", "err", err)
		return
	}
	// If we are care about TheDAO hard-fork check whether to override the extra-data or not
	if daoBlock := w.config.DAOForkBlock; daoBlock != nil {
		// Check whether the block is among the fork extra-override range
		limit := new(big.Int).Add(daoBlock, params.DAOForkExtraRange)
		if header.Number.Cmp(daoBlock) >= 0 && header.Number.Cmp(limit) < 0 {
			// Depending whether we support or oppose the fork, override differently
			if w.config.DAOForkSupport {
				header.Extra = common.CopyBytes(params.DAOForkBlockExtra)
			} else if bytes.Equal(header.Extra, params.DAOForkBlockExtra) {
				header.Extra = []byte{} // If miner opposes, don't let it use the reserved extra-data
			}
		}
	}
	// Could potentially happen if starting to mine in an odd state.
	err := w.makeCurrent(parent, header)
	if err != nil {
		log.Error("Failed to create mining context", "err", err)
		return
	}
	// Create the current work task and check any fork transitions needed
	env := w.current
	if w.config.DAOForkSupport && w.config.DAOForkBlock != nil && w.config.DAOForkBlock.Cmp(header.Number) == 0 {
		misc.ApplyDAOHardFork(env.state)
	}

	// compute uncles for the new block.
	var (
		uncles    []*types.Header
		badUncles []common.Hash
	)
	for hash, uncle := range w.possibleUncles {
		if len(uncles) == 2 {
			break
		}
		if err := w.commitUncle(env, uncle.Header()); err != nil {
			log.Trace("Bad uncle found and will be removed", "hash", hash)
			log.Trace(fmt.Sprint(uncle))

			badUncles = append(badUncles, hash)
		} else {
			log.Debug("Committing new uncle to block", "hash", hash)
			uncles = append(uncles, uncle.Header())
		}
	}
	for _, hash := range badUncles {
		delete(w.possibleUncles, hash)
	}

	if !noempty {
		// Create an empty block based on temporary copied state for sealing in advance without waiting block
		// execution finished.
		w.commit(uncles, nil, false, tstart)
	}

	// Fill the block with all available pending transactions.
	pending, err := w.eth.TxPool().Pending()
	if err != nil {
		log.Error("Failed to fetch pending transactions", "err", err)
		return
	}
	// Short circuit if there is no available pending transactions
	if len(pending) == 0 {
		w.updateSnapshot()
		return
	}
	// Split the pending transactions into locals and remotes
	localTxs, remoteTxs := make(map[common.Address]types.Transactions), pending
	for _, account := range w.eth.TxPool().Locals() {
		if txs := remoteTxs[account]; len(txs) > 0 {
			delete(remoteTxs, account)
			localTxs[account] = txs
		}
	}
	if len(localTxs) > 0 {
		txs := types.NewTransactionsByPriceAndNonce(w.current.signer, localTxs)
		if w.commitTransactions(txs, w.coinbase, interrupt) {
			return
		}
	}
	if len(remoteTxs) > 0 {
		txs := types.NewTransactionsByPriceAndNonce(w.current.signer, remoteTxs)
		if w.commitTransactions(txs, w.coinbase, interrupt) {
			return
		}
	}
	w.commit(uncles, w.fullTaskHook, true, tstart)
}

// commit runs any post-transaction state modifications, assembles the final block
// and commits new work if consensus engine is running.
/**
commit 函数是在执行完block中的所有 tx 后state得以修改后才会执行的一个函数，
组装块的最后状态，如果共识引擎正在运行，则提交新工作。
 */
func (w *worker) commit(uncles []*types.Header, interval func(), update bool, start time.Time) error {
	// Deep copy receipts here to avoid interaction between different tasks.
	receipts := make([]*types.Receipt, len(w.current.receipts))
	for i, l := range w.current.receipts {
		receipts[i] = new(types.Receipt)
		*receipts[i] = *l
	}
	s := w.current.state.Copy()
	block, err := w.engine.Finalize(w.chain, w.current.header, s, w.current.txs, uncles, w.current.receipts)
	if err != nil {
		return err
	}
	if w.isRunning() {
		if interval != nil {
			interval()
		}
		select {
		case w.taskCh <- &task{receipts: receipts, state: s, block: block, createdAt: time.Now()}:
			w.unconfirmed.Shift(block.NumberU64() - 1)

			feesWei := new(big.Int)
			for i, tx := range block.Transactions() {
				feesWei.Add(feesWei, new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), tx.GasPrice()))
			}
			feesEth := new(big.Float).Quo(new(big.Float).SetInt(feesWei), new(big.Float).SetInt(big.NewInt(params.Ether)))

			log.Info("Commit new mining work", "number", block.Number(), "uncles", len(uncles), "txs", w.current.tcount,
				"gas", block.GasUsed(), "fees", feesEth, "elapsed", common.PrettyDuration(time.Since(start)))

		case <-w.exitCh:
			log.Info("Worker has exited")
		}
	}
	if update {
		w.updateSnapshot()
	}
	return nil
}
