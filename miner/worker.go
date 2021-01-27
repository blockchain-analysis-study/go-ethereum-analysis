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

package miner

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/consensus"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/consensus/misc"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/state"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/types"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/vm"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/event"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/params"
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
	/** 当前签名者 todo 主要是  chainId */
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

	commitInterruptNone int32 = iota   	// 表示 任何都不是
	commitInterruptNewHead				// 表示 一个新的 head 事件到达而需要中断当前 pack 的标识位
	commitInterruptResubmit				// 表示 一个重新提交 worker pack 的标识位
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
	go worker.mainLoop()	// todo 步骤 2   接收 newWorkerReq， 监听 tx 和 chainSide <uncles> 事件 启动 执行tx 和 commit() <打包区>

	/** 最开始的 协程，监听 start 信号，写入 newWorkerReq  */
	go worker.newWorkLoop(recommit)   // todo 步骤 1    定时发起 或 被 chainHeader事件 触发 启动 newWorkerReq

	/** 接收 seal 完成打包之后的 block */
	go worker.resultLoop()  // todo 步骤 4     将打包好的 block 刷入本地磁盘  并     发布 新block 事件

	/** 接收 w.commit 过来的 task 实例； w.commit 可能在 mainLoop 被调用 */
	go worker.taskLoop()  // todo 步骤 3    接收 commit() 发来的 seal task， 将block 转交给 共识 打包

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
// pending返回挂起状态和相应的块。
func (w *worker) pending() (*types.Block, *state.StateDB) {
	// return a snapshot to avoid contention on currentMu mutex
	// 返回快照以避免在currentMu互斥锁上发生争用
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
	// 返回一个快照块
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
/**
close 函数：
终止 worker 维护的所有后台线程并清理缓冲的通道。
请注意，worker 不支持多次关闭。
 */
func (w *worker) close() {
	close(w.exitCh)
	// Clean up buffered channels
	// 清理缓冲的通道
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
	recalcRecommit 函数 根据反馈重新计算重新提交的时间间隔
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
			// 当接收到一个 空结果时，直接返回
			if result == nil {
				continue
			}
			// Short circuit when receiving duplicate result caused by resubmitting.
			// 当由于重复提交而接收到相同的结果时，直接返回
			block := result.block
			if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
				continue
			}
			// Update the block hash in all logs since it is now available and not when the
			// receipt/log of individual transactions were created.
			/**
			更新所有日志中的块哈希，因为它现在可用，而不是在创建单个 tx 的接收/日志时。
			 */
			 // 遍历收据
			for _, r := range result.receipts {
				// 遍历收据中的所有 日志
				for _, l := range r.Logs {
					l.BlockHash = block.Hash()
				}
			}
			// 遍历当前 state 的所有日志
			for _, log := range result.state.Logs() {
				log.BlockHash = block.Hash()
			}
			// Commit block and state to database.
			/** 打包节点直接 写链 */
			stat, err := w.chain.WriteBlockWithState(block, result.receipts, result.state)  // todo 将打包好的 block 刷入自己的磁盘
			if err != nil {
				log.Error("Failed writing block to chain", "err", err)
				continue
			}
			// Broadcast the block and announce chain insertion event
			// 广播块并 通知 链插入事件
			w.mux.Post(core.NewMinedBlockEvent{Block: block})   // todo 发布 新block 事件
			var (
				// 一个事件 切片
				events []interface{}
				// state 的所有 日志
				logs   = result.state.Logs()
			)
			// 判断写链的结果状态
			switch stat {

			//
			case core.CanonStatTy:
				events = append(events, core.ChainEvent{Block: block, Hash: block.Hash(), Logs: logs})
				events = append(events, core.ChainHeadEvent{Block: block})

			//
			case core.SideStatTy:
				events = append(events, core.ChainSideEvent{Block: block})
			}

			// 广播 事件及日志
			w.chain.PostChainEvents(events, logs)

			// Insert the block into the set of pending ones to resultLoop for confirmations
			// 将块插入到 pending 的一组中以resultLoop进行确认
			w.unconfirmed.Insert(block.NumberU64(), block.Hash())

		// 当接收到一个 退出信号
		case <-w.exitCh:
			return
		}
	}
}

// makeCurrent creates a new environment for the current cycle.
// makeCurrent 函数：
// 为当前打包周期创建一个新上下文环境。
func (w *worker) makeCurrent(parent *types.Block, header *types.Header) error {

	// 获取 chain 上的最新 state
	state, err := w.chain.StateAt(parent.Root())
	if err != nil {
		return err
	}

	/***
	这个吊东西超级重要
	当前打包的上下文
	 */
	env := &environment{
		// 签名器
		signer:    types.NewEIP155Signer(w.config.ChainID),
		// 当前 state
		state:     state,
		// 创建一个用于保存祖先的集
		ancestors: mapset.NewSet(),
		// 创建一个用于保存 确认的家谱区块的集
		family:    mapset.NewSet(),
		// 创建一个叔叔区块的集
		uncles:    mapset.NewSet(),
		// 当前预先处理好的header
		header:    header,
	}

	// when 08 is processed ancestors contain 07 (quick block)
	// 例如： 当处理 08 时，祖先包含 07 (这时候需要快速 阻止)
	// 获取当前 区块 7个祖先
	for _, ancestor := range w.chain.GetBlocksFromHash(parent.Hash(), 7) {
		// 获取 某个祖先的叔叔
		for _, uncle := range ancestor.Uncles() {
			// 全部追加到 家族中
			env.family.Add(uncle.Hash())
		}
		// 追加到 家族中
		env.family.Add(ancestor.Hash())
		// 追加到 祖先集中
		env.ancestors.Add(ancestor.Hash())
	}

	// Keep track of transactions which return errors so they can be removed
	// 跟踪返回错误的 tx，以便删除它们
	env.tcount = 0

	// 设置 当前 打包的上下文环境
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
/**
updateSnapshot 函数
更新 pending 的快照块和 state。
请注意，此函数假定当前变量是线程安全的。
 */
func (w *worker) updateSnapshot() {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	var uncles []*types.Header
	// 收集所有可能的uncle 块
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

	/**
	创建一个 快找块
	 */
	w.snapshotBlock = types.NewBlock(
		w.current.header,
		w.current.txs,
		uncles,
		w.current.receipts,
	)

	// 设置当前的 state 快照
	w.snapshotState = w.current.state.Copy()
}

/**
执行 交易
 */
func (w *worker) commitTransaction(tx *types.Transaction, coinbase common.Address) ([]*types.Log, error) {
	snap := w.current.state.Snapshot()

	/**
	todo 真正执行 单笔 交易
	 */
	receipt, _, err := core.ApplyTransaction(w.config, w.chain, &coinbase, w.current.gasPool, w.current.state, w.current.header, tx, &w.current.header.GasUsed, vm.Config{})
	if err != nil {
		// 回滚快照
		w.current.state.RevertToSnapshot(snap)
		return nil, err
	}
	// todo  ########################################
	// todo  ########################################
	// todo  ########################################
	// todo  ########################################
	//
	// todo 收集当前被执行过了的 交易
	//
	// todo 只有执行通过的 tx 才会被打包到 block 中
	w.current.txs = append(w.current.txs, tx)
	// 收集当前交易执行产生的 收据
	w.current.receipts = append(w.current.receipts, receipt)

	// 返回 收据中的 所有日志信息
	return receipt.Logs, nil
}

/**
执行 一批交易
 */
func (w *worker) commitTransactions(txs *types.TransactionsByPriceAndNonce, coinbase common.Address, interrupt *int32) bool {
	// Short circuit if current is nil
	// 如果当前 打包上下文为nil 则直接退出
	if w.current == nil {
		return true
	}

	// 设置 GasPool
	if w.current.gasPool == nil {
		// todo 预先设置 gasPool == header 中的gasLimit
		// 		由于所有的是 core.GasPool 的指针，所以随着 tx的执行
		// 		core.GasPool 也会一直的变化，即 w.current.gasPool 也会一直的变化
		w.current.gasPool = new(core.GasPool).AddGas(w.current.header.GasLimit)
	}

	// 合并的日志 ？？
	var coalescedLogs []*types.Log

	for {
		// In the following three cases, we will interrupt the execution of the transaction.
		// (1) new head block event arrival, the interrupt signal is 1
		// (2) worker start or restart, the interrupt signal is 1
		// (3) worker recreate the mining block with any newly arrived transactions, the interrupt signal is 2.
		// For the first two cases, the semi-finished work will be discarded.
		// For the third case, the semi-finished work will be submitted to the consensus engine.

		/**
		在以下三种情况下，我们将中断 tx 的执行。
		（1）新的头块事件到达，中断信号为1
		（2）worker 启动或重启，中断信号为1
		（3）worker用任何新到的 tx 重新创建 打包块，中断信号为2。

		对于前两种情况，半成品将被丢弃。
		对于第三种情况，半成品将被提交给共识引擎。
		 */
		if interrupt != nil && atomic.LoadInt32(interrupt) != commitInterruptNone {
			// Notify resubmit loop to increase resubmitting interval due to too frequent commits.
			// 由于过于频繁的提交，通知重新提交循环以增加重新提交间隔。
			// 如果 interval (中断信号) 为 2
			if atomic.LoadInt32(interrupt) == commitInterruptResubmit {
				// ratio: 比率
				// (当前块所有的 gasLimit - 打包block 时的所消耗gas) / 当前块所有的 gasLimit
				ratio := float64(w.current.header.GasLimit-w.current.gasPool.Gas()) / float64(w.current.header.GasLimit)
				// 如果生下来的 gas 比率为 < 0.1 则，应该为 0.1
				if ratio < 0.1 {
					ratio = 0.1
				}

				// todo 发送一个 调整 计算出块间隔 信号
				w.resubmitAdjustCh <- &intervalAdjust{
					ratio: ratio,
					inc:   true,
				}
			}

			/** 返回 当前中断信号是否为 1 */
			return atomic.LoadInt32(interrupt) == commitInterruptNewHead
		}
		// If we don't have enough gas for any further transactions then we're done
		// 如果我们没有足够的 gas 进行任何进一步的tx，那么我们就算 完了当前函数的执行,
		// 即： block 执行终止了
		if w.current.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", w.current.gasPool, "want", params.TxGas)
			break
		}
		// Retrieve the next transaction and abort if all done
		// todo 检索下一个 tx 并在完成所有操作后中止
		tx := txs.Peek()
		if tx == nil {
			break
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		//
		// We use the eip155 signer regardless of the current hf.

		/**
		这里可能会被忽略错误。 该 error 已经在 tx在 txpool 期间已被检查了。

		我们不论当前 hf 如何，都使用 eip155 签名者。
		 */
		from, _ := types.Sender(w.current.signer, tx)
		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		/**
		todo 检查tx是否重播受保护。 如果我们不在EIP155 hf阶段，请开始忽略发送方，直到我们这样做。
		 */
		 // todo 如果 tx 是受保护的 && 当前块高处于 eip155 条件的块高
		if tx.Protected() && !w.config.IsEIP155(w.current.header.Number) {
			log.Trace("Ignoring reply protected transaction", "hash", tx.Hash(), "eip155", w.config.EIP155Block)

			txs.Pop()
			continue
		}
		// Start executing the transaction
		// 填充当前 state 的 txHash (thash 字段) 及bhash字段 及txIndex 字段
		w.current.state.Prepare(tx.Hash(), common.Hash{}, w.current.tcount)

		// todo 真正执行单笔 tx
		//
		// todo 在这里面实现了， 只 打包执行通过的 tx 逻辑
		logs, err := w.commitTransaction(tx, coinbase)

		/* 判断 tx 的执行err， todo 调整 tx集 中的 tx 情况 */
		switch err {
		case core.ErrGasLimitReached:
			// Pop the current out-of-gas transaction without shifting in the next from the account
			//
			// todo 弹出(剔除)当前的 out-of-gas 的tx，而不会从账户中转移下一个
			log.Trace("Gas limit exceeded for current block", "sender", from)
			txs.Pop()

		case core.ErrNonceTooLow:
			// New head notification data race between the transaction pool and miner, shift
			//
			//todo 如果 txpool 和 miner 之间的 新header通知  存在 数据竞争，则翻页
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case core.ErrNonceTooHigh:
			// Reorg notification data race between the transaction pool and miner, skip account =
			//
			// todo 如果在 txpool 及 miner 之间存在重组 通知有数据竞争， 则跳过当前 账户的所有 tx
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			txs.Pop()

		case nil:
			// Everything ok, collect the logs and shift in the next transaction from the same account
			//
			// todo 所有的东西都 OK的话，则收集日志并从同一帐户转移下一个交易
			coalescedLogs = append(coalescedLogs, logs...)
			w.current.tcount++
			txs.Shift()

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			/**
			todo 奇怪的错误，丢弃 Tx 并获得下一个 Tx（注意，nonce-too-high 子句将阻止我们徒劳地执行）。
			 */
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
		}
	}

	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are mining. The reason is that
		// when we are mining, the worker will regenerate a mining block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.
		/**
		我们在挖掘时不会推送pendingLogsEvent。
		原因是当我们开采时，工人将每3秒钟再生一次采矿区。
		为了避免推送重复的pendingLog，我们禁用 pending的日志推送。
		 */
		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		/**
		在发生 copy 时，state缓存日志，并且当前块由本地矿工挖掘时，
		通过填充块 hash，这些日志从 pending 的日志“升级”到已挖掘的日志。
		如果在处理PendingLogsEvent之前“升级”了日志，则会导致竞争条件。
		 */
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		go w.mux.Post(core.PendingLogsEvent{Logs: cpy})  // 某个 jsonrpc api 那边有用的 ... 用来给客户端 过滤 logs
	}
	// Notify resubmit loop to decrease resubmitting interval if current interval is larger
	// than the user-specified one.
	/**
	如果当前间隔大于用户指定的间隔，则通知重新提交 loop 以减少重新提交间隔。
	 */
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

	// 获取当前最高块
	parent := w.chain.CurrentBlock()

	tstamp := tstart.Unix()

	// 如果最高块的出块时间戳比当前时间大；
	// 也就是 当前节点的服务器时间慢了
	if parent.Time().Cmp(new(big.Int).SetInt64(tstamp)) >= 0 {

		// 这时候，默认去当前打包时间为上一个块的出块时间 + 1
		tstamp = parent.Time().Int64() + 1
	}
	// this will ensure we're not going off too far in the future
	// 这将确保我们未来不会走得太远

	// 再次确保下 求出来的tstamp 是否大于 当前时间+1
	if now := time.Now().Unix(); tstamp > now+1 {
		// 如果是的话，则需要让程序等待到 tstamp 时间点
		wait := time.Duration(tstamp-now) * time.Second
		log.Info("Mining too far in the future", "wait", common.PrettyDuration(wait))
		time.Sleep(wait)
	}

	// 最高块的块高
	num := parent.Number()

	/** 构造一个当前块的不完整 头部 */
	header := &types.Header{

		// 上一个块的Hash
		ParentHash: parent.Hash(),
		// 当前快的块高
		Number:     num.Add(num, common.Big1),
		/**
		根据上一个块 计算出 当前快的 gas 最高限制  gasLimit
		 */
		GasLimit:   core.CalcGasLimit(parent),  // todo 计算当前区块的 gasLimit
		// 将命令行设置到 miner/worker中的 extra 字段设置到 header 中
		Extra:      w.extra,

		// 设置当前的出块时间
		Time:       big.NewInt(tstamp),
	}
	// Only set the coinbase if our consensus engine is running (avoid spurious block rewards)
	// 如果我们的共识引擎正在运行，则仅设置coinbase（避免虚假块奖励）
	if w.isRunning() {
		if w.coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return
		}
		header.Coinbase = w.coinbase
	}

	// 执行 共识中重要的三个方法之一 Prepare        (Prepare、Finalise、Seal)
	// 主要是对 header中的难度字段的计算
	if err := w.engine.Prepare(w.chain, header); err != nil {  // todo 主要计算当前 block 的难度
		log.Error("Failed to prepare header for mining", "err", err)
		return
	}
	// If we are care about TheDAO hard-fork check whether to override the extra-data or not
	// 如果我们关心TheDAO硬叉检查是否覆盖额外数据 (不用理会 硬分叉)
	if daoBlock := w.config.DAOForkBlock; daoBlock != nil {
		// Check whether the block is among the fork extra-override range
		// 检查块是否在fork extra-override范围之内
		limit := new(big.Int).Add(daoBlock, params.DAOForkExtraRange)
		if header.Number.Cmp(daoBlock) >= 0 && header.Number.Cmp(limit) < 0 {
			// Depending whether we support or oppose the fork, override differently
			// 根据我们是否支持或反对分叉，不同地覆盖
			if w.config.DAOForkSupport {
				header.Extra = common.CopyBytes(params.DAOForkBlockExtra)
			} else if bytes.Equal(header.Extra, params.DAOForkBlockExtra) {
				// 如果矿工反对，不要让它使用保留的额外数据
				header.Extra = []byte{} // If miner opposes, don't let it use the reserved extra-data
			}
		}
	}
	// Could potentially happen if starting to mine in an odd state.
	// 如果开始以奇怪 state 开采，可能会发生各种问题。
	/** 创建一个当前 打包周期的环境上下文 */
	err := w.makeCurrent(parent, header)
	if err != nil {
		log.Error("Failed to create mining context", "err", err)
		return
	}
	// Create the current work task and check any fork transitions needed
	// 创建当前工作任务并检查所需的任何fork转换 (硬分叉相关，不必理会)
	env := w.current
	if w.config.DAOForkSupport && w.config.DAOForkBlock != nil && w.config.DAOForkBlock.Cmp(header.Number) == 0 {
		misc.ApplyDAOHardFork(env.state)
	}

	// compute uncles for the new block.
	// 用于计算新块的叔叔集。
	var (
		uncles    []*types.Header
		badUncles []common.Hash
	)
	// 遍历 所有可能的叔叔块
	for hash, uncle := range w.possibleUncles {

		// 如果已经收集了两个叔叔，则结束 for
		if len(uncles) == 2 {
			break
		}

		// 将该叔叔块，添加到叔叔集中
		if err := w.commitUncle(env, uncle.Header()); err != nil {
			log.Trace("Bad uncle found and will be removed", "hash", hash)
			log.Trace(fmt.Sprint(uncle))

			// 如果出了问题，那么这个是有问题的叔叔块，则追加到有问题的叔叔集中
			badUncles = append(badUncles, hash)
		} else {
			log.Debug("Committing new uncle to block", "hash", hash)
			uncles = append(uncles, uncle.Header())
		}
	}

	// 将有问题的叔叔，从可能的叔叔集中删除
	for _, hash := range badUncles {
		delete(w.possibleUncles, hash)
	}

	// 如果 不为空标识位为 false
	if !noempty {
		// Create an empty block based on temporary copied state for sealing in advance without waiting block
		// execution finished.
		/**
		基于临时复制的 state 创建空块以提前进行密封，而无需等待块执行完成。
		 */
		w.commit(uncles, nil, false, tstart)
	}

	// Fill the block with all available pending transactions.
	// 使用所有可用的 pending tx 填充 block。
	pending, err := w.eth.TxPool().Pending()
	if err != nil {
		log.Error("Failed to fetch pending transactions", "err", err)
		return
	}
	// Short circuit if there is no available pending transactions
	// 如果没有可用的 pending tx，则 结束
	if len(pending) == 0 {
		// 记录下 快照
		w.updateSnapshot()
		return
	}
	// Split the pending transactions into locals and remotes
	// 将 pending tx 拆分为 本地 和 远程
	localTxs, remoteTxs := make(map[common.Address]types.Transactions), pending
	for _, account := range w.eth.TxPool().Locals() {
		if txs := remoteTxs[account]; len(txs) > 0 {
			delete(remoteTxs, account)
			localTxs[account] = txs
		}
	}
	// 如果有本地的 tx，则执行
	if len(localTxs) > 0 {
		txs := types.NewTransactionsByPriceAndNonce(w.current.signer, localTxs)
		if w.commitTransactions(txs, w.coinbase, interrupt) {
			return
		}
	}
	// 如果有 远程的 tx， 则执行
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
	// 此处 深拷贝 收据以避免不同任务之间的交互。
	receipts := make([]*types.Receipt, len(w.current.receipts))
	for i, l := range w.current.receipts {
		receipts[i] = new(types.Receipt)

		// 使用了 值复制 (然而 不能算是完整的 值复制，因为 receipt结构中还有其他字段指针的)
		*receipts[i] = *l
	}

	/***
	来一次， state 的 拷贝
	 */
	s := w.current.state.Copy()
	// 求实时的 根，填充 header 的root 字段
	block, err := w.engine.Finalize(w.chain, w.current.header, s, w.current.txs, uncles, w.current.receipts)
	if err != nil {
		return err
	}

	// 如果正在挖矿
	if w.isRunning() {
		// 不必理会的一个 调整函数 (钩子)
		if interval != nil {
			interval()
		}

		// 构建一个task，发送至 tsakCh
		select {
		case w.taskCh <- &task{receipts: receipts, state: s, block: block, createdAt: time.Now()}:

			// 翻页 未确定块集
			w.unconfirmed.Shift(block.NumberU64() - 1)

			// 计算下挖矿所需的手续费？？
			feesWei := new(big.Int)
			for i, tx := range block.Transactions() {
				feesWei.Add(feesWei, new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), tx.GasPrice()))
			}
			feesEth := new(big.Float).Quo(new(big.Float).SetInt(feesWei), new(big.Float).SetInt(big.NewInt(params.Ether)))

			log.Info("Commit new mining work", "number", block.Number(), "uncles", len(uncles), "txs", w.current.tcount,
				"gas", block.GasUsed(), "fees", feesEth, "elapsed", common.PrettyDuration(time.Since(start)))

		// 接收到 退出信号
		case <-w.exitCh:
			log.Info("Worker has exited")
		}
	}

	// 更新下 快照信息
	if update {
		w.updateSnapshot()
	}

	// 结束函数调用
	return nil
}
