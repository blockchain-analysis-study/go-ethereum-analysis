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

// Package miner implements Ethereum block creation and mining.
package miner

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/consensus"
	"github.com/go-ethereum-analysis/core"
	"github.com/go-ethereum-analysis/core/state"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/eth/downloader"
	"github.com/go-ethereum-analysis/event"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/params"
)

// Backend wraps all methods required for mining.
type Backend interface {
	BlockChain() *core.BlockChain
	TxPool() *core.TxPool
}

// Miner creates blocks and searches for proof-of-work values.
type Miner struct {
	// 一个在初始化的时候 从外界传进来的  事件
	mux      *event.TypeMux
	// worker 实例(挖矿的真正工作者)
	worker   *worker
	// 矿工账户
	coinbase common.Address
	// 全局的 Ethereum 实例
	eth      Backend
	// 共识引擎
	engine   consensus.Engine
	// 接收退出信号的 Chan
	exitCh   chan struct{}

	// 可以开始表明我们是否可以开始采矿作业 1: 可以挖矿；  0: 不可以
	canStart    int32 // can start indicates whether we can start the mining operation
	// 应该开始表明我们是否应该在同步后开始 (即：在区块同步之后)  1: 是需要在同步之后； 0: 不需要
	shouldStart int32 // should start indicates whether we should start after sync
}

func New(eth Backend, config *params.ChainConfig, mux *event.TypeMux, engine consensus.Engine, recommit time.Duration) *Miner {
	/**
	创建 一个 miner 实例
	 */
	miner := &Miner{
		// 全局的 Ethereum 实例
		eth:      eth,
		// 事件 (已经过时，后续可能都用 feed) 引用了 Ethereum 实例的
		mux:      mux,
		// 共识引擎
		engine:   engine,
		// 一个退出信号的 通道
		exitCh:   make(chan struct{}),
		// 一个 worker 实例
		worker:   newWorker(config, engine, eth, mux, recommit),
		// 表明是否 开始挖矿的 标识位
		canStart: 1,
	}

	// 开始一个 守护进程
	go miner.update()

	// 返回 miner 实例
	return miner
}

// update keeps track of the downloader events. Please be aware that this is a one shot type of update loop.
// It's entered once and as soon as `Done` or `Failed` has been broadcasted the events are unregistered and
// the loop is exited. This to prevent a major security vuln where external parties can DOS you with blocks
// and halt your mining operation for as long as the DOS continues.
/***
update跟踪 downloader 的事件。 请注意，这是一种单击类型的更新循环。
它被输入一次，一旦广播“完成”或“失败”，事件就会被注销，循环就会退出。
这可以防止一个主要的安全漏洞，外部各方可以使用块来阻止你并且只要DOS继续就停止你的挖掘操作。
 */
func (self *Miner) update() {
	// 订阅 downloader 过来的 三种事件类型：同步开始、同步结束、同步失败
	events := self.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})
	defer events.Unsubscribe()

	/**
	死循环 处理

	注意，由于直接在 for - select 结构中 使用 return 其实只是影响当前 本次 select 的哦
	for  不会被停止，(需要 for 停止的话，需要 用 return 或者 break 去分别加上 label 来实现)
	 */
	for {
		select {
		/**
		监听 事件通道中的 事件
		*/
		case ev := <-events.Chan():
			if ev == nil {
				return
			}

			/** 判断事件类型 */
			switch ev.Data.(type) {

			// 如果是 start 信号的事件
			case downloader.StartEvent:

				// 启动原子操作 将 canStart 标识位改为 0
				// 原因是 downloader 在工作的时候 需要停止 miner 的打包区块 工作
				atomic.StoreInt32(&self.canStart, 0)
				// 判断挖矿标识位
				if self.Mining() {
					// 停止 挖矿动作
					self.Stop()
					// 将 是否在 区块同步完之后开启 挖矿的标识位 改成 1
					atomic.StoreInt32(&self.shouldStart, 1)
					log.Info("Mining aborted due to sync")  // downloader 同步的时候需要暂停掉 挖矿
				}

			// 如果是 Done 或者 Failed 信号的事件
			// 标识，download 区块完成 或者 失败 都重新启动挖矿
			case downloader.DoneEvent, downloader.FailedEvent:
				// 为了各个状态 一致所以需要先判断标识位
				shouldStart := atomic.LoadInt32(&self.shouldStart) == 1

				// 复位各个标识位
				atomic.StoreInt32(&self.canStart, 1)
				atomic.StoreInt32(&self.shouldStart, 0)

				// 重新启动挖矿
				if shouldStart {
					self.Start(self.coinbase)
				}
				// stop immediately and ignore all further pending events
				// 立即停止并忽略所有其他待处理事件
				return
			}

		/**
		如果事件通道中没值 而 miner 的 exitCh 中有值的话，则直接 return 本次 select
		*/
		case <-self.exitCh:
			return
		}
	}
}

/**
启动 挖矿
 */
func (self *Miner) Start(coinbase common.Address) {
	// 这里 又将 shouldStart 改成 1 的用意 ？？
	atomic.StoreInt32(&self.shouldStart, 1)
	// 设置 coinbase
	self.SetEtherbase(coinbase)

	// 判断 canStart 标识位， 如果处于同步阶段 那么不可以挖矿
	// (因为 miner.Start 方法，不止是在一个地方启动调用， 及每次都需要判断是否在 同步区块哦)
	if atomic.LoadInt32(&self.canStart) == 0 {
		log.Info("Network syncing, will start miner afterwards")
		return
	}
	/**
	【注意】
	其实，真正的挖矿任务交由 worker 去实现的哦
	 */
	self.worker.start()
}

/**
停止 挖矿
 */
func (self *Miner) Stop() {
	// 停止 worker 的挖矿任务
	self.worker.stop()
	// 将 shouldStart 改为 0
	atomic.StoreInt32(&self.shouldStart, 0)
}

// 关闭 worker 的 信号通道及 miner 的 exitCh
func (self *Miner) Close() {
	self.worker.close()
	close(self.exitCh)
}

// 获取是否正在 挖矿的标识位
func (self *Miner) Mining() bool {
	return self.worker.isRunning()
}

// 返回什么 pow 速率 ？？ 貌似为了做统计用的
func (self *Miner) HashRate() uint64 {
	if pow, ok := self.engine.(consensus.PoW); ok {
		return uint64(pow.Hashrate())
	}
	return 0
}

// 设置 block 中的 extra 字段的默认值
func (self *Miner) SetExtra(extra []byte) error {
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("Extra exceeds max length. %d > %v", len(extra), params.MaximumExtraDataSize)
	}
	self.worker.setExtra(extra)
	return nil
}

// SetRecommitInterval sets the interval for sealing work resubmitting.
// SetRecommitInterval函数：
// 设置密封工作重新提交的间隔。
func (self *Miner) SetRecommitInterval(interval time.Duration) {
	self.worker.setRecommitInterval(interval)
}

// Pending returns the currently pending block and associated state.
// Pending函数：
// 返回当前挂起的块和关联的 state。
func (self *Miner) Pending() (*types.Block, *state.StateDB) {
	return self.worker.pending()
}

// PendingBlock returns the currently pending block.
//
// Note, to access both the pending block and the pending state
// simultaneously, please use Pending(), as the pending state can
// change between multiple method calls
/**
PendingBlock 函数：
返回当前正在阻塞的 block

【注意】，要同时访问挂起块和挂起状态，请使用Pending（），
因为挂起 state 可以在多个方法调用之间更改
 */
func (self *Miner) PendingBlock() *types.Block {
	return self.worker.pendingBlock()
}

// 设置 coinbase
func (self *Miner) SetEtherbase(addr common.Address) {
	self.coinbase = addr
	self.worker.setEtherbase(addr)
}
