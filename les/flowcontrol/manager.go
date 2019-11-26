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

// Package flowcontrol implements a client side flow control mechanism
package flowcontrol

import (
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common/mclock"
)

const rcConst = 1000000


// clientManager中的 peer 的实例
type cmNode struct {
	// 这个才是 轻节点的实例
	node                         *ClientNode
	// 最后一次更新的时间!?
	lastUpdate                   mclock.AbsTime

	// 服务中; 正在充电中
	// 说白了就是 Server的服务中; 或者Client的接收中
	serving, recharging          bool
	// 允许充电的大小?
	rcWeight                     uint64

	// 每个节点充电的value真实大小 ?;  ;
	rcValue, rcDelta, startValue int64

	// 节点完成 充电的时间
	// 即: 接收数据校验的时间
	finishRecharge               mclock.AbsTime
}

// 更新最后一次操作的时间
func (node *cmNode) update(time mclock.AbsTime) {

	// 求差值
	dt := int64(time - node.lastUpdate)

	// A = A+B *差值/1000000
	node.rcValue += node.rcDelta * dt / rcConst
	// todo 更新最后操作的时间
	node.lastUpdate = time
	// 如果该节点是在充电中 且 当前time >= 接收数据校验的时间
	//
	// 说白了就是处理超时了
	if node.recharging && time >= node.finishRecharge {

		// 重置状态标识位
		node.recharging = false
		// 重置几个接收数据相关的计数值
		node.rcDelta = 0
		node.rcValue = 0
	}
}

func (node *cmNode) set(serving bool, simReqCnt, sumWeight uint64) {
	if node.serving && !serving {
		node.recharging = true
		sumWeight += node.rcWeight
	}
	node.serving = serving
	if node.recharging && serving {
		node.recharging = false
		sumWeight -= node.rcWeight
	}

	node.rcDelta = 0
	if serving {
		node.rcDelta = int64(rcConst / simReqCnt)
	}
	if node.recharging {
		node.rcDelta = -int64(node.node.cm.rcRecharge * node.rcWeight / sumWeight)
		node.finishRecharge = node.lastUpdate + mclock.AbsTime(node.rcValue*rcConst/(-node.rcDelta))
	}
}

// CHT: Canonical Hash Trie, 规范哈希树

// 这是一个 轻节点的 client 端的管理器
type ClientManager struct {
	lock                             sync.Mutex
	// 被管理的所有 client
	nodes                            map[*cmNode]struct{}



	// simpleReqClient; 累计每个 node 的 充电容量的大小;  // 累计每个 node 的 真实充电量?
	simReqCnt, sumWeight, rcSumValue uint64

	// 最多可以处理多少 req; 最多可以处理多少 容量
	maxSimReq, maxRcSum              uint64
	rcRecharge                       uint64
	resumeQueue                      chan chan bool
	time                             mclock.AbsTime
}

func NewClientManager(rcTarget, maxSimReq, maxRcSum uint64) *ClientManager {
	cm := &ClientManager{
		nodes:       make(map[*cmNode]struct{}),
		resumeQueue: make(chan chan bool),
		rcRecharge:  rcConst * rcConst / (100*rcConst/rcTarget - rcConst),
		maxSimReq:   maxSimReq,
		maxRcSum:    maxRcSum,
	}
	go cm.queueProc()
	return cm
}

func (self *ClientManager) Stop() {
	self.lock.Lock()
	defer self.lock.Unlock()

	// signal any waiting accept routines to return false
	self.nodes = make(map[*cmNode]struct{})
	close(self.resumeQueue)
}

func (self *ClientManager) addNode(cnode *ClientNode) *cmNode {
	time := mclock.Now()
	node := &cmNode{
		node:           cnode,
		lastUpdate:     time,
		finishRecharge: time,
		rcWeight:       1,
	}
	self.lock.Lock()
	defer self.lock.Unlock()

	self.nodes[node] = struct{}{}
	self.update(mclock.Now())
	return node
}

func (self *ClientManager) removeNode(node *cmNode) {
	self.lock.Lock()
	defer self.lock.Unlock()

	time := mclock.Now()
	self.stop(node, time)
	delete(self.nodes, node)
	self.update(time)
}

// recalc sumWeight
// 重新计算sumWeight
func (self *ClientManager) updateNodes(time mclock.AbsTime) (rce bool) {


	var sumWeight, rcSum uint64

	// 遍历所有nodes
	for node := range self.nodes {

		// 获取 是否充电标识位
		rc := node.recharging

		// todo 使用当前时间 更新每一个node的lastUpdate字段 ;(这里面可能会再次更新 node.recharging 的值)
		node.update(time)

		// 如果之前是充电中的, 而后来变成了没有充电 (因为: 可能充电超时
		if rc && !node.recharging {
			rce = true
		}


		// 如果还在 充电中
		if node.recharging {

			// 累计每个 node 的 充电容量的大小
			sumWeight += node.rcWeight
		}

		// 累计每个 node 的 真实充电量?
		rcSum += uint64(node.rcValue)
	}
	self.sumWeight = sumWeight
	self.rcSumValue = rcSum
	return
}

func (self *ClientManager) update(time mclock.AbsTime) {
	for {
		firstTime := time

		// 遍历在manager中所有 node
		for node := range self.nodes {

			// 如果该node是client,且正在充电中 且该节点规定的完成充电时间小于当前时间
			if node.recharging && node.finishRecharge < firstTime {
				// 拿该时间作为 firstTime
				firstTime = node.finishRecharge
			}
		}

		// 最后获取奥最小的 firstTime
		// 并用这个最小的 firstTime 逐个更新 node中的lastUpdate字段
		// 并且重新计算 manager的sumWeight
		//
		// 如果其中只要有 node 处理超时了
		if self.updateNodes(firstTime) {

			// 需要逐个将所有处于正在 充电中的 node 做某些重新计算!? todo 有点看不懂啊
			for node := range self.nodes {
				if node.recharging {
					node.set(node.serving, self.simReqCnt, self.sumWeight)
				}
			}
		} else {
			// 更新下 time 字段
			self.time = time
			return
		}
	}
}


// 表示当前 manager 是否可以开始做 req 了
func (self *ClientManager) canStartReq() bool {
	return self.simReqCnt < self.maxSimReq && self.rcSumValue < self.maxRcSum
}

func (self *ClientManager) queueProc() {
	for rc := range self.resumeQueue {
		for {
			time.Sleep(time.Millisecond * 10)
			self.lock.Lock()
			self.update(mclock.Now())
			cs := self.canStartReq()
			self.lock.Unlock()
			if cs {
				break
			}
		}
		close(rc)
	}
}

// 判断 node 是否可以被处理?
func (self *ClientManager) accept(node *cmNode, time mclock.AbsTime) bool {
	self.lock.Lock()
	defer self.lock.Unlock()

	self.update(time)
	if !self.canStartReq() {
		resume := make(chan bool)
		self.lock.Unlock()
		self.resumeQueue <- resume
		<-resume
		self.lock.Lock()

		if _, ok := self.nodes[node]; !ok {
			// 如果节点已删除或管理器已停止，则拒绝
			return false // reject if node has been removed or manager has been stopped
		}
	}

	// simpleReqClient
	self.simReqCnt++
	node.set(true, self.simReqCnt, self.sumWeight)
	node.startValue = node.rcValue
	self.update(self.time)
	return true
}

func (self *ClientManager) stop(node *cmNode, time mclock.AbsTime) {
	if node.serving {
		self.update(time)
		self.simReqCnt--
		node.set(false, self.simReqCnt, self.sumWeight)
		self.update(time)
	}
}

func (self *ClientManager) processed(node *cmNode, time mclock.AbsTime) (rcValue, rcCost uint64) {
	self.lock.Lock()
	defer self.lock.Unlock()

	self.stop(node, time)
	return uint64(node.rcValue), uint64(node.rcValue - node.startValue)
}
