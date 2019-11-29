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

// todo 包流量控制实现了客户端流量控制机制

/**
流量控制
 */
package flowcontrol

import (
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common/mclock"
)

const fcTimeConst = time.Millisecond

// 握手时的重要参数
// recharge，代表这个server所能服务的请求能力，以及server运维者可以通过这个限制进行使用
// todo recharge: 恢复速度总和 (恢复什么, 恢复 镜像令牌桶 buffer, 也就是说当具备更多的令牌 <buffer> 时才可以被请求)
type ServerParams struct {
	// todo server端可能同时有多个client，
	//  恢复速度总和在server端有一个上限叫recharge，
	//  代表这个server所能服务的请求能力，
	//  以及server运维者可以通过这个限制进行使用

	// 缓存的限制,  最低恢复速度总和
	BufLimit, MinRecharge uint64
}

// todo 流量控制 client
// 这是实现一个 轻节点链接的 client端 (就是一个轻节点)
type ClientNode struct {
	params   *ServerParams

	// 该peer 被允许的缓存数量大小
	bufValue uint64

	// 上一次最后请求的 time
	lastTime mclock.AbsTime
	lock     sync.Mutex
	cm       *ClientManager

	// clientManager中的 该peer 的实例
	cmNode   *cmNode
}

/**
创建一个 light 模式的client
 */
func NewClientNode(cm *ClientManager, params *ServerParams) *ClientNode {
	node := &ClientNode{
		cm:       cm,
		params:   params,
		bufValue: params.BufLimit,
		lastTime: mclock.Now(),
	}
	node.cmNode = cm.addNode(node)
	return node
}

func (peer *ClientNode) Remove(cm *ClientManager) {
	cm.removeNode(peer.cmNode)
}

func (peer *ClientNode) recalcBV(time mclock.AbsTime) {

	// 当前时间 距 上一次请求该peer 的最后时间的 差值A
	dt := uint64(time - peer.lastTime)
	if time < peer.lastTime {  // 一般不可能存在这个吧
		dt = 0
	}


	// 该peer的被给予缓存数量的大小 =  该peer的被给予缓存数量的大小 + 最低充值率*差值A/1ms
	peer.bufValue += peer.params.MinRecharge * dt / uint64(fcTimeConst)

	// 如果 该peer的被给予缓存数量的大小 > 缓存的限制
	// 则, 就等于 缓存的限制
	if peer.bufValue > peer.params.BufLimit {
		peer.bufValue = peer.params.BufLimit
	}
	// 刷新最后一次请求时间
	peer.lastTime = time
}

func (peer *ClientNode) AcceptRequest() (uint64, bool) {
	peer.lock.Lock()
	defer peer.lock.Unlock()

	time := mclock.Now()

	// 重新计算 peer 的缓存数量大小和最后一次请求时间
	peer.recalcBV(time)
	// 第一参数: 该peer 被允许的缓存数量大小
	// 第二参数: 判断 node 是否可以被处理?
	return peer.bufValue, peer.cm.accept(peer.cmNode, time)
}

func (peer *ClientNode) RequestProcessed(cost uint64) (bv, realCost uint64) {
	peer.lock.Lock()
	defer peer.lock.Unlock()

	time := mclock.Now()
	peer.recalcBV(time)
	peer.bufValue -= cost
	peer.recalcBV(time)
	rcValue, rcost := peer.cm.processed(peer.cmNode, time)
	if rcValue < peer.params.BufLimit {
		bv := peer.params.BufLimit - rcValue
		if bv > peer.bufValue {
			peer.bufValue = bv
		}
	}
	return peer.bufValue, rcost
}


// todo 流量控制 Server
// 这是实现一个轻节点链接的 Server端 (一个全节点)
// 每个server 挂着多个client
// recharge，代表这个server所能服务的请求能力，以及server运维者可以通过这个限制进行使用
type ServerNode struct {
	// 需要开辟多少内存用来支持 s/c的同步的估算值<剩余量>
	bufEstimate uint64

	//最后一次操作的时间
	lastTime    mclock.AbsTime
	// server端的一些参数, 只有支持这些参数的client才可以连接
	params      *ServerParams
	// 发送到此服务器的请求费用总和 (累计消耗)
	sumCost     uint64            // sum of req costs sent to this server
	// value = 发送给定请求后的sumCost
	pending     map[uint64]uint64 // value = sumCost after sending the given req
	lock        sync.RWMutex
}

func NewServerNode(params *ServerParams) *ServerNode {
	return &ServerNode{
		bufEstimate: params.BufLimit,
		lastTime:    mclock.Now(),
		params:      params,
		pending:     make(map[uint64]uint64),
	}
}

func (peer *ServerNode) recalcBLE(time mclock.AbsTime) {
	dt := uint64(time - peer.lastTime)
	if time < peer.lastTime {
		dt = 0
	}
	peer.bufEstimate += peer.params.MinRecharge * dt / uint64(fcTimeConst)
	if peer.bufEstimate > peer.params.BufLimit {
		peer.bufEstimate = peer.params.BufLimit
	}
	peer.lastTime = time
}

// safetyMargin is added to the flow control waiting time when estimated buffer value is low
//
// 当估计的缓冲区值较低时，将safetyMargin添加到流控制等待时间
const safetyMargin = time.Millisecond


//握手时声明的3个参数为：
//
// Buffer Limit
// Maximum Request Cost table
// Minimum Rate of Recharge
//
func (peer *ServerNode) canSend(maxCost uint64) (time.Duration, float64) {
	peer.recalcBLE(mclock.Now()) // 客户总是对其电流有一个最低的估计BV，称为BLE
	maxCost += uint64(safetyMargin) * peer.params.MinRecharge / uint64(fcTimeConst)
	if maxCost > peer.params.BufLimit {
		maxCost = peer.params.BufLimit
	}
	if peer.bufEstimate >= maxCost {
		return 0, float64(peer.bufEstimate-maxCost) / float64(peer.params.BufLimit)
	}
	return time.Duration((maxCost - peer.bufEstimate) * uint64(fcTimeConst) / peer.params.MinRecharge), 0
}

// CanSend returns the minimum waiting time required before sending a request
// with the given maximum estimated cost. Second return value is the relative
// estimated buffer level after sending the request (divided by BufLimit).
//
//
// CanSend
// 返回以给定的最大估计成本发送请求之前所需的最短等待时间。
// 第二个返回值是发送请求后的相对估计缓冲区级别（由BufLimit划分）。
func (peer *ServerNode) CanSend(maxCost uint64) (time.Duration, float64) {
	peer.lock.RLock()
	defer peer.lock.RUnlock()

	return peer.canSend(maxCost)
}

// QueueRequest should be called when the request has been assigned to the given
// server node, before putting it in the send queue. It is mandatory that requests
// are sent in the same order as the QueueRequest calls are made.
//
/**
QueueRequest:
QueueRequest 将在 req 被分配给定的 server时,在加入发送队列之前被调用.
必须以与发出QueueRequest调用相同的顺序发送请求。
 */
func (peer *ServerNode) QueueRequest(reqID, maxCost uint64) {
	peer.lock.Lock()
	defer peer.lock.Unlock()

	// 将对端peer 的预估的剩余令牌 - 本次可能使用的消耗
	peer.bufEstimate -= maxCost
	// 将本次消耗追加到 累计消耗上
	peer.sumCost += maxCost
	// 将累计消耗和对应的reqId丢到 pending中
	peer.pending[reqID] = peer.sumCost
}

// GotReply adjusts estimated buffer value according to the value included in
// the latest request reply.
//
/**
GotReply:
根据最新请求回复中包含的值来调整估计的缓冲区值。
 */
func (peer *ServerNode) GotReply(reqID, bv uint64) {

	peer.lock.Lock()
	defer peer.lock.Unlock()

	if bv > peer.params.BufLimit {
		bv = peer.params.BufLimit
	}
	sc, ok := peer.pending[reqID]
	if !ok {
		return
	}
	delete(peer.pending, reqID)
	cc := peer.sumCost - sc
	peer.bufEstimate = 0
	if bv > cc {
		peer.bufEstimate = bv - cc
	}
	peer.lastTime = mclock.Now()
}
