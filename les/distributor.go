// Copyright 2017 The github.com/go-ethereum-analysis Authors
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

// Package light implements on-demand retrieval capable state and chain objects
// for the Ethereum Light Client.
package les

import (
	"container/list"
	"sync"
	"time"
)

// requestDistributor implements a mechanism that distributes requests to
// suitable peers, obeying flow control rules and prioritizing them in creation
// order (even when a resend is necessary).
/**
requestDistributor
实现了一种将请求分发到合适的peer的机制，
服从流控制规则并按创建顺序对它们进行优先级排序（即使需要重新发送）。
 */
// peerSetNotify 的一个实现
type requestDistributor struct {
	// 一个队列
	reqQueue         *list.List
	lastReqOrder     uint64
	peers            map[distPeer]struct{}
	peerLock         sync.RWMutex
	stopChn, loopChn chan struct{}
	loopNextSent     bool
	lock             sync.Mutex
}

// distPeer is an LES server peer interface for the request distributor.
// waitBefore returns either the necessary waiting time before sending a request
// with the given upper estimated cost or the estimated remaining relative buffer
// value after sending such a request (in which case the request can be sent
// immediately). At least one of these values is always zero.
//
//
/**
distPeer是请求分发器的 LES服务器peer 接口。
waitBefore 在发送具有给定的较高估计成本的请求之前返回必需的等待时间，
或者在发送此类请求之后返回估计的剩余相对缓冲区估计值
（在这种情况下，可以立即发送请求）。 这些值中的至少一个始终为零。

 */
type distPeer interface {
	waitBefore(uint64) (time.Duration, float64)
	canQueue() bool
	queueSend(f func())
}

// distReq is the request abstraction used by the distributor. It is based on
// three callback functions:
// - getCost returns the upper estimate of the cost of sending the request to a given peer
// - canSend tells if the server peer is suitable to serve the request
// - request prepares sending the request to the given peer and returns a function that
// does the actual sending. Request order should be preserved but the callback itself should not
// block until it is sent because other peers might still be able to receive requests while
// one of them is blocking. Instead, the returned function is put in the peer's send queue.
//
//
/**
distReq是分发服务器使用的请求抽象。 它基于三个回调函数：

- getCost 返回将请求发送到给定peer的开销的上限

- canSend 告知服务器peer是否适合处理请求

- request 准备将请求发送到给定的peer，并返回执行实际发送的功能。

应保留请求顺序，但回调请求本身必须等到发送后再阻塞，
因为其他peer可能仍能在其中一个阻塞时接收请求。
而是将返回的函数放在peer的发送队列中。

 */
type distReq struct {
	getCost func(distPeer) uint64
	canSend func(distPeer) bool
	request func(distPeer) func()

	reqOrder uint64
	sentChn  chan distPeer
	element  *list.Element
}

// newRequestDistributor creates a new request distributor
// 创建一个 请求分发器
func newRequestDistributor(peers *peerSet, stopChn chan struct{}) *requestDistributor {
	d := &requestDistributor{
		// 初始化请求的队列
		reqQueue: list.New(),
		// loop 信号chan
		loopChn:  make(chan struct{}, 2),
		// 退出信号 chan
		stopChn:  stopChn,
		// 缓存对端peer实例的 map
		peers:    make(map[distPeer]struct{}),
	}
	if peers != nil {
		// 逐个注册 peers中的 peer 到 请求分发器中
		peers.notify(d)
	}

	// todo 在这里处理各种 req
	go d.loop()
	return d
}

// registerPeer implements peerSetNotify
// 将所有某个时刻的 peerSet中的所有peer 注册到自己
func (d *requestDistributor) registerPeer(p *peer) {
	d.peerLock.Lock()
	d.peers[p] = struct{}{}
	d.peerLock.Unlock()
}

// unregisterPeer implements peerSetNotify
// 移除 peer
func (d *requestDistributor) unregisterPeer(p *peer) {
	d.peerLock.Lock()
	delete(d.peers, p)
	d.peerLock.Unlock()
}

// registerTestPeer adds a new test peer
func (d *requestDistributor) registerTestPeer(p distPeer) {
	d.peerLock.Lock()
	d.peers[p] = struct{}{}
	d.peerLock.Unlock()
}

// distMaxWait is the maximum waiting time after which further necessary waiting
// times are recalculated based on new feedback from the servers
const distMaxWait = time.Millisecond * 10

// main event loop
func (d *requestDistributor) loop() {
	for {
		select {

		// 是否接收到 退出信号
		case <-d.stopChn:
			d.lock.Lock()

			// 返回 队列中记录的 next 元素
			elem := d.reqQueue.Front()

			// 清空 队列中的 元素
			for elem != nil {
				close(elem.Value.(*distReq).sentChn)
				elem = elem.Next()
			}
			d.lock.Unlock()
			return

		// 接收到 loop 信号
		case <-d.loopChn:
			d.lock.Lock()

			// 先初始化 标识位 `loopNextSent`
			d.loopNextSent = false
		loop:
			// 一直清空队列中的请求req
			for {

				peer, req, wait := d.nextRequest()
				if req != nil && wait == 0 {
					chn := req.sentChn // save sentChn because remove sets it to nil   保存sendChn，因为remove将其设置为nil
					d.remove(req)

					// todo 获取 各自的 sendFunc
					send := req.request(peer)
					if send != nil {
						peer.queueSend(send)
					}
					chn <- peer
					close(chn)
				} else {
					if wait == 0 {
						// no request to send and nothing to wait for; the next
						// queued request will wake up the loop
						//
						// 当 没有req去send 且没有任何需要wait的,这时候 next req将继续loop
						break loop
					}
					// a "next" signal has been sent, do not send another one until this one has been received
					// 已发送“下一”信号，在收到该信号之前，请勿发送另一信号
					d.loopNextSent = true
					if wait > distMaxWait {
						// waiting times may be reduced by incoming request replies, if it is too long, recalculate it periodically
						// 入站请求回复可能会减少等待时间，如果时间太长，请定期重新计算
						wait = distMaxWait
					}
					go func() {
						time.Sleep(wait)
						d.loopChn <- struct{}{}
					}()
					break loop
				}
			}
			d.lock.Unlock()
		}
	}
}

// selectPeerItem represents a peer to be selected for a request by weightedRandomSelect
//
// selectPeerItem
// 表示要通过weightedRandomSelect选择用于请求的 peer
type selectPeerItem struct {
	peer   distPeer
	req    *distReq
	weight int64
}

// Weight implements wrsItem interface
func (sp selectPeerItem) Weight() int64 {
	return sp.weight
}

// nextRequest returns the next possible request from any peer, along with the
// associated peer and necessary waiting time
//
// nextRequest从任何peer返回下一个可能的请求，以及关联的peer和必要的等待时间
func (d *requestDistributor) nextRequest() (distPeer, *distReq, time.Duration) {

	// 初始化一个 有待 请求分发器检查的 les服务 peer的map
	checkedPeers := make(map[distPeer]struct{})
	// 从分发器的 peers缓存队列中取出next元素
	elem := d.reqQueue.Front()
	var (
		bestPeer distPeer
		bestReq  *distReq
		bestWait time.Duration
		sel      *weightedRandomSelect
	)

	d.peerLock.RLock()
	defer d.peerLock.RUnlock()

	for (len(d.peers) > 0 || elem == d.reqQueue.Front()) && elem != nil {

		// 获取 元素中对应的  req (请求， 可能是否个方法的调用干什么的) 实例
		req := elem.Value.(*distReq)

		// 是否可以发送请求了(即： 可以有资源处理请求了)
		canSend := false

		// TODO 遍历所有peer
		for peer := range d.peers {
			// 去重 且 告知服务器peer是否适合处理请求
			if _, ok := checkedPeers[peer]; !ok && peer.canQueue() && req.canSend(peer) {
				canSend = true
				// 返回将请求发送到给定peer的开销的上限
				cost := req.getCost(peer)

				// 返回以给定的最大估计成本发送请求之前所需的最短等待时间
				wait, bufRemain := peer.waitBefore(cost)
				if wait == 0 {
					if sel == nil {
						//  初始化一个 weightedRandomSelect
						//  weightedRandomSelect, 能够从一组项目中进行加权随机选择
						sel = newWeightedRandomSelect()
					}

					// selectPeerItem表示要通过weightedRandomSelect选择用于请求的peer
					//
					// 更新 selectItem 的权重
					sel.update(selectPeerItem{peer: peer, req: req, weight: int64(bufRemain*1000000) + 1})
				} else {
					if bestReq == nil || wait < bestWait {
						bestPeer = peer
						bestReq = req
						bestWait = wait
					}
				}
				checkedPeers[peer] = struct{}{}
			}
		}
		next := elem.Next()
		if !canSend && elem == d.reqQueue.Front() {
			close(req.sentChn)
			d.remove(req)
		}
		elem = next
	}

	if sel != nil {
		// TODO 随机返回一个 item
		c := sel.choose().(selectPeerItem)
		return c.peer, c.req, 0
	}
	return bestPeer, bestReq, bestWait
}

// queue adds a request to the distribution queue, returns a channel where the
// receiving peer is sent once the request has been sent (request callback returned).
// If the request is cancelled or timed out without suitable peers, the channel is
// closed without sending any peer references to it.
/**
queue:
将请求添加到分发队列，返回一个通道，
在该通道中，发送请求后将发送接收对等方（返回请求回调）。
如果在没有合适的对端peer的情况下取消或超时了该请求，
则该通道将关闭，而不发送任何对端peer的引用。

 */
func (d *requestDistributor) queue(r *distReq) chan distPeer {
	d.lock.Lock()
	defer d.lock.Unlock()

	if r.reqOrder == 0 {
		d.lastReqOrder++
		r.reqOrder = d.lastReqOrder
	}

	back := d.reqQueue.Back()
	if back == nil || r.reqOrder > back.Value.(*distReq).reqOrder {
		r.element = d.reqQueue.PushBack(r)
	} else {
		before := d.reqQueue.Front()
		for before.Value.(*distReq).reqOrder < r.reqOrder {
			before = before.Next()
		}
		r.element = d.reqQueue.InsertBefore(r, before)
	}

	if !d.loopNextSent {
		d.loopNextSent = true
		d.loopChn <- struct{}{}
	}

	r.sentChn = make(chan distPeer, 1)
	return r.sentChn
}

// cancel removes a request from the queue if it has not been sent yet (returns
// false if it has been sent already). It is guaranteed that the callback functions
// will not be called after cancel returns.
func (d *requestDistributor) cancel(r *distReq) bool {
	d.lock.Lock()
	defer d.lock.Unlock()

	if r.sentChn == nil {
		return false
	}

	close(r.sentChn)
	d.remove(r)
	return true
}

// remove removes a request from the queue
func (d *requestDistributor) remove(r *distReq) {
	r.sentChn = nil
	if r.element != nil {
		d.reqQueue.Remove(r.element)
		r.element = nil
	}
}
