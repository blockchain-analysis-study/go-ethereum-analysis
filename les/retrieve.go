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
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common/mclock"
	"github.com/go-ethereum-analysis/light"
)

var (
	retryQueue         = time.Millisecond * 100
	softRequestTimeout = time.Millisecond * 500
	hardRequestTimeout = time.Second * 10
)

// retrieveManager is a layer on top of requestDistributor which takes care of
// matching replies by request ID and handles timeouts and resends if necessary.
//
/**
resolveManager
是requestDistributor (请求分发器)之上的一层，负责按请求ID匹配答复，并处理超时并在必要时重新发送。
 */
type retrieveManager struct {
	// todo 这个才是真正的 请求分发器
	dist       *requestDistributor

	// 对端的 peerSet
	peers      *peerSet

	// 只有 client 端的 retrieveManager 才会有吧 !?
	// 实现一个池，用于存储和选择新发现的和已知的轻型服务器节点 <轻节点>。
	serverPool peerSelector

	lock     sync.RWMutex

	// todo 请求分发器中的所有 sendReq
	sentReqs map[uint64]*sentReq
}

// validatorFunc is a function that processes a reply message
type validatorFunc func(distPeer, *Msg) error

// peerSelector receives feedback info about response times and timeouts
//
/**
peerSelector: 接收有关 resp 时间和超时的反馈信息
 */
type peerSelector interface {
	adjustResponseTime(*poolEntry, time.Duration, bool)
}

// sentReq represents a request sent and tracked by retrieveManager
//
/**
sentReq:
代表由 retrieveManager 发送和跟踪的 req
 */
type sentReq struct {

	// 请求分发器的引用
	rm       *retrieveManager
	// 分发req 的实例
	req      *distReq
	// reqID
	id       uint64

	// req validatorFunc 引用
	validate validatorFunc

	// event 的 chan
	eventsCh chan reqPeerEvent
	stopCh   chan struct{}
	stopped  bool
	err      error

	lock   sync.RWMutex // protect access to sentTo map

	//  distPeer是请求分发器的 LES服务器peer 接口
	sentTo map[distPeer]sentReqToPeer

	// 最后一个 已排队但未发送的req
	lastReqQueued bool     // last request has been queued but not sent
	// 如果不是nil，则表示 最后一个请求已发送到给定 peer，但未超时
	lastReqSentTo distPeer // if not nil then last request has been sent to given peer but not timed out

	// 达到软（但不是硬）超时的请求数
	reqSrtoCount  int      // number of requests that reached soft (but not hard) timeout
}

// sentReqToPeer notifies the request-from-peer goroutine (tryRequest) about a response
// delivered by the given peer. Only one delivery is allowed per request per peer,
// after which delivered is set to true, the validity of the response is sent on the
// valid channel and no more responses are accepted.
//
/**
sentReqToPeer:
将有关给定 peer 传递的 resp 的 msg 通知给 对等请求goroutine（tryRequest）。
每个 peer 的每个 req 仅允许一次传递，之后将传递设置为true，将在有效通道上发送响应的有效性，并且不再接受其他响应。
 */
type sentReqToPeer struct {
	delivered bool
	valid     chan bool
}

// reqPeerEvent is sent by the request-from-peer goroutine (tryRequest) to the
// request state machine (retrieveLoop) through the eventsCh channel.
type reqPeerEvent struct {
	event int
	peer  distPeer
}

const (
	rpSent = iota // if peer == nil, not sent (no suitable peers)
	rpSoftTimeout
	rpHardTimeout
	rpDeliveredValid
	rpDeliveredInvalid
)

// newRetrieveManager creates the retrieve manager
func newRetrieveManager(peers *peerSet, dist *requestDistributor, serverPool peerSelector) *retrieveManager {
	return &retrieveManager{
		peers:      peers,
		dist:       dist,
		serverPool: serverPool,
		sentReqs:   make(map[uint64]*sentReq),
	}
}

// retrieve sends a request (to multiple peers if necessary) and waits for an answer
// that is delivered through the deliver function and successfully validated by the
// validator callback. It returns when a valid answer is delivered or the context is
// cancelled.
//
/**
retrieve:
发送一个请求（如果需要，可以发送给多个对等方），
并等待通过传递功能传递并由验证程序回调成功验证的答案。
当提供有效答案或取消上下文时，它将返回。
 */
func (rm *retrieveManager) retrieve(ctx context.Context, reqID uint64, req *distReq, val validatorFunc, shutdown chan struct{}) error {

	// todo 创建 拉取 req
	sentReq := rm.sendReq(reqID, req, val)
	select {
	case <-sentReq.stopCh:
	case <-ctx.Done():
		sentReq.stop(ctx.Err())
	case <-shutdown:
		sentReq.stop(fmt.Errorf("Client is shutting down"))
	}
	return sentReq.getError()
}

// sendReq starts a process that keeps trying to retrieve a valid answer for a
// request from any suitable peers until stopped or succeeded.
//
/**
todo 超级重要
		创建 sendReq
 */
func (rm *retrieveManager) sendReq(reqID uint64, req *distReq, val validatorFunc) *sentReq {

	r := &sentReq{
		rm:       rm,
		req:      req,
		id:       reqID,
		sentTo:   make(map[distPeer]sentReqToPeer),
		stopCh:   make(chan struct{}),
		eventsCh: make(chan reqPeerEvent, 10),
		validate: val,
	}

	canSend := req.canSend
	req.canSend = func(p distPeer) bool {
		// add an extra check to canSend: the request has not been sent to the same peer before
		r.lock.RLock()
		_, sent := r.sentTo[p]
		r.lock.RUnlock()
		return !sent && canSend(p)
	}


	request := req.request
	// todo 将func 向外再封装一层 注意: 很多发起 p2p 的请求 func 都是 req.request 中
	req.request = func(p distPeer) func() {
		// before actually sending the request, put an entry into the sentTo map
		r.lock.Lock()
		r.sentTo[p] = sentReqToPeer{false, make(chan bool, 1)}
		r.lock.Unlock()
		return request(p)
	}
	rm.lock.Lock()

	// todo 将请求追加到 请求分发器
	rm.sentReqs[reqID] = r
	rm.lock.Unlock()


	/**
	TODO 超级重要, 这个就是 sendReq 自我处理, 即各种请求重试, 请求调整
	 */
	go r.retrieveLoop()
	return r
}

// deliver is called by the LES protocol manager to deliver reply messages to waiting requests
//
// deliver:
// deliver 被 LES protocol manager 调用来 答复消息传递给等待的 reqs
func (rm *retrieveManager) deliver(peer distPeer, msg *Msg) error {
	rm.lock.RLock()
	// 根据响应的reqId 处理响应的 req, msg 是resp 的msg
	req, ok := rm.sentReqs[msg.ReqID]
	rm.lock.RUnlock()

	if ok {
		/**
		todo  啦啦啦, 上上上~
		 */
		return req.deliver(peer, msg)
	}
	return errResp(ErrUnexpectedResponse, "reqID = %v", msg.ReqID)
}

// reqStateFn represents a state of the retrieve loop state machine
type reqStateFn func() reqStateFn

// retrieveLoop is the retrieval state machine event loop
func (r *sentReq) retrieveLoop() {

	// todo 重要
	/**
	tryRequest:
	尝试将 req 发送到新 peer，并等待 req成功或超时（如果已发送）.
	它还将适当的reqPeerEvent消息发送到请求的事件通道。
	*/
	go r.tryRequest()


	r.lastReqQueued = true
	state := r.stateRequesting

	for state != nil {
		state = state()
	}

	r.rm.lock.Lock()
	delete(r.rm.sentReqs, r.id)
	r.rm.lock.Unlock()
}

// stateRequesting: a request has been queued or sent recently; when it reaches soft timeout,
// a new request is sent to a new peer
//
/**
stateRequesting：
一个 req 已被排队或最近发送； todo 当达到软超时时，新 req 将发送到新 peer
 */
func (r *sentReq) stateRequesting() reqStateFn {
	select {
	case ev := <-r.eventsCh:
		r.update(ev)
		switch ev.event {
		case rpSent:
			if ev.peer == nil {
				// request send failed, no more suitable peers
				if r.waiting() {
					// we are already waiting for sent requests which may succeed so keep waiting
					return r.stateNoMorePeers
				}
				// nothing to wait for, no more peers to ask, return with error
				r.stop(light.ErrNoPeers)
				// no need to go to stopped state because waiting() already returned false
				return nil
			}
		case rpSoftTimeout:
			// last request timed out, try asking a new peer
			go r.tryRequest()
			r.lastReqQueued = true
			return r.stateRequesting
		case rpDeliveredValid:
			r.stop(nil)
			return r.stateStopped
		}
		return r.stateRequesting
	case <-r.stopCh:
		return r.stateStopped
	}
}

// stateNoMorePeers: could not send more requests because no suitable peers are available.
// Peers may become suitable for a certain request later or new peers may appear so we
// keep trying.
//
/**
stateNoMorePeers：
无法发送更多 req ，因为没有合适的 peer。
peer可能以后会适合某个req，或者可能会出现新的 peer，因此我们会继续尝试。
 */
func (r *sentReq) stateNoMorePeers() reqStateFn {
	select {
	case <-time.After(retryQueue):
		go r.tryRequest()
		r.lastReqQueued = true
		return r.stateRequesting
	case ev := <-r.eventsCh:
		r.update(ev)
		if ev.event == rpDeliveredValid {
			r.stop(nil)
			return r.stateStopped
		}
		return r.stateNoMorePeers
	case <-r.stopCh:
		return r.stateStopped
	}
}

// stateStopped: request succeeded or cancelled, just waiting for some peers
// to either answer or time out hard
func (r *sentReq) stateStopped() reqStateFn {
	for r.waiting() {
		r.update(<-r.eventsCh)
	}
	return nil
}

// update updates the queued/sent flags and timed out peers counter according to the event
//
/**
update:
根据事件更新 queued/sent 的标志并超时记录 peer的计数器
 */
func (r *sentReq) update(ev reqPeerEvent) {
	switch ev.event {
	case rpSent:
		r.lastReqQueued = false
		r.lastReqSentTo = ev.peer
	case rpSoftTimeout:
		r.lastReqSentTo = nil
		r.reqSrtoCount++
	case rpHardTimeout:
		r.reqSrtoCount--
	case rpDeliveredValid, rpDeliveredInvalid:
		if ev.peer == r.lastReqSentTo {
			r.lastReqSentTo = nil
		} else {
			r.reqSrtoCount--
		}
	}
}

// waiting returns true if the retrieval mechanism is waiting for an answer from
// any peer
func (r *sentReq) waiting() bool {
	return r.lastReqQueued || r.lastReqSentTo != nil || r.reqSrtoCount > 0
}

// tryRequest tries to send the request to a new peer and waits for it to either
// succeed or time out if it has been sent. It also sends the appropriate reqPeerEvent
// messages to the request's event channel.
//
/**
todo 超级重要
tryRequest:
尝试将 req 发送到新 peer，并等待 req成功或超时（如果已发送）.
它还将适当的reqPeerEvent消息发送到请求的事件通道。
 */
func (r *sentReq) tryRequest() {

	// todo 将 req 入队,并发起 分发器 的loop 信号
	sent := r.rm.dist.queue(r.req)
	var p distPeer
	select {
	case p = <-sent:
	case <-r.stopCh:
		if r.rm.dist.cancel(r.req) {
			p = nil
		} else {
			p = <-sent
		}
	}

	// todo 发起 尝试req event 通知
	r.eventsCh <- reqPeerEvent{rpSent, p}
	if p == nil {
		return
	}

	reqSent := mclock.Now()
	srto, hrto := false, false

	r.lock.RLock()
	s, ok := r.sentTo[p]
	r.lock.RUnlock()
	if !ok {
		panic(nil)
	}

	defer func() {
		// send feedback to server pool and remove peer if hard timeout happened
		pp, ok := p.(*peer)
		if ok && r.rm.serverPool != nil {
			respTime := time.Duration(mclock.Now() - reqSent)
			r.rm.serverPool.adjustResponseTime(pp.poolEntry, respTime, srto)
		}
		if hrto {
			pp.Log().Debug("Request timed out hard")
			if r.rm.peers != nil {
				r.rm.peers.Unregister(pp.id)
			}
		}

		r.lock.Lock()
		delete(r.sentTo, p)
		r.lock.Unlock()
	}()


	/**
	todo 软延迟
	 */
	select {
	case ok := <-s.valid:
		if ok {
			r.eventsCh <- reqPeerEvent{rpDeliveredValid, p}
		} else {
			r.eventsCh <- reqPeerEvent{rpDeliveredInvalid, p}
		}
		return
	case <-time.After(softRequestTimeout):
		srto = true
		r.eventsCh <- reqPeerEvent{rpSoftTimeout, p}
	}

	/**
	todo 硬延迟
	 */
	select {
	case ok := <-s.valid:
		if ok {
			r.eventsCh <- reqPeerEvent{rpDeliveredValid, p}
		} else {
			r.eventsCh <- reqPeerEvent{rpDeliveredInvalid, p}
		}
	case <-time.After(hardRequestTimeout):
		hrto = true
		r.eventsCh <- reqPeerEvent{rpHardTimeout, p}
	}
}

// deliver a reply belonging to this request
//
// 传递属于此 req 的回复
/**
sentReq:
代表由 retrieveManager 发送和跟踪的 req
*/
func (r *sentReq) deliver(peer distPeer, msg *Msg) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	s, ok := r.sentTo[peer]
	if !ok || s.delivered {
		return errResp(ErrUnexpectedResponse, "reqID = %v", msg.ReqID)
	}

	/**
	r.validate(peer, msg)
	其实是
	lreq.Validate(odr.db, msg)

	todo lreq 有多种实现
		ChtRequest
		BloomRequest
		等等
	 */
	valid := r.validate(peer, msg) == nil

	r.sentTo[peer] = sentReqToPeer{true, s.valid}
	s.valid <- valid
	if !valid {
		return errResp(ErrInvalidResponse, "reqID = %v", msg.ReqID)
	}
	return nil
}

// stop stops the retrieval process and sets an error code that will be returned
// by getError
func (r *sentReq) stop(err error) {
	r.lock.Lock()
	if !r.stopped {
		r.stopped = true
		r.err = err
		close(r.stopCh)
	}
	r.lock.Unlock()
}

// getError returns any retrieval error (either internally generated or set by the
// stop function) after stopCh has been closed
func (r *sentReq) getError() error {
	return r.err
}

// genReqID generates a new random request ID
func genReqID() uint64 {
	var rnd [8]byte
	rand.Read(rnd[:])
	return binary.BigEndian.Uint64(rnd[:])
}
