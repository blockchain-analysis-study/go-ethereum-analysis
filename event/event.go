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

// Package event deals with subscriptions to real-time events.
package event

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// TypeMuxEvent is a time-tagged notification pushed to subscribers.
type TypeMuxEvent struct {
	Time time.Time
	Data interface{}
}

// A TypeMux dispatches events to registered receivers. Receivers can be
// registered to handle events of certain type. Any operation
// called after mux is stopped will return ErrMuxClosed.
//
// The zero value is ready to use.
//
// Deprecated: use Feed
//
//
// TypeMux 封装 event 调度到已注册的接收者.
// 			可以注册接收者以处理某些类型的事件. mux 停止后调用的任何操作都将返回ErrMuxClosed
//
// 零值可以使用了
//
// 不推荐使用了： 目前建议使用 Feed
//
//
type TypeMux struct {
	mutex   sync.RWMutex
	subm    map[reflect.Type][]*TypeMuxSubscription    // event类型 => 所有订阅了该 event 的实例 (这个里面又对了 TypeMux 做了封装)
	stopped bool
}

// ErrMuxClosed is returned when Posting on a closed TypeMux.
var ErrMuxClosed = errors.New("event: mux closed")

// Subscribe creates a subscription for events of the given types. The
// subscription's channel is closed when it is unsubscribed
// or the mux is closed.
//
// Subscribe() 	为给 定类型的事件 创建 订阅实例
// 				订阅实例 的通道在 取消订阅时 将被关闭 或 mux 被关闭时
//
func (mux *TypeMux) Subscribe(types ...interface{}) *TypeMuxSubscription {

	sub := newsub(mux)  // todo 创建一个 订阅实例 sub

	mux.mutex.Lock()
	defer mux.mutex.Unlock()

	// 如果之前的 当前 mux 的 stopped 标识位 为true
	// 则,
	if mux.stopped {
		// set the status to closed so that calling Unsubscribe after this
		// call will short circuit.
		// 将状态设置为关闭，以便在此调用后调用Unsubscribe将 直接退出。
		sub.closed = true
		close(sub.postC)
	} else {
		// 创建 装 sub 的 map
		if mux.subm == nil {
			mux.subm = make(map[reflect.Type][]*TypeMuxSubscription)
		}
		for _, t := range types {
			rtyp := reflect.TypeOf(t)

			// 返回该类型的 订阅事件 arr
			oldsubs := mux.subm[rtyp]

			/** 是否 重复 订阅的校验 **/
			if find(oldsubs, sub) != -1 {
				panic(fmt.Sprintf("event: duplicate type %s in Subscribe", rtyp))
			}

			// 创建一个新的 sub 的 arr 且len 比原来的 加一
			subs := make([]*TypeMuxSubscription, len(oldsubs)+1)

			// copy 到 新的 sub arr 中
			copy(subs, oldsubs)
			// 将新的 sub 追加进去 arr 中
			subs[len(oldsubs)] = sub
			// 将新的arr 置换到 map中
			mux.subm[rtyp] = subs
		}
	}
	// 返回本次创建的 sub
	return sub
}

// Post sends an event to all receivers registered for the given type.
// It returns ErrMuxClosed if the mux has been stopped.
//
//
// Post()  	向所有为给定类型注册的接收者发送事件
//			如果多路复用器已停止，则返回ErrMuxClosed
//
func (mux *TypeMux) Post(ev interface{}) error {
	event := &TypeMuxEvent{
		Time: time.Now(),
		Data: ev,  // 某种类型的event 引用
	}
	rtyp := reflect.TypeOf(ev)  // 获取 event 的类型
	mux.mutex.RLock()
	if mux.stopped {  // 当前 订阅者 已经关闭
		mux.mutex.RUnlock()
		return ErrMuxClosed
	}
	subs := mux.subm[rtyp]
	mux.mutex.RUnlock()
	for _, sub := range subs {
		sub.deliver(event)   // 传递 event
	}
	return nil
}

// Stop closes a mux. The mux can no longer be used.
// Future Post calls will fail with ErrMuxClosed.
// Stop blocks until all current deliveries have finished.
func (mux *TypeMux) Stop() {
	mux.mutex.Lock()
	for _, subs := range mux.subm {
		for _, sub := range subs {
			sub.closewait()
		}
	}
	mux.subm = nil
	mux.stopped = true
	mux.mutex.Unlock()
}

func (mux *TypeMux) del(s *TypeMuxSubscription) {
	mux.mutex.Lock()
	for typ, subs := range mux.subm {
		if pos := find(subs, s); pos >= 0 {
			if len(subs) == 1 {
				delete(mux.subm, typ)
			} else {
				mux.subm[typ] = posdelete(subs, pos)
			}
		}
	}
	s.mux.mutex.Unlock()
}

func find(slice []*TypeMuxSubscription, item *TypeMuxSubscription) int {
	for i, v := range slice {
		// 指针 比较 ？？
		if v == item {
			return i
		}
	}
	return -1
}

func posdelete(slice []*TypeMuxSubscription, pos int) []*TypeMuxSubscription {
	news := make([]*TypeMuxSubscription, len(slice)-1)
	copy(news[:pos], slice[:pos])
	copy(news[pos:], slice[pos+1:])
	return news
}

// TypeMuxSubscription is a subscription established through TypeMux.
//
// TypeMuxSubscription是通过 TypeMux 建立的 订阅实例
type TypeMuxSubscription struct {
	mux     *TypeMux
	created time.Time
	closeMu sync.Mutex
	closing chan struct{}
	closed  bool

	// these two are the same channel. they are stored separately so
	// postC can be set to nil without affecting the return value of
	// Chan.
	postMu sync.RWMutex

	/** 注意 readC 是读 postC 是写 */
	readC  <-chan *TypeMuxEvent
	postC  chan<- *TypeMuxEvent
}

func newsub(mux *TypeMux) *TypeMuxSubscription {
	// 创建一个 事件 通道
	c := make(chan *TypeMuxEvent)
	return &TypeMuxSubscription{
		mux:     mux,
		created: time.Now(),
		/** 将时间通道的引用分别赋值到 readC 和 postC */
		readC:   c,
		postC:   c,
		// 创建一个 用于接收 关闭信号的通道
		closing: make(chan struct{}),
	}
}

func (s *TypeMuxSubscription) Chan() <-chan *TypeMuxEvent {
	// 读取 readC
	return s.readC
}

/**
取消订阅
 */
func (s *TypeMuxSubscription) Unsubscribe() {
	// 删除掉 当前 sub 实例
	s.mux.del(s)
	s.closewait()
}

func (s *TypeMuxSubscription) Closed() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

func (s *TypeMuxSubscription) closewait() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return
	}
	close(s.closing)
	s.closed = true

	s.postMu.Lock()
	close(s.postC)
	s.postC = nil
	s.postMu.Unlock()
}

func (s *TypeMuxSubscription) deliver(event *TypeMuxEvent) {
	// Short circuit delivery if stale event
	if s.created.After(event.Time) {  // 如果 订阅实例的 创建时间比 event 发出的时间晚, 那么该 订阅实例 将不接收到这 event
		return
	}
	// Otherwise deliver the event
	s.postMu.RLock()
	defer s.postMu.RUnlock()

	select {
	case s.postC <- event:
	case <-s.closing:
	}
}
