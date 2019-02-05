// Copyright 2014 The go-ethereum Authors
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
type TypeMux struct {
	mutex   sync.RWMutex
	subm    map[reflect.Type][]*TypeMuxSubscription
	stopped bool
}

// ErrMuxClosed is returned when Posting on a closed TypeMux.
var ErrMuxClosed = errors.New("event: mux closed")

// Subscribe creates a subscription for events of the given types. The
// subscription's channel is closed when it is unsubscribed
// or the mux is closed.

/**
订阅为给定类型的事件创建订阅。 订阅的通道在取消订阅时将被关闭
或 mux 被关闭时。
 */
func (mux *TypeMux) Subscribe(types ...interface{}) *TypeMuxSubscription {

	/** 创建一个 订阅包实例 sub */
	sub := newsub(mux)

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
func (mux *TypeMux) Post(ev interface{}) error {
	event := &TypeMuxEvent{
		Time: time.Now(),
		Data: ev,
	}
	rtyp := reflect.TypeOf(ev)
	mux.mutex.RLock()
	if mux.stopped {
		mux.mutex.RUnlock()
		return ErrMuxClosed
	}
	subs := mux.subm[rtyp]
	mux.mutex.RUnlock()
	for _, sub := range subs {
		sub.deliver(event)
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
	if s.created.After(event.Time) {
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
