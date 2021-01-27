// Copyright 2016 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package rpc

import (
	"context"
	"errors"
	"sync"
)

var (
	// ErrNotificationsUnsupported is returned when the connection doesn't support notifications
	ErrNotificationsUnsupported = errors.New("notifications not supported")
	// ErrNotificationNotFound is returned when the notification for the given id is not found
	ErrSubscriptionNotFound = errors.New("subscription not found")
)

// ID defines a pseudo random number that is used to identify RPC subscriptions.
type ID string

// a Subscription is created by a notifier and tight to that notifier. The client can use
// this subscription to wait for an unsubscribe request for the client, see Err().
type Subscription struct {
	ID        ID
	namespace string
	err       chan error // closed on unsubscribe
}

// Err returns a channel that is closed when the client send an unsubscribe request.
func (s *Subscription) Err() <-chan error {
	return s.err
}

// notifierKey is used to store a notifier within the connection context.
type notifierKey struct{}

// Notifier is tight to a RPC connection that supports subscriptions.
// Server callbacks use the notifier to send notifications.
type Notifier struct {
	codec    ServerCodec
	subMu    sync.RWMutex // guards active and inactive maps

	// 为什么下面的是数组?
	//
	// 因为 Client 和 Server 发起 WebSocket 或者 IPC 连接后,
	// 这个 连接 会一直 存在, 在这个连接中 只有一个 Notifier 实例,
	// 但是在该连接的生命周期中, 客户端是可以发起 多个 类型的 [订阅] 方法的调用的
	// 每个 [订阅] 方法的调用都会对应一个  ID (毕竟是 长连接, 那么[订阅]方法在被调用后会一直存活着, 直到连接断开或者[退订])
	//
	active   map[ID]*Subscription	// 本次 正在处理被调用中的 [订阅] 方法  todo 在 activate() 中被添加,  n.active 会在 Notifier.Notify() 和 Notifier.unsubscribe() 中被使用
	inactive map[ID]*Subscription   // 本次 准备被调用的 [订阅]  方法
}

// newNotifier creates a new notifier that can be used to send subscription
// notifications to the client.
func newNotifier(codec ServerCodec) *Notifier {
	return &Notifier{
		codec:    codec,
		active:   make(map[ID]*Subscription),
		inactive: make(map[ID]*Subscription),
	}
}

// NotifierFromContext returns the Notifier value stored in ctx, if any.
//
// NotifierFromContext 是如何从 ctx 中取得 Notifier 的，因为 ctx 的 Notifier 是在 websocket 的 handler 的一开始被新创建的
func NotifierFromContext(ctx context.Context) (*Notifier, bool) {
	n, ok := ctx.Value(notifierKey{}).(*Notifier)
	return n, ok
}

// CreateSubscription returns a new subscription that is coupled to the
// RPC connection. By default subscriptions are inactive and notifications
// are dropped until the subscription is marked as active. This is done
// by the RPC server after the subscription ID is send to the client.
func (n *Notifier) CreateSubscription() *Subscription {
	s := &Subscription{ID: NewID(), err: make(chan error)}
	n.subMu.Lock()
	n.inactive[s.ID] = s  // 每次 [订阅] 方法, 被调用前, 创建本次 [订阅] 方法调用实例时, 追加
	n.subMu.Unlock()
	return s
}

// Notify sends a notification to the client with the given data as payload.
// If an error occurs the RPC connection is closed and the error is returned.
func (n *Notifier) Notify(id ID, data interface{}) error {  // todo Notifier 对象给 各个 service api 的 [订阅] 方法中调用的...
	n.subMu.RLock()
	defer n.subMu.RUnlock()

	sub, active := n.active[id]  // 找到, 返回, 用来做 Notify 给 客户端 ...
	if active {
		notification := n.codec.CreateNotification(string(id), sub.namespace, data)
		if err := n.codec.Write(notification); err != nil {  // todo 将被订阅到的  结果数据, 推送回给 客户端 ...
			n.codec.Close()
			return err
		}
	}
	return nil
}

// Closed returns a channel that is closed when the RPC connection is closed.
func (n *Notifier) Closed() <-chan interface{} {
	return n.codec.Closed()
}

// unsubscribe a subscription.
// If the subscription could not be found ErrSubscriptionNotFound is returned.
func (n *Notifier) unsubscribe(id ID) error {
	n.subMu.Lock()
	defer n.subMu.Unlock()
	if s, found := n.active[id]; found {  // 找到, 并 删除
		close(s.err)
		delete(n.active, id)
		return nil
	}
	return ErrSubscriptionNotFound
}

// activate enables a subscription. Until a subscription is enabled all
// notifications are dropped. This method is called by the RPC server after
// the subscription ID was sent to client. This prevents notifications being
// send to the client before the subscription ID is send to the client.
func (n *Notifier) activate(id ID, namespace string) {
	n.subMu.Lock()
	defer n.subMu.Unlock()
	if sub, found := n.inactive[id]; found {
		sub.namespace = namespace
		n.active[id] = sub  //  每次 [订阅] 方法的调用, 都追加这个 .   todo 这里的 n.active 会在 Notifier.Notify() 和 Notifier.unsubscribe() 中被使用 ...
		delete(n.inactive, id)
	}
}
