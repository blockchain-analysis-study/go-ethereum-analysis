// Copyright 2017 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package ethapi

import (
	"sync"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
)

// todo 一个不错的设计
//
//		钱包账户 锁
type AddrLocker struct {
	mu    sync.Mutex
	locks map[common.Address]*sync.Mutex
}

// lock returns the lock of the given address.
// 返回一把当前账户对应的锁
func (l *AddrLocker) lock(address common.Address) *sync.Mutex {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.locks == nil {
		l.locks = make(map[common.Address]*sync.Mutex)
	}
	if _, ok := l.locks[address]; !ok {
		l.locks[address] = new(sync.Mutex)
	}
	return l.locks[address]
}

// LockAddr locks an account's mutex. This is used to prevent another tx getting the
// same nonce until the lock is released. The mutex prevents the (an identical nonce) from
// being read again during the time that the first transaction is being signed.
/**
LockAddr函数：
用操作某些帐户的互斥锁。
这用于防止另一个tx获得相同的nonce。
互斥锁防止在第一个事务签名期间再次读取（相同的随机数）。
 */
func (l *AddrLocker) LockAddr(address common.Address) {
	l.lock(address).Lock()
}

// UnlockAddr unlocks the mutex of the given account.
/**
UnlockAddr函数：
解锁给定帐户的互斥锁。
 */
func (l *AddrLocker) UnlockAddr(address common.Address) {
	l.lock(address).Unlock()
}
