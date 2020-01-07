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

package state

import (
	"math/big"

	"github.com/go-ethereum-analysis/common"
)

// journalEntry is a modification entry in the state change journal that can be
// reverted on demand.
//
// journalEntry是 `State更改日记帐` 中的修改条目，可以按需还原。
type journalEntry interface {
	// revert undoes the changes introduced by this journal entry.
	//
	// revert: 撤消此日记帐分录引入的更改。
	revert(*StateDB)

	// dirtied returns the Ethereum address modified by this journal entry.
	//
	// dirtied: 返回由该日志条目修改的以太坊地址。
	dirtied() *common.Address
}

// journal contains the list of state modifications applied since the last state
// commit. These are tracked to be able to be reverted in case of an execution
// exception or revertal request.
//
/**
journal包含自上次提交State以来应用的State修改列表。 在执行异常或恢复请求的情况下，将跟踪这些 `日志账条目` 以使其能够恢复。
 */
type journal struct {
	// 日记跟踪的当前更改
	entries []journalEntry         // Current changes tracked by the journal

	// 最近变更的账户 和 更改次数
	// map[账户]变更次数
	dirties map[common.Address]int // Dirty accounts and the number of changes
}

// newJournal create a new initialized journal.
func newJournal() *journal {
	return &journal{
		dirties: make(map[common.Address]int),
	}
}

// append inserts a new modification entry to the end of the change journal.
//
//
func (j *journal) append(entry journalEntry) {
	// todo 往 `State的修改杂志` 中添加 日志账条目
	j.entries = append(j.entries, entry)

	// todo 如果对应的   日志账条目 有 addr 存在的话，则记录下最近日志帐条目中对应的账户 Addr和变更次数
	if addr := entry.dirtied(); addr != nil {
		j.dirties[*addr]++
	}
}

// revert undoes a batch of journalled modifications along with any reverted
// dirty handling too.
func (j *journal) revert(statedb *StateDB, snapshot int) {

	// todo 遍历出最近存入的 所有  日志账条目实例
	for i := len(j.entries) - 1; i >= snapshot; i-- {
		// Undo the changes made by the operation
		j.entries[i].revert(statedb)

		// Drop any dirty tracking induced by the change
		if addr := j.entries[i].dirtied(); addr != nil {
			if j.dirties[*addr]--; j.dirties[*addr] == 0 {
				delete(j.dirties, *addr)
			}
		}
	}
	j.entries = j.entries[:snapshot]
}

// dirty explicitly sets an address to dirty, even if the change entries would
// otherwise suggest it as clean. This method is an ugly hack to handle the RIPEMD
// precompile consensus exception.
func (j *journal) dirty(addr common.Address) {
	j.dirties[addr]++
}

// length returns the current number of entries in the journal.
func (j *journal) length() int {
	return len(j.entries)
}

// todo ###############################
// todo ###############################
// todo ###############################
// todo ###############################
//
// todo 下面这些都是 `journalEntry` 的实现
// todo journalEntry 是 `State更改日记帐` 中的修改条目，可以按需还原。
type (
	// Changes to the account trie.
	//
	// 更改帐户尝试。

	// todo 创建账户的 日志帐条目
	createObjectChange struct {
		account *common.Address
	}

	// todo 重置账户的 日志帐条目
	resetObjectChange struct {
		prev *stateObject
	}

	// todo 账户自杀的 日志账条目
	suicideChange struct {
		account     *common.Address
		prev        bool // whether account had already suicided
		prevbalance *big.Int
	}

	// Changes to individual accounts.
	//
	// 更改个人帐户。

	// todo 余额变更的 日志帐条目
	balanceChange struct {
		account *common.Address
		prev    *big.Int
	}

	// todo nonce变更的 日志帐条目
	nonceChange struct {
		account *common.Address
		prev    uint64
	}

	// todo 账户的存储数据变更的 日志账条目
	storageChange struct {
		account       *common.Address
		key, prevalue common.Hash
	}

	// todo 账户的code变更的 日志账条目
	codeChange struct {
		account            *common.Address
		prevcode, prevhash []byte
	}

	// Changes to other state values.
	//
	// 更改为其他状态值。

	// todo 需要退款的 日志账条目
	refundChange struct {
		prev uint64
	}

	// todo 增加了 log的 日志账条目
	addLogChange struct {
		txhash common.Hash
	}

	// todo preimage数据变更的 日志账条目
	addPreimageChange struct {
		hash common.Hash
	}

	// todo 这个还没启用 ...
	touchChange struct {
		account   *common.Address
		prev      bool
		prevDirty bool
	}
)

func (ch createObjectChange) revert(s *StateDB) {
	delete(s.stateObjects, *ch.account)
	delete(s.stateObjectsDirty, *ch.account)
}

func (ch createObjectChange) dirtied() *common.Address {
	return ch.account
}

func (ch resetObjectChange) revert(s *StateDB) {
	s.setStateObject(ch.prev)
}

func (ch resetObjectChange) dirtied() *common.Address {
	return nil
}

func (ch suicideChange) revert(s *StateDB) {
	obj := s.getStateObject(*ch.account)
	if obj != nil {
		obj.suicided = ch.prev
		obj.setBalance(ch.prevbalance)
	}
}

func (ch suicideChange) dirtied() *common.Address {
	return ch.account
}

var ripemd = common.HexToAddress("0000000000000000000000000000000000000003")

func (ch touchChange) revert(s *StateDB) {
}

func (ch touchChange) dirtied() *common.Address {
	return ch.account
}

func (ch balanceChange) revert(s *StateDB) {
	s.getStateObject(*ch.account).setBalance(ch.prev)
}

func (ch balanceChange) dirtied() *common.Address {
	return ch.account
}

func (ch nonceChange) revert(s *StateDB) {
	s.getStateObject(*ch.account).setNonce(ch.prev)
}

func (ch nonceChange) dirtied() *common.Address {
	return ch.account
}

func (ch codeChange) revert(s *StateDB) {
	s.getStateObject(*ch.account).setCode(common.BytesToHash(ch.prevhash), ch.prevcode)
}

func (ch codeChange) dirtied() *common.Address {
	return ch.account
}

func (ch storageChange) revert(s *StateDB) {
	s.getStateObject(*ch.account).setState(ch.key, ch.prevalue)
}

func (ch storageChange) dirtied() *common.Address {
	return ch.account
}

func (ch refundChange) revert(s *StateDB) {
	s.refund = ch.prev
}

func (ch refundChange) dirtied() *common.Address {
	return nil
}

func (ch addLogChange) revert(s *StateDB) {
	logs := s.logs[ch.txhash]
	if len(logs) == 1 {
		delete(s.logs, ch.txhash)
	} else {
		s.logs[ch.txhash] = logs[:len(logs)-1]
	}
	s.logSize--
}

func (ch addLogChange) dirtied() *common.Address {
	return nil
}

func (ch addPreimageChange) revert(s *StateDB) {
	delete(s.preimages, ch.hash)
}

func (ch addPreimageChange) dirtied() *common.Address {
	return nil
}
