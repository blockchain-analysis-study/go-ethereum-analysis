// Copyright 2016 The go-ethereum Authors
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

package core

import (
	"math/big"

	"go-ethereum/common"
	"go-ethereum/consensus"
	"go-ethereum/core/types"
	"go-ethereum/core/vm"
)

// ChainContext supports retrieving headers and consensus parameters from the
// current blockchain to be used during transaction processing.
type ChainContext interface {
	// Engine retrieves the chain's consensus engine.
	Engine() consensus.Engine

	// GetHeader returns the hash corresponding to their hash.
	GetHeader(common.Hash, uint64) *types.Header
}

// NewEVMContext creates a new context for use in the EVM.
func NewEVMContext(msg Message, header *types.Header, chain ChainContext, author *common.Address) vm.Context {
	// If we don't have an explicit author (i.e. not mining), extract from the header
	// 如果我们没有明确的作者（即不挖矿），请从header中提取
	// 求出矿工账户
	var beneficiary common.Address
	if author == nil {
		// 从共识中拿 coinbase，初始化共识的时候注入了
		beneficiary, _ = chain.Engine().Author(header) // 忽略错误，我们已通过header验证
	} else {
		beneficiary = *author
	}
	return vm.Context{
		// 注入回调函数，判断是否可以执行tx转账
		CanTransfer: CanTransfer,
		// 注入回调函数，执行tx的转账
		Transfer:    Transfer,
		// 注入回调函数，返回一个可以根据 num求Hash的函数
		GetHash:     GetHashFn(header, chain),
		// tx的发起者
		Origin:      msg.From(),
		// 矿工账户
		Coinbase:    beneficiary,
		// 块高
		BlockNumber: new(big.Int).Set(header.Number),
		// 出块时间
		Time:        new(big.Int).Set(header.Time),
		// 块的挖矿难度
		Difficulty:  new(big.Int).Set(header.Difficulty),
		// 当前块的总gas允许上限
		GasLimit:    header.GasLimit,
		// 当前tx的gasPrice
		GasPrice:    new(big.Int).Set(msg.GasPrice()),
	}
}

// GetHashFn returns a GetHashFunc which retrieves header hashes by number
func GetHashFn(ref *types.Header, chain ChainContext) func(n uint64) common.Hash {
	var cache map[uint64]common.Hash

	return func(n uint64) common.Hash {
		// If there's no hash cache yet, make one
		if cache == nil {
			cache = map[uint64]common.Hash{
				ref.Number.Uint64() - 1: ref.ParentHash,
			}
		}
		// Try to fulfill the request from the cache
		if hash, ok := cache[n]; ok {
			return hash
		}
		// Not cached, iterate the blocks and cache the hashes
		for header := chain.GetHeader(ref.ParentHash, ref.Number.Uint64()-1); header != nil; header = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1) {
			cache[header.Number.Uint64()-1] = header.ParentHash
			if n == header.Number.Uint64()-1 {
				return header.ParentHash
			}
		}
		return common.Hash{}
	}
}

// CanTransfer checks whether there are enough funds in the address' account to make a transfer.
// This does not take the necessary gas in to account to make the transfer valid.
func CanTransfer(db vm.StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// Transfer subtracts amount from sender and adds amount to recipient using the given Db
func Transfer(db vm.StateDB, sender, recipient common.Address, amount *big.Int) {
	db.SubBalance(sender, amount)
	db.AddBalance(recipient, amount)
}
