// Copyright 2014 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package vm

import "errors"

// List execution errors
//
// 合约执行的err
var (
	// gas 不足
	ErrOutOfGas                 = errors.New("out of gas")
	// 部署合约时 code 消耗的gas 太多
	ErrCodeStoreOutOfGas        = errors.New("contract creation code storage out of gas")
	// 超过最大通话深度
	ErrDepth                    = errors.New("max call depth exceeded")
	// 日志数达到指定限制
	ErrTraceLimitReached        = errors.New("the number of logs reached the specified limit")
	// 余额不足，无法转移
	ErrInsufficientBalance      = errors.New("insufficient balance for transfer")
	// 合约地址冲突
	ErrContractAddressCollision = errors.New("contract address collision")
	// 没有兼容的 执行器
	ErrNoCompatibleInterpreter  = errors.New("no compatible interpreter")
)
