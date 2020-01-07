// Copyright 2015 The github.com/go-ethereum-analysis Authors
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

package vm

import (
	"math/big"

	"github.com/go-ethereum-analysis/params"
)

// Gas costs
const (
	GasQuickStep   uint64 = 2
	GasFastestStep uint64 = 3
	GasFastStep    uint64 = 5
	GasMidStep     uint64 = 8
	GasSlowStep    uint64 = 10
	GasExtStep     uint64 = 20

	GasReturn       uint64 = 0
	GasStop         uint64 = 0
	GasContractByte uint64 = 200
)

// calcGas returns the actual gas cost of the call.
//
// The cost of gas was changed during the homestead price change HF. To allow for EIP150
// to be implemented. The returned gas is gas - base * 63 / 64.
//
/**
todo  牛逼
calcGas： 返回调用时的实际 gas消耗费用。

在家园的 gasPrice 变动【 硬分叉期间】，Gas 成本发生了变化。
为了实现EIP150。 返回的 gas 为： 【gas - base * 63 / 64】

gasTable： gas表
availableGas： 可用的gas数量
base： 必须消耗的gas数量
callCost： 调用的gas成本数量


todo 在一次以太坊升级中，规定了每次通过 call 或 delegatecall 调用合约函数时，
	只能为被调用函数分配最多 63/64 的剩余 gas.
	而以太坊中每个区块最多只能包含约 470 万的 gas。
	也就是说，如果调用者最初投入了数量为 a 的 gas, 在 10 层递归调用后，最内层的函数最多只有 (63/64)^10*a 的 gas.



 */
func callGas(gasTable params.GasTable, availableGas, base uint64, callCost *big.Int) (uint64, error) {

	// 如果是在账户自杀期间做的事
	if gasTable.CreateBySuicide > 0 {
		availableGas = availableGas - base
		gas := availableGas - availableGas/64
		// If the bit length exceeds 64 bit we know that the newly calculated "gas" for EIP150
		// is smaller than the requested amount. Therefor we return the new gas instead
		// of returning an error.
		//
		/**
		如果callCost长度超过64位，且我们知道EIP150的新计算的“gas”小于请求时给的callCost数量。 因此，我们返回新气体而不返回错误。
		 */
		if callCost.BitLen() > 64 || gas < callCost.Uint64() {
			return gas, nil
		}
	}

	//
	if callCost.BitLen() > 64 {
		return 0, errGasUintOverflow
	}

	// 否则使用 入参的callCost
	return callCost.Uint64(), nil
}
