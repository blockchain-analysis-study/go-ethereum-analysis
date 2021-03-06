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

/**
绝大部分操作码所需的gas都在这里计算
 */
package params

// GasTable organizes gas prices for different ethereum phases.
//
//  todo GasTable组织了不同以太坊阶段的天然气价格。
type GasTable struct {
	ExtcodeSize uint64
	ExtcodeCopy uint64
	ExtcodeHash uint64
	Balance     uint64
	// 表示 加载 State数据时的gas固定消耗
	SLoad       uint64

	// todo 这个表示 四种跨合约调用时的必须gas消耗
	// 	直接随着 gasTable 走
	Calls       uint64

	// todo 表示 自杀的固定gas消耗
	Suicide     uint64

	ExpByte uint64

	// CreateBySuicide occurs when the
	// refunded account is one that does
	// not exist. This logic is similar
	// to call. May be left nil. Nil means
	// not charged.
	//
	/**
	todo 如果退款的帐户不存在，则会发生CreateBySuicide。 此逻辑类似于Call。 可能为零。 0: 表示未收费。
	 */
	CreateBySuicide uint64
}

// Variables containing gas prices for different ethereum phases.
var (
	// GasTableHomestead contain the gas prices for
	// the homestead phase.
	GasTableHomestead = GasTable{
		ExtcodeSize: 20,
		ExtcodeCopy: 20,
		Balance:     20,
		SLoad:       50,
		Calls:       40,
		Suicide:     0,
		ExpByte:     10,
	}

	// GasTableEIP150 contain the gas re-prices for
	// the EIP150 phase.
	GasTableEIP150 = GasTable{
		ExtcodeSize: 700,
		ExtcodeCopy: 700,
		Balance:     400,
		SLoad:       200,
		Calls:       700,
		Suicide:     5000,
		ExpByte:     10,

		CreateBySuicide: 25000,
	}
	// GasTableEIP158 contain the gas re-prices for
	// the EIP155/EIP158 phase.
	GasTableEIP158 = GasTable{
		ExtcodeSize: 700,
		ExtcodeCopy: 700,
		Balance:     400,
		SLoad:       200,
		Calls:       700,
		Suicide:     5000,
		ExpByte:     50,

		CreateBySuicide: 25000,
	}
	// GasTableConstantinople contain the gas re-prices for
	// the constantinople phase.
	GasTableConstantinople = GasTable{
		ExtcodeSize: 700,
		ExtcodeCopy: 700,
		ExtcodeHash: 400,
		Balance:     400,
		SLoad:       200,
		Calls:       700,
		Suicide:     5000,
		ExpByte:     50,

		CreateBySuicide: 25000,
	}
)
