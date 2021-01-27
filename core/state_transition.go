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

package core

import (
	"errors"
	"math"
	"math/big"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/vm"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/params"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
)

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp         *GasPool
	msg        Message
	gas        uint64  // 当前剩余可用的  gas
	gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	CheckNonce() bool
	Data() []byte
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
/** 计算tx的data字段中的字节数所消耗的固定gas */
func IntrinsicGas(data []byte, contractCreation, homestead bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	// 先算无条件的固定消耗
	// 是否是部署合约 || 家园版本
	if contractCreation && homestead {
		// 固定消耗 53000 gas
		gas = params.TxGasContractCreation
	} else {
		// 普通tx 固定消耗 21000 gas
		gas = params.TxGas
	}
	// Bump the required gas by the amount of transactional data
	// 这时候才是来算data的消耗gas
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		// 字节计数量
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		/** 确保所有数据组合都不超过uint64 */
		// ((2^64 - 1) - (固有的gas消耗))/68
		if (math.MaxUint64-gas)/params.TxDataNonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		gas += nz * params.TxDataNonZeroGas   // 非0 的byte个数 * 68

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		gas += z * params.TxDataZeroGas  // 0 的byte个数 * 4
	}
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	// 实例化一个 stateTx 实例
	return &StateTransition{
		// 当前块的 gasLimit限制
		gp:       gp,
		evm:      evm,
		msg:      msg,
		// 当前tx的gasPrice
		gasPrice: msg.GasPrice(),
		// 当前tx的value
		value:    msg.Value(),
		// 当前tx的data字段
		data:     msg.Data(),
		// 依赖的state
		state:    evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(evm *vm.EVM, msg Message, gp *GasPool) ([]byte, uint64, bool, error) {
	/** 实例化一个stateTx实例并执行tx */
	return NewStateTransition(evm, msg, gp).TransitionDb()
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) useGas(amount uint64) error {
	if st.gas < amount {
		return vm.ErrOutOfGas
	}
	st.gas -= amount

	return nil
}

// 对gas做各种预处理
func (st *StateTransition) buyGas() error {
	// 先计算当前tx所消耗的 ether (gas数目 * gasPrice)
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)
	// 校验账户中的余额是否足够
	if st.state.GetBalance(st.msg.From()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	//  当前 block 的剩余gasLimit - 当前tx的gas
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	// 初始化当前 tx 剩余可用的gas (后学合约或者tx 需要使用)
	st.gas += st.msg.Gas()
	// 先记录着当前tx中愿意花费的gas  (st.initialGas - st.gas == st.UseGas <本次交易 所消耗的 gas>)
	st.initialGas = st.msg.Gas()
	// 账户上先减掉这部分 tx的gas消耗  (不怕, 后面有剩的 会被加回来的)
	st.state.SubBalance(st.msg.From(), mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	// Make sure this transaction's nonce is correct.
	if st.msg.CheckNonce() {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	// 初始化各种gas的预处理
	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the used gas. It returns an error if failed.
// An error indicates a consensus issue.
/** EVM 真正执行tx */
func (st *StateTransition) TransitionDb() (ret []byte, usedGas uint64, failed bool, err error) {

	// 执行前的检查
	// 主要是nonce的检查 及 初始化Gas
	if err = st.preCheck(); err != nil {
		return
	}
	// 当前msg
	msg := st.msg
	// 当前tx的 发起者
	sender := vm.AccountRef(msg.From())
	// 是否 家园版标识位
	homestead := st.evm.ChainConfig().IsHomestead(st.evm.BlockNumber)
	// 是否是部署合约的tx标识位
	contractCreation := msg.To() == nil

	// 先计算当前data字段中的字节数锁消耗的固定gas  (非0的byte个数 X 68 + 0的byte个数 X 4)
	gas, err := IntrinsicGas(st.data, contractCreation, homestead)
	if err != nil {
		return nil, 0, false, err
	}
	if err = st.useGas(gas); err != nil {
		return nil, 0, false, err
	}

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)
	if contractCreation {
		ret, _, st.gas, vmerr = evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		// 先更新该账户下一次发交易应该发的 nonce
		//
		// todo 注意： evm.Create() 实在 func 里面做掉了
		st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)

		// todo 然后才是做 contract 调用
		ret, st.gas, vmerr = evm.Call(sender, st.to(), st.data, st.gas, st.value)
	}
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		// A possible consensus error is if there is not enough balance to complete the transfer. The first balance transfer may never fail.
		// There are also times when VMs are aborted.
		/**
		todo 唯一可能的 consensus-error是，
			如果没有足够的余额来完成转移。 第一次余额转移可能永远不会失败。
		 */
		if vmerr == vm.ErrInsufficientBalance {
			return nil, 0, false, vmerr
		}
	}
	// todo  可以看出只有当 余额不足err 时，才不会消耗gas，其他的都消耗


	// 退还多余的 gas
	st.refundGas()
	st.state.AddBalance(st.evm.Coinbase, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.gasPrice))

	return ret, st.gasUsed(), vmerr != nil, err
}

func (st *StateTransition) refundGas() {

	// todo 清理状态 和 清理存储槽 和 删除带有自会操作码的合约 都会收到 gas 退款
	//
	// 只有 tx 结束时 提供调用.
	//
	// 最高退款是 当前tx 已经消耗的 gas 的 一半.

	// Apply refund counter, capped to half of the used gas.
	//
	// 申请退款柜台，上限为已用 gas 的一半。
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	// Return ETH for remaining gas, exchanged at the original rate.
	//
	// 返回ETH剩余的gas，以原始汇率 兑换。
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(st.msg.From(), remaining)

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	//
	// 还要将剩余的gas返回到 block gas 计数器，以便下次交易使用。
	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
//
// todo gasUsed: 返回状态转换用完的 gas 数量。
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
