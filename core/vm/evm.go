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

package vm

import (
	"math/big"
	"sync/atomic"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/crypto"
	"github.com/go-ethereum-analysis/params"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the nth block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) common.Hash
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *EVM, contract *Contract, input []byte) ([]byte, error) {
	if contract.CodeAddr != nil {
		precompiles := PrecompiledContractsHomestead
		if evm.ChainConfig().IsByzantium(evm.BlockNumber) {
			precompiles = PrecompiledContractsByzantium
		}
		if p := precompiles[*contract.CodeAddr]; p != nil {
			return RunPrecompiledContract(p, input, contract)
		}
	}
	for _, interpreter := range evm.interpreters {
		if interpreter.CanRun(contract.Code) {
			if evm.interpreter != interpreter {
				// Ensure that the interpreter pointer is set back
				// to its current value upon return.
				defer func(i Interpreter) {
					evm.interpreter = i
				}(evm.interpreter)
				evm.interpreter = interpreter
			}
			return interpreter.Run(contract, input)
		}
	}
	return nil, ErrNoCompatibleInterpreter
}

// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	//
	//  检查 账户的balance是否足够的回调Fn
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	//
	// 执行转账的回调Fn
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	// 根据相应的n <BlockNumber> 返回对应的Hash
	GetHash GetHashFunc

	// Message information
	//
	// 这些事 Msg 的 信息
	//

	// 提供 ORIGIN `起源` 信息
	Origin   common.Address // Provides information for ORIGIN
	// 提供 GASPRICE `gasPrice` 信息
	GasPrice *big.Int       // Provides information for GASPRICE

	// Block information
	// 下面这些是指 Block信息

	// 矿工信息
	Coinbase    common.Address // Provides information for COINBASE

	// 当前 Block 的GasLimit
	GasLimit    uint64         // Provides information for GASLIMIT

	// 当前 Block 的 Number
	BlockNumber *big.Int       // Provides information for NUMBER

	// 当前 Block 的 timestamp
	Time        *big.Int       // Provides information for TIME

	// 当前 Block 的 难度
	Difficulty  *big.Int       // Provides information for DIFFICULTY
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	/** 当前调用栈深度 */
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	vmConfig Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.
	interpreters []Interpreter
	interpreter  Interpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	callGasTemp uint64
}

// NewEVM returns a new EVM. The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(ctx Context, statedb StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	evm := &EVM{
		// EVM的上下文
		Context:      ctx,
		// 依赖的stateDB
		StateDB:      statedb,
		// evm配置
		vmConfig:     vmConfig,
		// chain配置
		chainConfig:  chainConfig,
		chainRules:   chainConfig.Rules(ctx.BlockNumber),
		// 收集 执行器数组
		interpreters: make([]Interpreter, 1),
	}
	// 实例化一个根据配置生成的执行器
	evm.interpreters[0] = NewEVMInterpreter(evm, vmConfig)
	// 默认的执行器
	evm.interpreter = evm.interpreters[0]

	return evm
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Interpreter returns the current interpreter
func (evm *EVM) Interpreter() Interpreter {
	return evm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {

	// todo 还是一上来就先判断是否禁用的解释器的 Call ，Callcode， DelegateCall和 Create
	// 		且 stack调用深度是否 > 0
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}

	// Fail if we're trying to execute above the call depth limit
	//
	// todo 深度检查， 如果我们试图执行超过上限时，则失败。
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	//
	// todo 判断余额是否足够
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	var (
		// 拿到 合约的地址
		to       = AccountRef(addr)
		// 获取一个state 的快照， 为了回滚用
		snapshot = evm.StateDB.Snapshot()
	)

	// todo 如果合约账户 不存在 state中， 那么应该是系统合约调用了
	//   以前 以太坊的 系统合约是不会在 state中存在账户信息的
	if !evm.StateDB.Exist(addr) {

		// 先拿正常的系统合约
		precompiles := PrecompiledContractsHomestead
		if evm.ChainConfig().IsByzantium(evm.BlockNumber) {

			// 如果是拜占庭分叉，则拿拜占庭内置合约
			precompiles = PrecompiledContractsByzantium
		}

		// todo 如果不存在内置合约，且 value 等于0
		if precompiles[addr] == nil && evm.ChainConfig().IsEIP158(evm.BlockNumber) && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer

			// 是否是 debug 模式
			if evm.vmConfig.Debug && evm.depth == 0 {
				evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)
				evm.vmConfig.Tracer.CaptureEnd(ret, 0, 0, nil)
			}
			return nil, gas, nil
		}

		// todo 否则，一概创建 state 账户
		evm.StateDB.CreateAccount(addr)
	}

	// todo 还是老做法，什么都不管，先来一波转账
	evm.Transfer(evm.StateDB, caller.Address(), to.Address(), value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	//
	// 初始化一个合约执行的上下文环境 `contract`
	contract := NewContract(caller, to, value, gas)
	// todo 先取出 合约的 code
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// 开始记录执行时间
	start := time.Now()

	// Capture the tracer start/end events in debug mode
	//
	// 判断是否是 debug 模式
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)

		defer func() { // Lazy evaluation of the parameters
			evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
		}()
	}

	/**
	todo 真正去执行合约
	 */
	ret, err = run(evm, contract, input)

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	//
	// todo 处理 err
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	// 将结果返回
	return ret, contract.Gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {

	// todo 还是一上来就先判断是否禁用的解释器的 Call ，Callcode， DelegateCall和 Create
	// 		且 stack调用深度是否 > 0
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}

	// Fail if we're trying to execute above the call depth limit
	//
	// todo 深度检查， 如果我们试图执行超过上限时，则失败。
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	//
	// todo 判断余额是否足够
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)
	// initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {

	// todo 还是一上来就先判断是否禁用的解释器的 Call ，Callcode， DelegateCall和 Create
	// 		且 stack调用深度是否 > 0
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	//
	// todo 深度检查， 如果我们试图执行超过上限时，则失败。
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)

	// Initialise a new contract and make initialise the delegate values
	contract := NewContract(caller, to, nil, gas).AsDelegate()
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {

	// todo 还是一上来就先判断是否禁用的解释器的 Call ，Callcode， DelegateCall和 Create
	// 		且 stack调用深度是否 > 0
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	//
	// todo 深度检查， 如果我们试图执行超过上限时，则失败。
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Make sure the readonly is only set if we aren't in readonly yet
	// this makes also sure that the readonly flag isn't removed for
	// child calls.
	if !evm.interpreter.IsReadOnly() {
		evm.interpreter.SetReadOnly(true)
		defer func() { evm.interpreter.SetReadOnly(false) }()
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	// Initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, to, new(big.Int), gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in Homestead this also counts for code storage gas errors.
	ret, err = run(evm, contract, input)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// create creates a new contract using code as deployment code.
//
// 部署一个 Contract
func (evm *EVM) create(caller ContractRef, code []byte, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.

	// todo 深度检查， 如果我们试图执行超过上限时，则失败。
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}

	// 校验caller的余额是否足够
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}

	// 获取 当点 caller的nonce
	nonce := evm.StateDB.GetNonce(caller.Address())

	// 更新下一次发交易的 nonce
	//
	// todo 注意。 evm.call() 是在它的外面，也就是调用它之前执行做的这一步
	//
	// todo 先校验 stack 的调用深度 和 账户的剩余balance
	//   然后才更新nonce
	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	// Ensure there's no existing contract already at the designated address
	//
	// 确保指定 Addr 上没有现有合同
	contractHash := evm.StateDB.GetCodeHash(address)

	// 校验指定Addr 是否合法：
	// 如果Addr 的nonce 不为0
	// 如果Addr 存在contractCode
	//
	// 则，都表示该Addr 已经被使用了， 这是后想要创建合约，需要再次部署一次，
	// 因为 caller 的nonce已经改变，所以 caller Addr+ nonce 生成的 contractAddr 肯定是一个新的
	//
	// todo 注意： 此处的 Addr 是 外面生成的 contract Addr
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	//
	// 给 contractAddr 创建一个新的账户到 StateDB
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
		evm.StateDB.SetNonce(address, 1)
	}

	// 如果在创建的同时还在 value 转了钱的话，则需要将 value 中的钱转入生成的 contract Addr
	evm.Transfer(evm.StateDB, caller.Address(), address, value)

	// initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	//
	// 初始化新 contract 并设置将由EVM使用的代码。 contract 仅是此执行上下文的作用域环境。
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCallCode(&address, crypto.Keccak256Hash(code), code)


	// todo 如果禁用的解释器的 Call ，Callcode， DelegateCall和 Create
	// 		且 当前stack 的深度 > 0
	// 		则，直接结束
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, address, gas, nil
	}


	// todo 如果是 Debug 模式，且 stack调用深度 == 0
	//   则，开启 虚机字节码的logger
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), address, true, code, gas, value)
	}

	// 记录启动时间戳
	start := time.Now()


	/**
	TODO 开始执行 部署，
			部署成功后，返回 ret 和 err
			ret 既是部署之后的 指令码集
	 */
	ret, err := run(evm, contract, nil)

	// check whether the max code size has been exceeded
	//
	// 检查是否超过了最大代码大小
	//
	// todo 即， 指令码集是否超过限制
	maxCodeSizeExceeded := evm.ChainConfig().IsEIP158(evm.BlockNumber) && len(ret) > params.MaxCodeSize
	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	//
	/**
	todo 如果 contarct 创建成功执行并且没有返回错误，则计算存储代码所需的费用。
		 如果由于气体不足而无法存储该代码，请设置一个错误，并通过下面的错误检查条件进行处理。
	 */
	if err == nil && !maxCodeSizeExceeded {

		// todo 使用 指令码的占用的长度 * 单价的gas
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {

			// todo 如果有足够的余额足够支付 这些gas，则记录下来
			//  	并将 code 存储起来
			evm.StateDB.SetCode(address, ret)
		} else {
			// todo 否则返回一个错误
			err = ErrCodeStoreOutOfGas
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if maxCodeSizeExceeded || (err != nil && (evm.ChainConfig().IsHomestead(evm.BlockNumber) || err != ErrCodeStoreOutOfGas)) {
		// todo 有问题，则回滚state
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}

	// todo 如果是 debug 形式，则还需要记录 err
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	}

	// 结束，并将结果返回
	return ret, address, contract.Gas, err

}

// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {

	// todo 直接使用当前 Caller 的Addr 和 nonce，生成 contract Addr
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))

	//
	return evm.create(caller, code, gas, value, contractAddr)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses sha3(0xff ++ msg.sender ++ salt ++ sha3(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress2(caller.Address(), common.BigToHash(salt), code)
	return evm.create(caller, code, gas, endowment, contractAddr)
}

// ChainConfig returns the environment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }
