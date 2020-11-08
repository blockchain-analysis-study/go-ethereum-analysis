// Copyright 2017 The github.com/go-ethereum-analysis Authors
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

// Package accounts implements high level Ethereum account management.
package accounts

import (
	"math/big"

	ethereum "github.com/go-ethereum-analysis"
	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/event"
)

// 在accounts中总共支持【两大类 共4种】钱包类型.  两大类包括 `keystore` 和 `usbwallet` <usb接入的硬件钱包>
//
// 其中 keystore 中的  私钥存储可以分为  [加密 keystore_passphrase] 的和 [不加密 keystore_plain] 的;  usbwallet 支持 [ledger] 和 [trenzor] 两种硬件钱包.
//
//
// todo keystore 钱包
//
//		keystore类型的钱包其实是一个本地文件夹目录.
// 				在这个目录下可以存放多个文件，每个文件都存储着一个私钥信息.
// 				这些文件都是json格式，其中的私钥可以是加密的，也可以是非加密的明文.
// 				但非加密的格式已经被废弃了.
//
//		keystore的目录路径 可以在配置文件中 或者 启动命令行 指定，默认路径是: <DataDir>/keystore
//							每一个文件的文件名格式为：UTC--<created_at UTC ISO8601>--<address hex>
// 							例如:   UTC--2016-03-22T12-57-55--7ef5a6135f1fd6a02593eedc869c6d41d934aef8
//
//
// todo HD 钱包：分层确定性（Hierarchical Deterministic）钱包
//
//		在 hd.go 中定义
//
//
//
//


// todo accounts模块的第一个概念是Backend，它代表的是不同的钱包类型.
// 			accounts内部有两种类型的Backend：本地目录（keystore）和硬件钱包（usbwallet）.
// 						本地目录的方式支持将私钥加密后存储在本地目录中；
// 						硬件钱包支持ledger和trezor两种
//
// todo accounts的第二个概念是Wallet，它内部的Wallet接口代表着对   [一个账号和私钥]  的管理，而不是“钱包”的概念 (其实就是 "KeyPair" 的概念).

// Account represents an Ethereum account located at a specific location defined
// by the optional URL field.
type Account struct {

	// 以太坊钱包 addr
	Address common.Address `json:"address"` // Ethereum account address derived from the key

	// (可选项) 钱包(keystore)的存放路径
	URL     URL            `json:"url"`     // Optional resource locator within a backend
}



//
//
// todo  下面是 Wallet 接口 和 Backend 接口
//
//	todo 所有钱包实例 都必须实现 Wallet 和 Backend 两个接口 ...
//
//

// todo 注意:
//		一个Wallet对象（如keyStoreWallet）仅仅只代表了一个账户，而不是多个.
//
// 		拿keyStoreWallet来说，它只代表了一个账户，也只代表了一个文件.
//
//
// Wallet represents a software or hardware wallet that might contain one or more
// accounts (derived from the same seed).
type Wallet interface {
	// URL retrieves the canonical path under which this wallet is reachable. It is
	// user by upper layers to define a sorting order over all wallets from multiple
	// backends.
	URL() URL

	// Status returns a textual status to aid the user in the current state of the
	// wallet. It also returns an error indicating any failure the wallet might have
	// encountered.
	Status() (string, error)

	// Open initializes access to a wallet instance. It is not meant to unlock or
	// decrypt account keys, rather simply to establish a connection to hardware
	// wallets and/or to access derivation seeds.
	//
	// The passphrase parameter may or may not be used by the implementation of a
	// particular wallet instance. The reason there is no passwordless open method
	// is to strive towards a uniform wallet handling, oblivious to the different
	// backend providers.
	//
	// Please note, if you open a wallet, you must close it to release any allocated
	// resources (especially important when working with hardware wallets).
	Open(passphrase string) error

	// Close releases any resources held by an open wallet instance.
	Close() error

	// Accounts retrieves the list of signing accounts the wallet is currently aware
	// of. For hierarchical deterministic wallets, the list will not be exhaustive,
	// rather only contain the accounts explicitly pinned during account derivation.
	Accounts() []Account

	// Contains returns whether an account is part of this particular wallet or not.
	Contains(account Account) bool

	// Derive attempts to explicitly derive a hierarchical deterministic account at
	// the specified derivation path. If requested, the derived account will be added
	// to the wallet's tracked account list.
	Derive(path DerivationPath, pin bool) (Account, error)

	// SelfDerive sets a base account derivation path from which the wallet attempts
	// to discover non zero accounts and automatically add them to list of tracked
	// accounts.
	//
	// Note, self derivaton will increment the last component of the specified path
	// opposed to decending into a child path to allow discovering accounts starting
	// from non zero components.
	//
	// You can disable automatic account discovery by calling SelfDerive with a nil
	// chain state reader.
	SelfDerive(base DerivationPath, chain ethereum.ChainStateReader)

	// SignHash requests the wallet to sign the given hash.
	//
	// It looks up the account specified either solely via its address contained within,
	// or optionally with the aid of any location metadata from the embedded URL field.
	//
	// If the wallet requires additional authentication to sign the request (e.g.
	// a password to decrypt the account, or a PIN code o verify the transaction),
	// an AuthNeededError instance will be returned, containing infos for the user
	// about which fields or actions are needed. The user may retry by providing
	// the needed details via SignHashWithPassphrase, or by other means (e.g. unlock
	// the account in a keystore).
	SignHash(account Account, hash []byte) ([]byte, error)

	// SignTx requests the wallet to sign the given transaction.
	//
	// It looks up the account specified either solely via its address contained within,
	// or optionally with the aid of any location metadata from the embedded URL field.
	//
	// If the wallet requires additional authentication to sign the request (e.g.
	// a password to decrypt the account, or a PIN code to verify the transaction),
	// an AuthNeededError instance will be returned, containing infos for the user
	// about which fields or actions are needed. The user may retry by providing
	// the needed details via SignTxWithPassphrase, or by other means (e.g. unlock
	// the account in a keystore).
	SignTx(account Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	// SignHashWithPassphrase requests the wallet to sign the given hash with the
	// given passphrase as extra authentication information.
	//
	// It looks up the account specified either solely via its address contained within,
	// or optionally with the aid of any location metadata from the embedded URL field.
	SignHashWithPassphrase(account Account, passphrase string, hash []byte) ([]byte, error)

	// SignTxWithPassphrase requests the wallet to sign the given transaction, with the
	// given passphrase as extra authentication information.
	//
	// It looks up the account specified either solely via its address contained within,
	// or optionally with the aid of any location metadata from the embedded URL field.
	SignTxWithPassphrase(account Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

// todo 其实对外面来说 Backend 才是一个大的钱包, 而 Wallet 则是代表 每个账户 (Manager 操作的是 Backend 而不是 Wallet)
//
// todo keystore 类型的钱包中 keystore 实例，和 usbwallet 类型钱包中 hub 实例， 其实就是两种类型钱包的 Backend 实现.
//
// Backend is a "wallet provider" that may contain a batch of accounts they can
// sign transactions with and upon request, do so.
type Backend interface {
	// Wallets retrieves the list of wallets the backend is currently aware of.
	//
	// The returned wallets are not opened by default. For software HD wallets this
	// means that no base seeds are decrypted, and for hardware wallets that no actual
	// connection is established.
	//
	// The resulting wallet list will be sorted alphabetically based on its internal
	// URL assigned by the backend. Since wallets (especially hardware) may come and
	// go, the same wallet might appear at a different positions in the list during
	// subsequent retrievals.
	Wallets() []Wallet

	// Subscribe creates an async subscription to receive notifications when the
	// backend detects the arrival or departure of a wallet.
	Subscribe(sink chan<- WalletEvent) event.Subscription
}


// WalletEventType represents the different event types that can be fired by
// the wallet subscription subsystem.
type WalletEventType int

const (
	// WalletArrived is fired when a new wallet is detected either via USB or via
	// a filesystem event in the keystore.
	WalletArrived WalletEventType = iota

	// WalletOpened is fired when a wallet is successfully opened with the purpose
	// of starting any background processes such as automatic key derivation.
	WalletOpened

	// WalletDropped
	WalletDropped
)

// WalletEvent is an event fired by an account backend when a wallet arrival or
// departure is detected.
type WalletEvent struct {
	Wallet Wallet          // Wallet instance arrived or departed
	Kind   WalletEventType // Event type that happened in the system
}
