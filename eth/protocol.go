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

package eth

import (
	"fmt"
	"io"
	"math/big"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/types"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/event"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rlp"
)

// Constants to match up protocol versions and messages
const (
	eth62 = 62
	eth63 = 63
)

// ProtocolName is the official short name of the protocol used during capability negotiation.
var ProtocolName = "eth"

// ProtocolVersions are the upported versions of the eth protocol (first is primary).
var ProtocolVersions = []uint{eth63, eth62}

// ProtocolLengths are the number of implemented message corresponding to different protocol versions.
var ProtocolLengths = []uint64{17, 8}

const ProtocolMaxMsgSize = 10 * 1024 * 1024 // Maximum cap on the size of a protocol message

// eth protocol message codes
//
// 下面这些 基本是 p2p Msg 的 code   todo RLPx 传输中使用的  code 做为 MsgId 功能复用的话, 应当大于0x11  (0x00 - 0x10 保留用于 "p2p" 功能)
const (
	// Protocol messages belonging to eth/62
	StatusMsg          = 0x00
	NewBlockHashesMsg  = 0x01
	TxMsg              = 0x02
	GetBlockHeadersMsg = 0x03
	BlockHeadersMsg    = 0x04
	GetBlockBodiesMsg  = 0x05
	BlockBodiesMsg     = 0x06
	NewBlockMsg        = 0x07

	// Protocol messages belonging to eth/63
	GetNodeDataMsg = 0x0d
	NodeDataMsg    = 0x0e
	GetReceiptsMsg = 0x0f
	ReceiptsMsg    = 0x10
)

type errCode int

const (
	ErrMsgTooLarge = iota
	ErrDecode
	ErrInvalidMsgCode
	ErrProtocolVersionMismatch
	ErrNetworkIdMismatch
	ErrGenesisBlockMismatch
	ErrNoStatusMsg
	ErrExtraStatusMsg
	ErrSuspendedPeer
)

func (e errCode) String() string {
	return errorToString[int(e)]
}

// XXX change once legacy code is out
var errorToString = map[int]string{
	ErrMsgTooLarge:             "Message too long",
	ErrDecode:                  "Invalid message",
	ErrInvalidMsgCode:          "Invalid message code",
	ErrProtocolVersionMismatch: "Protocol version mismatch",
	ErrNetworkIdMismatch:       "NetworkId mismatch",
	ErrGenesisBlockMismatch:    "Genesis block mismatch",
	ErrNoStatusMsg:             "No status message",
	ErrExtraStatusMsg:          "Extra status message",
	ErrSuspendedPeer:           "Suspended peer",
}

type txPool interface {
	// AddRemotes should add the given transactions to the pool.
	AddRemotes([]*types.Transaction) []error

	// Pending should return pending transactions.
	// The slice should be modifiable by the caller.
	Pending() (map[common.Address]types.Transactions, error)

	// SubscribeNewTxsEvent should return an event subscription of
	// NewTxsEvent and send events to the given channel.
	SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription
}

// statusData is the network packet for the status message.
//
// statusData是状态消息的网络数据包。
type statusData struct {
	ProtocolVersion uint32  // 协议的版本
	NetworkId       uint64  // 当前本地节点网络的Id
	TD              *big.Int // 当前本地节点的最新难度值
	CurrentBlock    common.Hash // 当前本地节点链上最高块的Hash
	GenesisBlock    common.Hash // 当前本地节点的创世块Hash
}

// newBlockHashesData is the network packet for the block announcements.
type newBlockHashesData []struct {
	Hash   common.Hash // Hash of one particular block being announced
	Number uint64      // Number of one particular block being announced
}

// getBlockHeadersData represents a block header query.
//
// 抓取一批 header 的实例封装
//
type getBlockHeadersData struct {

	// 拉取 一批 headers 的起点 blockNumber
	Origin  hashOrNumber // Block from which to retrieve headers

	// 最大一次拉多少个 header
	Amount  uint64       // Maximum number of headers to retrieve

	// 在连续的一批 header 中间隔的block 个数:  todo 如:  header1| skip |header2|...|skip|...|headerN
	//
	Skip    uint64       // Blocks to skip between consecutive headers

	// 查询方向（false =上升到最新，true =下降到起源）
	Reverse bool         // Query direction (false = rising towards latest, true = falling towards genesis)
}

// hashOrNumber is a combined field for specifying an origin block.
type hashOrNumber struct {
	Hash   common.Hash // Block hash from which to retrieve headers (excludes Number)
	Number uint64      // Block hash from which to retrieve headers (excludes Hash)
}

// EncodeRLP is a specialized encoder for hashOrNumber to encode only one of the
// two contained union fields.
func (hn *hashOrNumber) EncodeRLP(w io.Writer) error {
	if hn.Hash == (common.Hash{}) {
		return rlp.Encode(w, hn.Number)
	}
	if hn.Number != 0 {
		return fmt.Errorf("both origin hash (%x) and number (%d) provided", hn.Hash, hn.Number)
	}
	return rlp.Encode(w, hn.Hash)
}

// DecodeRLP is a specialized decoder for hashOrNumber to decode the contents
// into either a block hash or a block number.
func (hn *hashOrNumber) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	origin, err := s.Raw()
	if err == nil {
		switch {
		case size == 32:
			err = rlp.DecodeBytes(origin, &hn.Hash)
		case size <= 8:
			err = rlp.DecodeBytes(origin, &hn.Number)
		default:
			err = fmt.Errorf("invalid input size %d for origin", size)
		}
	}
	return err
}

// newBlockData is the network packet for the block propagation message.
type newBlockData struct {
	Block *types.Block
	TD    *big.Int
}

// blockBody represents the data content of a single block.
type blockBody struct {
	Transactions []*types.Transaction // Transactions contained within a block
	Uncles       []*types.Header      // Uncles contained within a block
}

// blockBodiesData is the network packet for block content distribution.
type blockBodiesData []*blockBody
