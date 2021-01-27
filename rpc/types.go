// Copyright 2015 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package rpc

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"

	mapset "github.com/deckarep/golang-set"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/common/hexutil"
)

// API describes the set of methods offered over the RPC interface
//
// 实现 jsonRPC API 的接口结构
type API struct {

	// 整个 api 模块名, 如:  eth、  miner、  debug 等等
	//
	// 和 Service 字段相呼应
	Namespace string      // namespace under which the rpc methods of Service are exposed

	// api 的版本
	Version   string      // api version for DApp's

	// 当前 模块 api 方法的 Service实现引用
	//
	// 和 Namespace 字段相呼应
	//
	// 如: NewPublicMinerAPI、NewPrivateMinerAPI、NewPublicAccountAPI、NewPrivateAccountAPI 等等实例的引用
	//
	Service   interface{} // receiver instance which holds the methods

	// 当前 模块 api 是否对外开放 (在 HTTP  的 rpc 服务中 whitelist 中用到)
	Public    bool        // indication if the methods must be considered safe for public use
}

// callback is a method callback which was registered in the server
//
type callback struct {
	rcvr        reflect.Value  // receiver of method												NewPublicAdminAPI、NewPrivateBlockChainAPI 等等的反射Value
	method      reflect.Method // callback															NewPublicAdminAPI、NewPrivateBlockChainAPI 等等的 某个 Fn
	argTypes    []reflect.Type // input argument types												Fn 的 入参 (input)
	hasCtx      bool           // method's first argument is a context (not included in argTypes)	检测第一个参数是否为context 的标识位
	errPos      int            // err return idx, of -1 when method cannot return error				返回错误的索引err，无法返回则为-1
	isSubscribe bool           // indication if the callback is a subscription						该callback是否为订阅
}

// service represents a registered object
//
type service struct {  // 对 将各种 API (Miner/Debug/BlockChain/Account 等等) 的封装

	name          string        // name for service     						name字段为 miner、debug、account、admin 等等
	typ           reflect.Type  // receiver type								类型为: NewPublicAdminAPI、NewPrivateBlockChainAPI 等等的反射类型

	// service 中的关键字段是 callbacks 和 subscriptions 字段，这两个字段的内容是从 rpc.API.Service 对象中解析出来的、对象的导出方法的相关信息，也就是具体 api 的相关信息.
	//
	// 其中 【订阅】机制允许客户端订阅某些消息，在有消息时服务端会主动推送这些消息到客户端，而不需要客户端不停的查询.
	// 用来进行消息订阅的 API 与普通 API 基本没什么区别，但如果某个方法的第一个参数是 context 类型、第一个返回值的类型是 *Subscription、第二个返回值类型是 error，
	// 那么 rpc 模块就会把这个方法当作一个 [订阅方法] ，并将这个方法的信息放到 service.subscriptions 字段中.
	//
	callbacks     callbacks     // registered handlers							回调Fn 的集合
	subscriptions subscriptions // available subscriptions/notifications		订阅/发布 Fn 的集合
}

// serverRequest is an incoming request
type serverRequest struct {
	id            interface{}
	svcname       string
	callb         *callback  // 本次 json rpc 请求中 客户端要求调用的 Fn 的指针
	args          []reflect.Value
	isUnsubscribe bool		// 是否为  [退订阅] 请求表示
	err           Error
}

type serviceRegistry map[string]*service // collection of services
type callbacks map[string]*callback      // collection of RPC callbacks
type subscriptions map[string]*callback  // collection of subscription callbacks

// Server represents a RPC server
type Server struct {

	services serviceRegistry  	// map(ApiServiceName => service)   其中 ApiServiceName为miner、debug、account、admin 等等
	run      int32				// 用来控制server是否可运行，0: 不可运行, 1: 为运行
	codecsMu sync.Mutex			// 用来保护多线程访问codecs的锁
	codecs   mapset.Set			// 用来存储所有的编码解码器，其实就是所有的连接
}

// rpcRequest represents a raw incoming RPC request
//
// 一个 根据 客户端发来的 codec 转化成的  Req
type rpcRequest struct {
	service  string
	method   string		// 当前 req 被客户端 调用的 Fn
	id       interface{}
	isPubSub bool		// 当前 被调用的  Fn 是否为一个 【订阅】方法??
	params   interface{}
	err      Error // invalid batch element
}

// Error wraps RPC errors, which contain an error code in addition to the message.
type Error interface {
	Error() string  // returns the message
	ErrorCode() int // returns the code
}

// ServerCodec implements reading, parsing and writing RPC messages for the server side of
// a RPC session. Implementations must be go-routine safe since the codec can be called in
// multiple go-routines concurrently.
//
// 它贯穿了客户端和服务器端的交流
//
// 被 jsonCodec 所实现 ...
//
type ServerCodec interface {
	// Read next request
	ReadRequestHeaders() ([]rpcRequest, bool, Error)
	// Parse request argument to the given types
	ParseRequestArguments(argTypes []reflect.Type, params interface{}) ([]reflect.Value, Error)
	// Assemble success response, expects response id and payload
	CreateResponse(id interface{}, reply interface{}) interface{}
	// Assemble error response, expects response id and error
	CreateErrorResponse(id interface{}, err Error) interface{}
	// Assemble error response with extra information about the error through info
	CreateErrorResponseWithInfo(id interface{}, err Error, info interface{}) interface{}
	// Create notification response
	CreateNotification(id, namespace string, event interface{}) interface{}
	// Write msg to client.
	Write(msg interface{}) error
	// Close underlying data stream
	Close()
	// Closed when underlying connection is closed
	Closed() <-chan interface{}
}

type BlockNumber int64

const (
	PendingBlockNumber  = BlockNumber(-2)
	LatestBlockNumber   = BlockNumber(-1)
	EarliestBlockNumber = BlockNumber(0)
)

// UnmarshalJSON parses the given JSON fragment into a BlockNumber. It supports:
// - "latest", "earliest" or "pending" as string arguments
// - the block number
// Returned errors:
// - an invalid block number error when the given argument isn't a known strings
// - an out of range error when the given block number is either too little or too large
func (bn *BlockNumber) UnmarshalJSON(data []byte) error {
	input := strings.TrimSpace(string(data))
	if len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"' {
		input = input[1 : len(input)-1]
	}

	switch input {
	case "earliest":
		*bn = EarliestBlockNumber
		return nil
	case "latest":
		*bn = LatestBlockNumber
		return nil
	case "pending":
		*bn = PendingBlockNumber
		return nil
	}

	blckNum, err := hexutil.DecodeUint64(input)
	if err != nil {
		return err
	}
	if blckNum > math.MaxInt64 {
		return fmt.Errorf("Blocknumber too high")
	}

	*bn = BlockNumber(blckNum)
	return nil
}

func (bn BlockNumber) Int64() int64 {
	return (int64)(bn)
}
