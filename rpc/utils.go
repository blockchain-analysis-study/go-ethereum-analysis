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

package rpc

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	subscriptionIDGenMu sync.Mutex
	subscriptionIDGen   = idGenerator()
)

// Is this an exported - upper case - name?
func isExported(name string) bool {
	rune, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(rune)
}

// Is this type exported or a builtin?
func isExportedOrBuiltinType(t reflect.Type) bool {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	// PkgPath will be non-empty even for an exported type,
	// so we need to check the type name as well.
	return isExported(t.Name()) || t.PkgPath() == ""
}

var contextType = reflect.TypeOf((*context.Context)(nil)).Elem()

// isContextType returns an indication if the given t is of context.Context or *context.Context type
func isContextType(t reflect.Type) bool {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t == contextType
}

var errorType = reflect.TypeOf((*error)(nil)).Elem()

// Implements this type the error interface
func isErrorType(t reflect.Type) bool {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Implements(errorType)
}

var subscriptionType = reflect.TypeOf((*Subscription)(nil)).Elem()

// isSubscriptionType returns an indication if the given t is of Subscription or *Subscription type
func isSubscriptionType(t reflect.Type) bool {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t == subscriptionType
}

// isPubSub tests whether the given method has as as first argument a context.Context
// and returns the pair (Subscription, error)
//
func isPubSub(methodType reflect.Type) bool {  // 判断 某个 API service 的方法是否为 [订阅方法]; 其中 API service 为 (NewPublicAdminAPI、NewPrivateAccountAPI 等等之类)
	// numIn(0) is the receiver type
	if methodType.NumIn() < 2 || methodType.NumOut() != 2 {
		return false
	}

	// 如果某个方法的第一个 入参是 context 类型、第一个返回值的类型是 *Subscription、第二个返回值类型是 error，
	// 那么 rpc 模块就会把这个方法当作一个订阅方法，并将这个方法的信息放到 service.subscriptions 字段中.
	return isContextType(methodType.In(1)) &&
		isSubscriptionType(methodType.Out(0)) &&
		isErrorType(methodType.Out(1))
}

// formatName will convert to first character to lower case
func formatName(name string) string {
	ret := []rune(name)
	if len(ret) > 0 {
		ret[0] = unicode.ToLower(ret[0])
	}
	return string(ret)
}

// suitableCallbacks iterates over the methods of the given type. It will determine if a method satisfies the criteria
// for a RPC callback or a subscription callback and adds it to the collection of callbacks or subscriptions. See server
// documentation for a summary of these criteria.
func suitableCallbacks(rcvr reflect.Value, typ reflect.Type) (callbacks, subscriptions) {
	callbacks := make(callbacks)
	subscriptions := make(subscriptions)

METHODS:
	for m := 0; m < typ.NumMethod(); m++ {
		method := typ.Method(m)
		mtype := method.Type
		mname := formatName(method.Name)  // 先将 Fn 的首字母变为小写,  后续需要和 api service 的 Namespace 拼接成 `eth_getBlock` 的形式
		if method.PkgPath != "" { // method must be exported
			continue
		}

		var h callback   // 对 rcvr 每一个 方法都封装成一个  callback;  其中 rcvr 为:  NewPublicAdminAPI、NewPrivateBlockChainAPI 等等的反射Value
		h.isSubscribe = isPubSub(mtype)  // 判断 API service 的方法是否为 [订阅方法]
		h.rcvr = rcvr
		h.method = method	// NewPublicAdminAPI、NewPrivateBlockChainAPI 等等的 某个 Fn
		h.errPos = -1

		// firstArg 定义了第一个  非 context.Context 类型 的参数的索引，因为后面会填充 callback.argTypes 字段，
		// 			而第一个参数如果是 context.Context 类型，则不会记录在这个字段里，而是记录在 callback.hasCtx 字段里
		firstArg := 1  //
		numIn := mtype.NumIn()
		if numIn >= 2 && mtype.In(1) == contextType {
			h.hasCtx = true
			firstArg = 2
		}

		// 如果 该方法 为 [订阅方法], 我们将其 追加到 subscriptions 集合中
		if h.isSubscribe {
			h.argTypes = make([]reflect.Type, numIn-firstArg) // skip rcvr type
			for i := firstArg; i < numIn; i++ {
				argType := mtype.In(i)
				if isExportedOrBuiltinType(argType) {
					h.argTypes[i-firstArg] = argType
				} else {
					continue METHODS
				}
			}

			subscriptions[mname] = &h
			continue METHODS
		}

		// determine method arguments, ignore first arg since it's the receiver type
		// Arguments must be exported or builtin types
		h.argTypes = make([]reflect.Type, numIn-firstArg)
		for i := firstArg; i < numIn; i++ {
			argType := mtype.In(i)
			if !isExportedOrBuiltinType(argType) {
				continue METHODS
			}
			h.argTypes[i-firstArg] = argType
		}

		// check that all returned values are exported or builtin types
		for i := 0; i < mtype.NumOut(); i++ {
			if !isExportedOrBuiltinType(mtype.Out(i)) {
				continue METHODS
			}
		}

		// when a method returns an error it must be the last returned value
		h.errPos = -1
		for i := 0; i < mtype.NumOut(); i++ {
			if isErrorType(mtype.Out(i)) {
				h.errPos = i
				break
			}
		}

		if h.errPos >= 0 && h.errPos != mtype.NumOut()-1 {
			continue METHODS
		}

		switch mtype.NumOut() {
		case 0, 1, 2:
			if mtype.NumOut() == 2 && h.errPos == -1 { // method must one return value and 1 error
				continue METHODS
			}
			callbacks[mname] = &h   // 一般对外的方法 追加到  callbacks 集合中
		}
	}

	return callbacks, subscriptions
}

// idGenerator helper utility that generates a (pseudo) random sequence of
// bytes that are used to generate identifiers.
func idGenerator() *rand.Rand {
	if seed, err := binary.ReadVarint(bufio.NewReader(crand.Reader)); err == nil {
		return rand.New(rand.NewSource(seed))
	}
	return rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
}

// NewID generates a identifier that can be used as an identifier in the RPC interface.
// e.g. filter and subscription identifier.
func NewID() ID {
	subscriptionIDGenMu.Lock()
	defer subscriptionIDGenMu.Unlock()

	id := make([]byte, 16)
	for i := 0; i < len(id); i += 7 {
		val := subscriptionIDGen.Int63()
		for j := 0; i+j < len(id) && j < 7; j++ {
			id[i+j] = byte(val)
			val >>= 8
		}
	}

	rpcId := hex.EncodeToString(id)
	// rpc ID's are RPC quantities, no leading zero's and 0 is 0x0
	rpcId = strings.TrimLeft(rpcId, "0")
	if rpcId == "" {
		rpcId = "0"
	}

	return ID("0x" + rpcId)
}
