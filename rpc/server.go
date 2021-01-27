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
	"context"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	mapset "github.com/deckarep/golang-set"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
)

const MetadataApi = "rpc"

// CodecOption specifies which type of messages this codec supports
type CodecOption int

const (
	// OptionMethodInvocation is an indication that the codec supports RPC method calls
	OptionMethodInvocation CodecOption = 1 << iota

	// OptionSubscriptions is an indication that the codec suports RPC notifications
	OptionSubscriptions = 1 << iota // support pub sub
)

// NewServer will create a new server instance with no registered handlers.
//
func NewServer() *Server {  // 实例化 (HTTP/WebSocket/IPC/InProc) 的 RPC Server
	server := &Server{
		services: make(serviceRegistry),
		codecs:   mapset.NewSet(),
		run:      1,
	}

	// register a default service which will provide meta information about the RPC service such as the services and
	// methods it offers.  		注册一个默认的rpc服务，该服务可以提供server的一些基本信息.
	// RPCService的目的是给出server中的一些基本参数信息，目前来说，貌似只能给出拥有的service名称和对应的版本号，而且都是1.0    <只有这个方法:  `(s *RPCService) Modules()` >
	rpcService := &RPCService{server}
	server.RegisterName(MetadataApi, rpcService)   // 将各种 RPC API  的 name 和 实例引用 注册到 (HTTP/WebSocket/IPC/InProc) Server 实例中； (HTTP/WebSocket/IPC/InProc Sever 都会有 RCP API 注册进来)

	return server
}

// RPCService gives meta information about the server.
// e.g. gives information about the loaded modules.
type RPCService struct {
	server *Server
}

// Modules returns the list of RPC services with their version number
func (s *RPCService) Modules() map[string]string {
	modules := make(map[string]string)
	for name := range s.server.services {
		modules[name] = "1.0"
	}
	return modules
}

// RegisterName will create a service for the given rcvr type under the given name. When no methods on the given rcvr
// match the criteria to be either a RPC method or a subscription an error is returned. Otherwise a new service is
// created and added to the service collection this server instance serves.
func (s *Server) RegisterName(name string, rcvr interface{}) error {  // 将各种 API (Miner/Debug/BlockChain/Account 等等) 的 name 和 实例引用 注册到 (HTTP/WebSocket/IPC/InProc) Server 实例中
	if s.services == nil {
		s.services = make(serviceRegistry)
	}

	svc := new(service)
	svc.typ = reflect.TypeOf(rcvr)
	rcvrVal := reflect.ValueOf(rcvr)

	if name == "" {
		return fmt.Errorf("no service name for type %s", svc.typ.String())
	}
	if !isExported(reflect.Indirect(rcvrVal).Type().Name()) {  // 检查提供 [api 的对象] 自身是否是导出的，这里要求这个对象必须是导出的，否则后面就无法调用这个对象的所有方法.
		return fmt.Errorf("%s is not exported", reflect.Indirect(rcvrVal).Type().Name())
	}

	// 使用service反射后的结果来判断是属于 `对外开放的 Fn` 还是 `订阅 Fn`
	methods, subscriptions := suitableCallbacks(rcvrVal, svc.typ)  // (NewPublicAdminAPI、NewPrivateAccountAPI 等等) 类型 的 api service 的 Fn

	if len(methods) == 0 && len(subscriptions) == 0 {
		return fmt.Errorf("Service %T doesn't have any suitable methods/subscriptions to expose", rcvr)
	}

	// already a previous service register under given name, merge methods/subscriptions
	//
	// 若 (HTTP/WebSocket/IPC/InProc) 的 API services [即: NewPublicAdminAPI、NewPrivateAccountAPI 等等] 中已经有了 该 service ，则直接合并 [普通Fn] 和 [订阅Fn]
	if regsvc, present := s.services[name]; present {
		for _, m := range methods {
			regsvc.callbacks[formatName(m.method.Name)] = m
		}
		for _, s := range subscriptions {
			regsvc.subscriptions[formatName(s.method.Name)] = s
		}
		return nil
	}

	svc.name = name
	svc.callbacks, svc.subscriptions = methods, subscriptions

	s.services[svc.name] = svc   // (api  service Name  ==> api service ); 其中 API services [即: NewPublicAdminAPI、NewPrivateAccountAPI 等等]
	return nil
}

// serveRequest will reads requests from the codec, calls the RPC callback and
// writes the response to the given codec.
//
// If singleShot is true it will process a single request, otherwise it will handle
// requests until the codec returns an error when reading a request (in most cases
// an EOF). It executes requests in parallel when singleShot is false.
//
//
//  入参:
//		ctx:   			上下文
//		codec:			jsonCodec实现, 表示 客户端发来的信息
//		singleShot:		是否为 同步处理模式,  true: 同步,   false: 异步
// 		options:
//
func (s *Server) serveRequest(ctx context.Context, codec ServerCodec, singleShot bool, options CodecOption) error {  // todo 具体处理客户端发来的请求
	var pend sync.WaitGroup

	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Error(string(buf))
		}
		s.codecsMu.Lock()
		s.codecs.Remove(codec)
		s.codecsMu.Unlock()
	}()

	//	ctx, cancel := context.WithCancel(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// todo 【订阅】 和 【退订】 只有使用 WebSocket 或 IPC 的方式连接服务端时，才可以使用这个功能；使用 HTTP 连接时是无法使用的.
	//
	//		WebSocket 或 IPC 这两种连接的消息处理函数也是在连接建立以后一直运行，直到连接中断后才会退出.
	// 						所以在这里我们首先要注意的是在消息处理函数运行之初，建立的一个 notifier 对象.

	// if the codec supports notification include a notifier that callbacks can use
	// to send notification to clients. It is tied to the codec/connection. If the
	// connection is closed the notifier will stop and cancels all active subscriptions.
	if options&OptionSubscriptions == OptionSubscriptions {
		// todo 后面的 s.exec() 或者 s.execBatch() 中调用的 s.handle() 中最终调用的 `NotifierFromContext(ctx)` [从 ctx 取得类型为 Notifier 的变量]
		//		其实就是这里放到  ctx 中的 ...
		//
		// WebSocket 或 IPC 的 handler 在某个连接连接成功以后被调用，其后一直运行，直到连接断开.
		//
		// 因此刚才调用 newNotifier 的代码类似于一个初始化的代码，只要连接不断开，使用此连接订阅的消息都会记录在这个 notifier 中.
		//
		// 换句话说，「订阅」和「退订」请求中的 ID，只有在同一连接中有效.
		//
		//
		// WebSocket 或 IPC 方式的连接，参数 options 都会带有 OptionSubscriptions 标志位，
		// 					因此也一定会调用 newNotifier 在 ctx 中创建一个 Notifier 类型的变量.
		// 					这个变量是消息订阅的关键，也是中枢.
		// 					所有本次连接的消息订阅事件都是记录在这个对象中的.
		//
		//
		// 因为 Client 和 Server 发起 WebSocket 或者 IPC 连接后,
		// 这个 连接 会一直 存在, 在这个连接中 只有一个 Notifier 实例,
		// 但是在该连接的生命周期中, 客户端是可以发起 多个 类型的 [订阅] 方法的调用的
		// 每个 [订阅] 方法的调用都会对应一个  ID (毕竟是 长连接, 那么[订阅]方法在被调用后会一直存活着, 直到连接断开或者[退订])
		//
		ctx = context.WithValue(ctx, notifierKey{}, newNotifier(codec))
	}
	s.codecsMu.Lock()
	if atomic.LoadInt32(&s.run) != 1 { // server stopped
		s.codecsMu.Unlock()
		return &shutdownError{}
	}
	s.codecs.Add(codec)
	s.codecsMu.Unlock()

	// test if the server is ordered to stop
	for atomic.LoadInt32(&s.run) == 1 {

		reqs, batch, err := s.readRequest(codec)  // todo Server.readRequest 处理发送过来的请求数据，将这些请求数据组织到 reqs 变量里
		if err != nil {
			// If a parsing error occurred, send an error
			if err.Error() != "EOF" {
				log.Debug(fmt.Sprintf("read error %v\n", err))
				codec.Write(codec.CreateErrorResponse(nil, err))
			}
			// Error or end of stream, wait for requests and tear down
			pend.Wait()
			return nil
		}

		// check if server is ordered to shutdown and return an error
		// telling the client that his request failed.
		if atomic.LoadInt32(&s.run) != 1 {
			err = &shutdownError{}
			if batch {
				resps := make([]interface{}, len(reqs))
				for i, r := range reqs {
					resps[i] = codec.CreateErrorResponse(&r.id, err)
				}
				codec.Write(resps)
			} else {
				codec.Write(codec.CreateErrorResponse(&reqs[0].id, err))
			}
			return nil
		}

		// 如果是 同步模式,  走这里的 if 并直接返回 .

		// If a single shot request is executing, run and return immediately
		//
		// 根据 singleShot 值的不同来决定当前请求是在新的 goroutine 中执行，还是直接执行请求并返回.
		//
		// 当连接方式是 HTTP 时，singleShot 的值为 true，todo 因为对于 http 连接，一次连接就是一次请求，请求执行完就直接返回结果，不需要使用 gotoutine
		if singleShot {
			if batch {
				s.execBatch(ctx, codec, reqs) // Server.execBatch 用来执行一次请求中包含多个 API 调用的情况，我们这里暂不关心这种情况，其实处理方式都是一样的，无非就是多个循环而已
			} else {
				s.exec(ctx, codec, reqs[0])
			}
			return nil
		}

		// 如果是 异步模式:  走下面的 go

		// For multi-shot connections, start a goroutine to serve and loop back
		pend.Add(1)

		go func(reqs []*serverRequest, batch bool) {
			defer pend.Done()
			if batch {
				s.execBatch(ctx, codec, reqs) // Server.execBatch 用来执行一次请求中包含多个 API 调用的情况，我们这里暂不关心这种情况，其实处理方式都是一样的，无非就是多个循环而已
			} else {
				s.exec(ctx, codec, reqs[0])
			}
		}(reqs, batch)
	}
	return nil
}

// ServeCodec reads incoming requests from codec, calls the appropriate callback and writes the
// response back using the given codec. It will block until the codec is closed or the server is
// stopped. In either case the codec is closed.
//
//
// 参数codec中存储的是客户端发来的请求，经过处理后，会将响应结果写入codec中并返回给客户端
//
func (s *Server) ServeCodec(codec ServerCodec, options CodecOption) {  // 异步处理 客户端 发过来的 rpc 方法调用请求
	defer codec.Close()
	s.serveRequest(context.Background(), codec, false, options)  // 具体处理客户端发来的请求 (异步处理)  todo  WebSocket、IPC、以及 InProc 使用
}

// ServeSingleRequest reads and processes a single RPC request from the given codec. It will not
// close the codec unless a non-recoverable error has occurred. Note, this method will return after
// a single request has been processed!
func (s *Server) ServeSingleRequest(ctx context.Context, codec ServerCodec, options CodecOption) {
	s.serveRequest(ctx, codec, true, options)  // 具体处理客户端发来的请求   (同步处理)   todo 只有 HTTP 使用
}

// Stop will stop reading new requests, wait for stopPendingRequestTimeout to allow pending requests to finish,
// close all codecs which will cancel pending requests/subscriptions.
func (s *Server) Stop() {
	if atomic.CompareAndSwapInt32(&s.run, 1, 0) {
		log.Debug("RPC Server shutdown initiatied")
		s.codecsMu.Lock()
		defer s.codecsMu.Unlock()
		s.codecs.Each(func(c interface{}) bool {
			c.(ServerCodec).Close()
			return true
		})
	}
}

// createSubscription will call the subscription callback and returns the subscription id or error.
func (s *Server) createSubscription(ctx context.Context, c ServerCodec, req *serverRequest) (ID, error) {
	// subscription have as first argument the context following optional arguments
	args := []reflect.Value{req.callb.rcvr, reflect.ValueOf(ctx)}
	args = append(args, req.args...)
	reply := req.callb.method.Func.Call(args)  // 反射 调用 [订阅]  方法

	if !reply[1].IsNil() { // subscription creation failed
		return "", reply[1].Interface().(error)
	}

	return reply[0].Interface().(*Subscription).ID, nil
}

// handle executes a request and returns the response from the callback.
func (s *Server) handle(ctx context.Context, codec ServerCodec, req *serverRequest) (interface{}, func()) {  // todo 真正的去处理 jsonrpc 请求调用 Server 的 service api 方法
	if req.err != nil {
		return codec.CreateErrorResponse(&req.id, req.err), nil
	}

	//
	// 代码在一开始解析请求数据的阶段就已经准备好了当前是 哪种类型的调用，以及该调用哪个方法（req.callb）; 然后根据不同类型的请求，使用 go 的反射库特性，对方法进行调用.
	//


	// todo  先对「退订」这种情况进行处理
	//
	// 		如果是「退订」请求，它首先从 ctx 取得类型为 Notifier 的变量.
	// 		然后将参数列表中的第一个参数作为 ID，并调用 Notifier.unsubscribe 退订指定的消息.
	//
	if req.isUnsubscribe { // cancel subscription, first param must be the subscription id
		if len(req.args) >= 1 && req.args[0].Kind() == reflect.String {
			notifier, supported := NotifierFromContext(ctx)
			if !supported { // interface doesn't support subscriptions (e.g. http)
				return codec.CreateErrorResponse(&req.id, &callbackError{ErrNotificationsUnsupported.Error()}), nil
			}

			subid := ID(req.args[0].String())
			if err := notifier.unsubscribe(subid); err != nil {
				return codec.CreateErrorResponse(&req.id, &callbackError{err.Error()}), nil
			}

			return codec.CreateResponse(req.id, true), nil
		}
		return codec.CreateErrorResponse(&req.id, &invalidParamsError{"Expected subscription id as first argument"}), nil
	}


	// todo 如果是 [订阅]
	//
	//    那么调用 Server.createSubscription() 响应这一请求，并返回本次订阅的 ID.
	//
	if req.callb.isSubscribe {
		subid, err := s.createSubscription(ctx, codec, req)
		if err != nil {
			return codec.CreateErrorResponse(&req.id, &callbackError{err.Error()}), nil
		}

		// active the subscription after the sub id was successfully sent to the client
		activateSub := func() {
			notifier, _ := NotifierFromContext(ctx)
			notifier.activate(subid, req.svcname)
		}

		return codec.CreateResponse(req.id, subid), activateSub
	}

	// todo 如果是 普通的 API 请求.
	//
	//  首先检查  请求数据中的参数个数 与 注册时定义的参数 个数是否一致，如果不一致肯定是无法调用的.
	// 	然后就是构造参数列表，并通过 req.callb.method.Func.Call() 调用 (这与「订阅」请法时的调用方式一样，用的都是 go 语言反射库的特性).
	//
	// regular RPC call, prepare arguments
	if len(req.args) != len(req.callb.argTypes) {
		rpcErr := &invalidParamsError{fmt.Sprintf("%s%s%s expects %d parameters, got %d",
			req.svcname, serviceMethodSeparator, req.callb.method.Name,
			len(req.callb.argTypes), len(req.args))}
		return codec.CreateErrorResponse(&req.id, rpcErr), nil
	}

	arguments := []reflect.Value{req.callb.rcvr}
	if req.callb.hasCtx {
		arguments = append(arguments, reflect.ValueOf(ctx))
	}
	if len(req.args) > 0 {
		arguments = append(arguments, req.args...)
	}

	// execute RPC method and return result
	reply := req.callb.method.Func.Call(arguments)  // 反射 调用 普通 rpc api 方法
	if len(reply) == 0 {
		return codec.CreateResponse(req.id, nil), nil
	}
	if req.callb.errPos >= 0 { // test if method returned an error
		if !reply[req.callb.errPos].IsNil() {
			e := reply[req.callb.errPos].Interface().(error)
			res := codec.CreateErrorResponse(&req.id, &callbackError{e.Error()})
			return res, nil
		}
	}
	return codec.CreateResponse(req.id, reply[0].Interface()), nil
}

// exec executes the given request and writes the result back using the codec.
func (s *Server) exec(ctx context.Context, codec ServerCodec, req *serverRequest) {  // 去调用 Server 中的对应 req 中的 api 去执行  ...
	var response interface{}
	var callback func()
	if req.err != nil {
		response = codec.CreateErrorResponse(&req.id, req.err)
	} else {
		response, callback = s.handle(ctx, codec, req) // todo 主要功能在被调用的 Server.handle 这个方法上，它会调用相应的 API，并将结果返回到 response 变量中     (在 exec() 中 )
	}

	if err := codec.Write(response); err != nil {
		log.Error(fmt.Sprintf("%v\n", err))
		codec.Close()
	}

	// when request was a subscribe request this allows these subscriptions to be actived
	if callback != nil {
		callback()  // 只有 [订阅] 才会有 回调,  因为他们是给 WebSocket | IPC 用的方法 (但是 [退订] 是没有 回调的, 毕竟都 取消 [订阅] 了啊)
	}
}

// execBatch executes the given requests and writes the result back using the codec.
// It will only write the response back when the last request is processed.
func (s *Server) execBatch(ctx context.Context, codec ServerCodec, requests []*serverRequest) {  // Server.execBatch 用来执行一次请求中包含多个 API 调用的情况
	responses := make([]interface{}, len(requests))
	var callbacks []func()
	for i, req := range requests {
		if req.err != nil {
			responses[i] = codec.CreateErrorResponse(&req.id, req.err)
		} else {
			var callback func()
			if responses[i], callback = s.handle(ctx, codec, req); callback != nil { // todo 主要功能在被调用的 Server.handle 这个方法上，它会调用相应的 API，并将结果返回到 response 变量中   (在 execBatch() 中 )
				callbacks = append(callbacks, callback)
			}
		}
	}

	if err := codec.Write(responses); err != nil {
		log.Error(fmt.Sprintf("%v\n", err))
		codec.Close()
	}

	// when request holds one of more subscribe requests this allows these subscriptions to be activated
	for _, c := range callbacks {
		c()  // 只有 [订阅] 才会有 回调,  因为他们是给 WebSocket | IPC 用的方法 (但是 [退订] 是没有 回调的, 毕竟都 取消 [订阅] 了啊)
	}
}

// readRequest requests the next (batch) request from the codec. It will return the collection
// of requests, an indication if the request was a batch, the invalid request identifier and an
// error when the request could not be read/parsed.
//
// todo  只在 `(s *Server) serveRequest() ` 中被调用 ...
//
func (s *Server) readRequest(codec ServerCodec) ([]*serverRequest, bool, Error) {  // 将 codec 解析成 req 和 batch

	// 目前， 只有 `jsonCodec` 实现 ...
	reqs, batch, err := codec.ReadRequestHeaders()  // 首先调用 Servercodec.ReadRequestHeaders 读取请求数据，然后进一步解析这些数据，并填充到 requests 变量中返回
	if err != nil {
		return nil, batch, err
	}

	requests := make([]*serverRequest, len(reqs))

	// verify requests    逐个校验 reqs
	for i, r := range reqs {
		var ok bool
		var svc *service

		if r.err != nil {
			requests[i] = &serverRequest{id: r.id, err: r.err}
			continue
		}

		// todo 处理 [退订] 请求

		// 首先处理的是「退订」的请求，如果 r.isPubSub 的值为 true（在 ServerCodec.ReadRequestHeaders 中被设置，后面会讲到），
		// 且 API 的名字后缀为「 _unsubscribe 」，就认为这是一个「退订」的请求.
		//
		// 这种情况的 serverRequest 变量很简单，就是设置 id 和 isUnsubscribe 字段就可以了.
		// 然后调用 ServerCodec.ParseRequestArguments() 从请求数据中解析参数信息，存储到 serverRequest.args 字段中.
		//
		if r.isPubSub && strings.HasSuffix(r.method, unsubscribeMethodSuffix) {
			requests[i] = &serverRequest{id: r.id, isUnsubscribe: true}
			argTypes := []reflect.Type{reflect.TypeOf("")} // expect subscription id as first arg
			if args, err := codec.ParseRequestArguments(argTypes, r.params); err == nil {  // 调用 ServerCodec.ParseRequestArguments() 从请求数据中解析参数信息，存储到 serverRequest.args 字段中
				requests[i].args = args
			} else {
				requests[i].err = &invalidParamsError{err.Error()}
			}
			continue
		}

		// todo 处理 [订阅] 请求

		if svc, ok = s.services[r.service]; !ok { // rpc method isn't available
			requests[i] = &serverRequest{id: r.id, err: &methodNotFoundError{r.service, r.method}}
			continue
		}

		// 判断是否是「订阅」请求
		if r.isPubSub { // eth_subscribe, r.method contains the subscription method name

		// 通过请求的 API 的名字，从 svc.subscriptions 中拿到对应的 API 信息，并存储在 callb 变量中.
		//
		// 这个变量接着被转存到了 serverRequest.callb 字段中.
		//
		// 和 上面的 [退订] 的处理中类似，请求中的参数信息也是存储到了 serverRequest.args 中.
		//
			if callb, ok := svc.subscriptions[r.method]; ok {
				requests[i] = &serverRequest{id: r.id, svcname: svc.name, callb: callb}
				if r.params != nil && len(callb.argTypes) > 0 {
					argTypes := []reflect.Type{reflect.TypeOf("")}
					argTypes = append(argTypes, callb.argTypes...)
					if args, err := codec.ParseRequestArguments(argTypes, r.params); err == nil { // 请求中的参数信息也是存储到了 serverRequest.args 中
						requests[i].args = args[1:] // first one is service.method name which isn't an actual argument
					} else {
						requests[i].err = &invalidParamsError{err.Error()}
					}
				}
			} else {
				requests[i] = &serverRequest{id: r.id, err: &methodNotFoundError{r.service, r.method}}
			}
			continue
		}

		// todo 处理 普通请求
		//
		// 判断不是「订阅」信息，那么应该是一个普通的 API 请求了

		// 先是从 svc.callbacks 中取出 API 的信息到 callb 变量中，与「订阅」消息区别的是这是一个普通 API 请求，
		// 因此 API 信息是从 svc.callbacks 中获取而非 svc.subscriptions 中.
		//
		//
		// 和上面的 [退订] 和 [订阅] 类似, 请求的参数信息也是存储在 serverRequest.args 中.
		if callb, ok := svc.callbacks[r.method]; ok { // lookup RPC method
			requests[i] = &serverRequest{id: r.id, svcname: svc.name, callb: callb}
			if r.params != nil && len(callb.argTypes) > 0 {
				if args, err := codec.ParseRequestArguments(callb.argTypes, r.params); err == nil {  // 请求的参数信息也是存储在 serverRequest.args 中.
					requests[i].args = args
				} else {
					requests[i].err = &invalidParamsError{err.Error()}
				}
			}
			continue
		}

		requests[i] = &serverRequest{id: r.id, err: &methodNotFoundError{r.service, r.method}}
	}

	return requests, batch, nil
}
