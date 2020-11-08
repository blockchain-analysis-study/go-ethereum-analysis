// Copyright 2018 The github.com/go-ethereum-analysis Authors
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
	"net"

	"github.com/go-ethereum-analysis/log"
)

// StartHTTPEndpoint starts the HTTP RPC endpoint, configured with cors/vhosts/modules
func StartHTTPEndpoint(endpoint string, apis []API, modules []string, cors []string, vhosts []string, timeouts HTTPTimeouts) (net.Listener, *Server, error) {
	// Generate the whitelist based on the allowed modules
	whitelist := make(map[string]bool)
	for _, module := range modules { // todo HTTP Server 启动后, 根据配置文件中的 jsonrpc api 的 service 白名单信息生成一个 临时的白名单 map (如: eth、admin、debug 等等)
		whitelist[module] = true
	}
	// Register all the APIs exposed by the services
	handler := NewServer()  // 实例化  HTTP 的 RPC Server
	for _, api := range apis {

		// 判断 api 是否 对外开放
		if whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public) { // 判断 api 是否 对外开放 (HTTP)

			if err := handler.RegisterName(api.Namespace, api.Service); err != nil { // 逐个 将各种 API (Miner/Debug/BlockChain/Account 等等) 的 name 和 实例引用 注册到 HTTP Server 实例中
				return nil, nil, err
			}
			log.Debug("HTTP registered", "namespace", api.Namespace)
		}
	}
	// All APIs registered, start the HTTP listener
	var (
		listener net.Listener
		err      error
	)

	// 先监听 TCP
	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return nil, nil, err
	}

	// 使用 TCP Listen 创建一个 HTTP Server   (HTTP 是 基于 TCP 的)
	go NewHTTPServer(cors, vhosts, timeouts, handler).Serve(listener)  // 调用其 Serve() 方法就可以构造一个 HTTP 服务端
	return listener, handler, err
}

// StartWSEndpoint starts a websocket endpoint
func StartWSEndpoint(endpoint string, apis []API, modules []string, wsOrigins []string, exposeAll bool) (net.Listener, *Server, error) {

	// Generate the whitelist based on the allowed modules
	whitelist := make(map[string]bool)
	for _, module := range modules {  // todo WebSocket Server 启动后, 根据配置文件中的 jsonrpc api 的 service 白名单信息生成一个 临时的白名单 map (如: eth、admin、debug 等等)
		whitelist[module] = true
	}
	// Register all the APIs exposed by the services
	handler := NewServer()  // 实例化  WebSocket  的 RPC Server
	for _, api := range apis {
		if exposeAll || whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public) { // 判断 api 是否 对外开放 (WebSocket)

			if err := handler.RegisterName(api.Namespace, api.Service); err != nil { // 逐个 将各种 API (Miner/Debug/BlockChain/Account 等等) 的 name 和 实例引用 注册到  WebSocket Server 实例中
				return nil, nil, err
			}
			log.Debug("WebSocket registered", "service", api.Service, "namespace", api.Namespace)
		}
	}
	// All APIs registered, start the HTTP listener
	var (
		listener net.Listener
		err      error
	)

	// 先监听 TCP
	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return nil, nil, err
	}

	// 使用 TCP Listen 创建一个 WebSocket Server   (WebSocket 是 基于 TCP 的)
	go NewWSServer(wsOrigins, handler).Serve(listener) // 调用其 Serve() 方法就可以构造一个 WebSocket 服务端
	return listener, handler, err

}

// StartIPCEndpoint starts an IPC endpoint.
//
// IPC 使用 pipe 模式实现的  (契合了 操作系统的 IPC调用模式就是 pipe)
func StartIPCEndpoint(ipcEndpoint string, apis []API) (net.Listener, *Server, error) {
	// Register all the APIs exposed by the services.
	handler := NewServer()  // 实例化  IPC 的 RPC Server
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil { // 逐个将各种 API (Miner/Debug/BlockChain/Account 等等) 的 name 和 实例引用 注册到  IPC Server 实例中
			return nil, nil, err
		}
		log.Debug("IPC registered", "namespace", api.Namespace)
	}
	// All APIs registered, start the IPC listener.
	//
	// 直接使用 命令行指定的  ipc 端点 名称, 启动 IPC  Listen
	listener, err := ipcListen(ipcEndpoint)
	if err != nil {
		return nil, nil, err
	}
	go handler.ServeListener(listener)  // 使用 IPC Listen 启动 IPC Server
	return listener, handler, nil
}
