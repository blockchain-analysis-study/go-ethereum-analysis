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

package node

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/go-ethereum-analysis/accounts"
	"github.com/go-ethereum-analysis/ethdb"
	"github.com/go-ethereum-analysis/event"
	"github.com/go-ethereum-analysis/internal/debug"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/p2p"
	"github.com/go-ethereum-analysis/rpc"
	"github.com/prometheus/prometheus/util/flock"
)

// Node is a container on which services can be registered.
//
// 这个是  代表 整个 Etheruem 实例的 node     和 discover\node.go  不是一个东西 (discover\node.go 是 p2p 的node)
type Node struct {
	eventmux *event.TypeMux // Event multiplexer used between the services of a stack
	config   *Config
	accman   *accounts.Manager

	ephemeralKeystore string         // if non-empty, the key directory that will be removed by Stop

	// 防止并发使用实例目录    flock  为 文件锁
	instanceDirLock   flock.Releaser // prevents concurrent use of instance directory

	serverConfig p2p.Config

	// todo p2p 服务
	server       *p2p.Server // Currently running P2P networking layer

	// todo 这个 转载这 各种 服务 (Service) 的 初始化函数指针
	//
	// 			ETH 服务、   dashboard 服务、  shh 服务 (whisper 相关)、  EthStats 服务 等等 几个
	//
	serviceFuncs []ServiceConstructor     // Service constructors (in dependency order)
	// todo 上面的 ServiceConstructor 被调用后 所初始化的 服务实例引用       (ETH 服务、   dashboard 服务、  shh 服务 (whisper 相关)、  EthStats 服务 等等)
	services     map[reflect.Type]Service // Currently running services

	// 节点当前提供的API列表
	rpcAPIs       []rpc.API   // List of APIs currently provided by the node

	// - - - - - - -  cmd - - - - - - -
	// 进程内RPC请求 处理程序 以处理API请求   todo 当前节点 命令行操作  jsonRpc
	inprocHandler *rpc.Server // In-process RPC request handler to process the API requests

	// - - - - - - -  IPC - - - - - - -
	// 要侦听的IPC端点 (empty = 禁用IPC)
	ipcEndpoint string       // IPC endpoint to listen at (empty = IPC disabled)
	// IPC RPC侦听器套接字，用于服务API请求
	ipcListener net.Listener // IPC RPC listener socket to serve API requests
	// IPC RPC请求 处理程序 以处理API请求
	ipcHandler  *rpc.Server  // IPC RPC request handler to process the API requests

	// - - - - - - -  HTTP - - - - - - -
	// 要侦听的HTTP端点  (接口 + 端口) (empty = 禁用IPC)
	httpEndpoint  string       // HTTP endpoint (interface + port) to listen at (empty = HTTP disabled)
	// 允许通过此端点的HTTP RPC模块   (api 的白名单, 表明 http 对外的 jsonRpc 接口)
	httpWhitelist []string     // HTTP RPC modules to allow through this endpoint
	// 服务器API请求的HTTP RPC侦听器套接字
	httpListener  net.Listener // HTTP RPC listener socket to server API requests
	// HTTP RPC请求  处理程序 以处理API请求
	httpHandler   *rpc.Server  // HTTP RPC request handler to process the API requests


	// - - - - - - -  WebSocket - - - - - - -
	// 要侦听的Websocket端点  (接口 + 端口) (empty = 禁用IPC)
	wsEndpoint string       // Websocket endpoint (interface + port) to listen at (empty = websocket disabled)
	// 服务器API请求的Websocket RPC侦听器套接字
	wsListener net.Listener // Websocket RPC listener socket to server API requests
	// Websocket RPC请求 处理程序 以处理API请求
	wsHandler  *rpc.Server  // Websocket RPC request handler to process the API requests

	stop chan struct{} // Channel to wait for termination notifications
	lock sync.RWMutex

	log log.Logger
}

// New creates a new P2P node, ready for protocol registration.
func New(conf *Config) (*Node, error) {
	// Copy config and resolve the datadir so future changes to the current
	// working directory don't affect the node.
	confCopy := *conf
	conf = &confCopy
	if conf.DataDir != "" {
		absdatadir, err := filepath.Abs(conf.DataDir)
		if err != nil {
			return nil, err
		}
		conf.DataDir = absdatadir
	}
	// Ensure that the instance name doesn't cause weird conflicts with
	// other files in the data directory.
	/**
	确保实例名称不会导致与数据目录中的其他文件发生奇怪的冲突。
	 */
	if strings.ContainsAny(conf.Name, `/\`) {
		return nil, errors.New(`Config.Name must not contain '/' or '\'`)
	}
	// datadirDefaultKeyStore : keystore
	if conf.Name == datadirDefaultKeyStore {
		return nil, errors.New(`Config.Name cannot be "` + datadirDefaultKeyStore + `"`)
	}
	if strings.HasSuffix(conf.Name, ".ipc") {
		return nil, errors.New(`Config.Name cannot end in ".ipc"`)
	}
	// Ensure that the AccountManager method works before the node has started.
	// We rely on this in cmd/geth.
	/**
	创建钱包账户
	返回 AccountManager 和 keystore的 URL
	*/
	am, ephemeralKeystore, err := makeAccountManager(conf)
	if err != nil {
		return nil, err
	}
	// config 的 logger
	if conf.Logger == nil {
		conf.Logger = log.New()
	}
	// Note: any interaction with Config that would create/touch files
	// in the data directory or instance directory is delayed until Start.
	/**
	构建一个 节点实例 Node
	 */
	return &Node{
		// AccountManager
		accman:            am,
		// keystore URL
		ephemeralKeystore: ephemeralKeystore,
		// 节点的配置
		config:            conf,
		// 这个是 收集节点上的所有 server 服务的
		serviceFuncs:      []ServiceConstructor{},
		// IPC 端点
		ipcEndpoint:       conf.IPCEndpoint(),
		// HTTP 端点
		httpEndpoint:      conf.HTTPEndpoint(),
		// WS 端点
		wsEndpoint:        conf.WSEndpoint(),
		// 这个是一个事件管理相关的
		// 后续都是用 feed
		eventmux:          new(event.TypeMux),
		// 这个log 实例和 conf 中的log 实例是同一个
		log:               conf.Logger,
	}, nil
}

// Register injects a new service into the node's stack. The service created by
// the passed constructor must be unique in its type with regard to sibling ones.
func (n *Node) Register(constructor ServiceConstructor) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.server != nil {
		return ErrNodeRunning
	}
	n.serviceFuncs = append(n.serviceFuncs, constructor)
	return nil
}

// Start create a live P2P node and starts running it.
func (n *Node) Start() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	// Short circuit if the node's already running
	if n.server != nil {
		return ErrNodeRunning
	}
	// 打开 ether node 的目录
	if err := n.openDataDir(); err != nil {
		return err
	}

	// Initialize the p2p server. This creates the node key and discovery databases.
	//
	// 初始化p2p服务端. 这将创建 node key 和 节点发现的 db
	n.serverConfig = n.config.P2P
	n.serverConfig.PrivateKey = n.config.NodeKey() 	// 设置当前 node 的私钥
	n.serverConfig.Name = n.config.NodeName()		// node 的name
	n.serverConfig.Logger = n.log
	if n.serverConfig.StaticNodes == nil {
		n.serverConfig.StaticNodes = n.config.StaticNodes()  // todo 加载配置文件的  静态节点
	}
	if n.serverConfig.TrustedNodes == nil {
		n.serverConfig.TrustedNodes = n.config.TrustedNodes()	// todo 加载配置文件的  可信任节点
	}
	if n.serverConfig.NodeDatabase == "" {
		n.serverConfig.NodeDatabase = n.config.NodeDB()			// 根据配置文件 指定  p2p node 的 db 目录
	}

	// todo 初始化 p2p Server 实例
	running := &p2p.Server{Config: n.serverConfig}
	n.log.Info("Starting peer-to-peer node", "instance", n.serverConfig.Name)

	// Otherwise copy and specialize the P2P configuration
	//
	// 用来收集 各种 服务引用
	services := make(map[reflect.Type]Service)

	// todo 逐个实例化 各个服务  (ETH 服务、   dashboard 服务、  shh 服务 (whisper 相关)、  EthStats 服务 等等)
	for _, constructor := range n.serviceFuncs {
		// Create a new context for the particular service
		ctx := &ServiceContext{
			config:         n.config,
			services:       make(map[reflect.Type]Service),
			EventMux:       n.eventmux,
			AccountManager: n.accman,
		}
		for kind, s := range services { // copy needed for threaded access
			ctx.services[kind] = s
		}
		// Construct and save the service
		service, err := constructor(ctx)     // todo 逐个实例化 各个服务  (ETH 服务、   dashboard 服务、  shh 服务 (whisper 相关)、  EthStats 服务 等等)
		if err != nil {
			return err
		}
		kind := reflect.TypeOf(service)
		if _, exists := services[kind]; exists {
			return &DuplicateServiceError{Kind: kind}
		}
		services[kind] = service
	}
	// todo ##############################
	// todo ##############################
	// todo ##############################
	// todo ##############################
	// todo ##############################
	// todo ##############################
	//
	// Gather the protocols and start the freshly assembled P2P server
	//
	// todo 收集协议并启动新组装的P2P服务器, 逐个启动
	// todo 各类节点都走这里启动 peer 实例
	//
	// todo ##############################
	// todo ##############################
	// todo ##############################
	// todo ##############################
	// todo ##############################
	// todo ##############################
	for _, service := range services {
		running.Protocols = append(running.Protocols, service.Protocols()...)
	}

	if err := running.Start(); err != nil {  // todo 这里启动 p2p 服务, 不是 peer 实例哦
		return convertFileLockError(err)
	}
	// Start each of the services
	started := []reflect.Type{}
	for kind, service := range services {
		// Start the next service, stopping all previous upon failure
		//
		// 启动下一个服务，一旦失败就停止所有先前的服务
		//
		// todo 这里 逐个 启动各个 服务 (Service) 实例,        (ETH 服务、   dashboard 服务、  shh 服务 (whisper 相关)、  EthStats 服务 等等 )
		if err := service.Start(running); err != nil {
			for _, kind := range started {
				services[kind].Stop()
			}
			running.Stop()
			return err
		}
		// Mark the service started for potential cleanup
		started = append(started, kind)  // 收集 所有已经启动了的  服务kind    (ETH 服务、   dashboard 服务、  shh 服务 (whisper 相关)、  EthStats 服务 等等 )
	}
	// Lastly start the configured RPC interfaces
	if err := n.startRPC(services); err != nil {   // todo 启动 各种 jsonrpc 服务   (inproc<进程内部rpc>、 IPC、 HTTP、 WebSocket)
		for _, service := range services {
			service.Stop()
		}
		running.Stop()
		return err
	}
	// Finish initializing the startup
	n.services = services			//	节点的各种服务  (ETH 服务、   dashboard 服务、  shh 服务 (whisper 相关)、  EthStats 服务 等等)
	n.server = running				//  p2p 服务
	n.stop = make(chan struct{})	// 节点停止 信号通道

	return nil
}

// 打开 ether node 的数据目录 (锁定目录, 放置并发修改)
func (n *Node) openDataDir() error {
	if n.config.DataDir == "" {
		return nil // ephemeral
	}

	instdir := filepath.Join(n.config.DataDir, n.config.name())
	if err := os.MkdirAll(instdir, 0700); err != nil {
		return err
	}
	// Lock the instance directory to prevent concurrent use by another instance as well as
	// accidental use of the instance directory as a database.
	//
	// 锁定实例目录 以防止被另一个实例并发使用，以及意外地将该实例目录用作数据库     flock  为 文件锁
	release, _, err := flock.New(filepath.Join(instdir, "LOCK"))
	if err != nil {
		return convertFileLockError(err)
	}
	n.instanceDirLock = release
	return nil
}

// startRPC is a helper method to start all the various RPC endpoint during node
// startup. It's not meant to be called at any time afterwards as it makes certain
// assumptions about the state of the node.
func (n *Node) startRPC(services map[reflect.Type]Service) error {  // 启动各种 jsonrpc 服务    (inproc<进程内部rpc>、 IPC、 HTTP、 WebSocket)
	// Gather all the possible APIs to surface

	// 获取 ether node 实例 内置的 api
	apis := n.apis()

	// 追加收集  各个 服务的api     (ETH 服务、   dashboard 服务、  shh 服务 (whisper 相关)、  EthStats 服务 等等 )
	for _, service := range services {
		apis = append(apis, service.APIs()...)
	}


	// Start the various API endpoints, terminating all in case of errors
	//
	// 启动各种API端点，如果发生错误则终止所有端点    todo  逐个 启动各个 jsonrpc 服务

	if err := n.startInProc(apis); err != nil {  // 启动 inproc<进程内部rpc>
		return err
	}
	if err := n.startIPC(apis); err != nil {	// 启动 IPC
		n.stopInProc()
		return err
	}
	if err := n.startHTTP(n.httpEndpoint, apis, n.config.HTTPModules, n.config.HTTPCors, n.config.HTTPVirtualHosts, n.config.HTTPTimeouts); err != nil {	// 启动 HTTP
		n.stopIPC()
		n.stopInProc()
		return err
	}
	if err := n.startWS(n.wsEndpoint, apis, n.config.WSModules, n.config.WSOrigins, n.config.WSExposeAll); err != nil {		// 启动 WebSocket
		n.stopHTTP()
		n.stopIPC()
		n.stopInProc()
		return err
	}
	// All API endpoints started successfully
	n.rpcAPIs = apis
	return nil
}

// startInProc initializes an in-process RPC endpoint.
func (n *Node) startInProc(apis []rpc.API) error {
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()  // 实例化  InProc 的 RPC Server
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil { // 将各种 API (Miner/Debug/BlockChain/Account 等等) 的 name 和 实例引用 注册到  InProc Server 实例中
			return err
		}
		n.log.Debug("InProc registered", "service", api.Service, "namespace", api.Namespace)
	}
	n.inprocHandler = handler
	return nil
}

// stopInProc terminates the in-process RPC endpoint.
func (n *Node) stopInProc() {
	if n.inprocHandler != nil {
		n.inprocHandler.Stop()
		n.inprocHandler = nil
	}
}

// startIPC initializes and starts the IPC RPC endpoint.
func (n *Node) startIPC(apis []rpc.API) error {
	if n.ipcEndpoint == "" {
		return nil // IPC disabled.
	}
	listener, handler, err := rpc.StartIPCEndpoint(n.ipcEndpoint, apis)
	if err != nil {
		return err
	}
	n.ipcListener = listener
	n.ipcHandler = handler
	n.log.Info("IPC endpoint opened", "url", n.ipcEndpoint)
	return nil
}

// stopIPC terminates the IPC RPC endpoint.
func (n *Node) stopIPC() {
	if n.ipcListener != nil {
		n.ipcListener.Close()
		n.ipcListener = nil

		n.log.Info("IPC endpoint closed", "endpoint", n.ipcEndpoint)
	}
	if n.ipcHandler != nil {
		n.ipcHandler.Stop()
		n.ipcHandler = nil
	}
}

// startHTTP initializes and starts the HTTP RPC endpoint.
func (n *Node) startHTTP(endpoint string, apis []rpc.API, modules []string, cors []string, vhosts []string, timeouts rpc.HTTPTimeouts) error {
	// Short circuit if the HTTP endpoint isn't being exposed
	if endpoint == "" {
		return nil
	}
	listener, handler, err := rpc.StartHTTPEndpoint(endpoint, apis, modules, cors, vhosts, timeouts) // 启动 http rpc Endpoint
	if err != nil {
		return err
	}
	n.log.Info("HTTP endpoint opened", "url", fmt.Sprintf("http://%s", endpoint), "cors", strings.Join(cors, ","), "vhosts", strings.Join(vhosts, ","))
	// All listeners booted successfully
	n.httpEndpoint = endpoint
	n.httpListener = listener
	n.httpHandler = handler

	return nil
}

// stopHTTP terminates the HTTP RPC endpoint.
func (n *Node) stopHTTP() {
	if n.httpListener != nil {
		n.httpListener.Close()
		n.httpListener = nil

		n.log.Info("HTTP endpoint closed", "url", fmt.Sprintf("http://%s", n.httpEndpoint))
	}
	if n.httpHandler != nil {
		n.httpHandler.Stop()
		n.httpHandler = nil
	}
}

// startWS initializes and starts the websocket RPC endpoint.
func (n *Node) startWS(endpoint string, apis []rpc.API, modules []string, wsOrigins []string, exposeAll bool) error {
	// Short circuit if the WS endpoint isn't being exposed
	if endpoint == "" {
		return nil
	}
	listener, handler, err := rpc.StartWSEndpoint(endpoint, apis, modules, wsOrigins, exposeAll)
	if err != nil {
		return err
	}
	n.log.Info("WebSocket endpoint opened", "url", fmt.Sprintf("ws://%s", listener.Addr()))
	// All listeners booted successfully
	n.wsEndpoint = endpoint
	n.wsListener = listener
	n.wsHandler = handler

	return nil
}

// stopWS terminates the websocket RPC endpoint.
func (n *Node) stopWS() {
	if n.wsListener != nil {
		n.wsListener.Close()
		n.wsListener = nil

		n.log.Info("WebSocket endpoint closed", "url", fmt.Sprintf("ws://%s", n.wsEndpoint))
	}
	if n.wsHandler != nil {
		n.wsHandler.Stop()
		n.wsHandler = nil
	}
}

// Stop terminates a running node along with all it's services. In the node was
// not started, an error is returned.
func (n *Node) Stop() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	// Short circuit if the node's not running
	if n.server == nil {
		return ErrNodeStopped
	}

	// Terminate the API, services and the p2p server.
	n.stopWS()
	n.stopHTTP()
	n.stopIPC()
	n.rpcAPIs = nil
	failure := &StopError{
		Services: make(map[reflect.Type]error),
	}
	for kind, service := range n.services {
		if err := service.Stop(); err != nil {
			failure.Services[kind] = err
		}
	}
	n.server.Stop()
	n.services = nil
	n.server = nil

	// Release instance directory lock.
	if n.instanceDirLock != nil {
		if err := n.instanceDirLock.Release(); err != nil {
			n.log.Error("Can't release datadir lock", "err", err)
		}
		n.instanceDirLock = nil
	}

	// unblock n.Wait
	close(n.stop)  // 关闭 stop  通道, 外面就能收到 nil 信号

	// Remove the keystore if it was created ephemerally.
	var keystoreErr error
	if n.ephemeralKeystore != "" {
		keystoreErr = os.RemoveAll(n.ephemeralKeystore)
	}

	if len(failure.Services) > 0 {
		return failure
	}
	if keystoreErr != nil {
		return keystoreErr
	}
	return nil
}

// Wait blocks the thread until the node is stopped. If the node is not running
// at the time of invocation, the method immediately returns.
func (n *Node) Wait() {
	n.lock.RLock()
	if n.server == nil {
		n.lock.RUnlock()
		return
	}
	stop := n.stop
	n.lock.RUnlock()

	// 其 阻塞 用
	<-stop
}

// Restart terminates a running node and boots up a new one in its place. If the
// node isn't running, an error is returned.
func (n *Node) Restart() error {
	if err := n.Stop(); err != nil {
		return err
	}
	if err := n.Start(); err != nil {
		return err
	}
	return nil
}

// Attach creates an RPC client attached to an in-process API handler.
func (n *Node) Attach() (*rpc.Client, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	if n.server == nil {
		return nil, ErrNodeStopped
	}
	return rpc.DialInProc(n.inprocHandler), nil
}

// RPCHandler returns the in-process RPC request handler.
func (n *Node) RPCHandler() (*rpc.Server, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	if n.inprocHandler == nil {
		return nil, ErrNodeStopped
	}
	return n.inprocHandler, nil
}

// Server retrieves the currently running P2P network layer. This method is meant
// only to inspect fields of the currently running server, life cycle management
// should be left to this Node entity.
func (n *Node) Server() *p2p.Server {
	n.lock.RLock()
	defer n.lock.RUnlock()

	return n.server
}

// Service retrieves a currently running service registered of a specific type.
func (n *Node) Service(service interface{}) error {
	n.lock.RLock()
	defer n.lock.RUnlock()

	// Short circuit if the node's not running
	if n.server == nil {
		return ErrNodeStopped
	}
	// Otherwise try to find the service to return
	element := reflect.ValueOf(service).Elem()
	if running, ok := n.services[element.Type()]; ok {
		element.Set(reflect.ValueOf(running))
		return nil
	}
	return ErrServiceUnknown
}

// DataDir retrieves the current datadir used by the protocol stack.
// Deprecated: No files should be stored in this directory, use InstanceDir instead.
func (n *Node) DataDir() string {
	return n.config.DataDir
}

// InstanceDir retrieves the instance directory used by the protocol stack.
func (n *Node) InstanceDir() string {
	return n.config.instanceDir()
}

// AccountManager retrieves the account manager used by the protocol stack.
func (n *Node) AccountManager() *accounts.Manager {
	return n.accman
}

// IPCEndpoint retrieves the current IPC endpoint used by the protocol stack.
func (n *Node) IPCEndpoint() string {
	return n.ipcEndpoint
}

// HTTPEndpoint retrieves the current HTTP endpoint used by the protocol stack.
func (n *Node) HTTPEndpoint() string {
	return n.httpEndpoint
}

// WSEndpoint retrieves the current WS endpoint used by the protocol stack.
func (n *Node) WSEndpoint() string {
	return n.wsEndpoint
}

// EventMux retrieves the event multiplexer used by all the network services in
// the current protocol stack.
func (n *Node) EventMux() *event.TypeMux {
	return n.eventmux
}

// OpenDatabase opens an existing database with the given name (or creates one if no
// previous can be found) from within the node's instance directory. If the node is
// ephemeral, a memory database is returned.
func (n *Node) OpenDatabase(name string, cache, handles int) (ethdb.Database, error) {
	if n.config.DataDir == "" {
		return ethdb.NewMemDatabase(), nil
	}
	return ethdb.NewLDBDatabase(n.config.ResolvePath(name), cache, handles)
}

// ResolvePath returns the absolute path of a resource in the instance directory.
func (n *Node) ResolvePath(x string) string {
	return n.config.ResolvePath(x)
}

// apis returns the collection of RPC descriptors this node offers.
func (n *Node) apis() []rpc.API {
	return []rpc.API{
		{
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(n),
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPublicAdminAPI(n),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   debug.Handler,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(n),
			Public:    true,
		}, {
			Namespace: "web3",
			Version:   "1.0",
			Service:   NewPublicWeb3API(n),
			Public:    true,
		},
	}
}
