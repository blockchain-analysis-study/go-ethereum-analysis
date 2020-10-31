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

// Package p2p implements the Ethereum p2p network protocols.
package p2p

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/common/mclock"
	"github.com/go-ethereum-analysis/event"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/p2p/discover"
	"github.com/go-ethereum-analysis/p2p/discv5"
	"github.com/go-ethereum-analysis/p2p/nat"
	"github.com/go-ethereum-analysis/p2p/netutil"
)

const (
	defaultDialTimeout = 15 * time.Second

	// Connectivity defaults.
	maxActiveDialTasks     = 16
	defaultMaxPendingPeers = 50
	defaultDialRatio       = 3

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	frameWriteTimeout = 20 * time.Second
)

var errServerStopped = errors.New("server stopped")

// Config holds Server options.
type Config struct {
	// This field must be set to a valid secp256k1 private key.
	PrivateKey *ecdsa.PrivateKey `toml:"-"`   // 当前本地node的私钥

	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	MaxPeers int  // 表示当前 peer 可以被多少个 peer 连接

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	MaxPendingPeers int `toml:",omitempty"`

	// DialRatio controls the ratio of inbound to dialed connections.
	// Example: a DialRatio of 2 allows 1/2 of connections to be dialed.
	// Setting DialRatio to zero defaults it to 3.
	//
	//
	// DialRatio控制 入站与已拨连接 的比率
	//			示例：DialRatio为2允许拨打1/2个连接
	//			将DialRatio设置为零会将其默认设置为3
	DialRatio int `toml:",omitempty"`

	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	//
	// NoDiscovery 可用于禁用 peer 发现机制
	// 禁用对于协议调试（手动拓扑）很有用
	NoDiscovery bool

	// DiscoveryV5 specifies whether the the new topic-discovery based V5 discovery
	// protocol should be started or not.
	//
	// DiscoveryV5 指定是否应该启动 新的基于 主题发现(topic-discovery) 的 V5发现协议
	DiscoveryV5 bool `toml:",omitempty"`

	// Name sets the node name of this server.
	// Use common.MakeName to create a name that follows existing conventions.
	Name string `toml:"-"`

	// BootstrapNodes are used to establish connectivity
	// with the rest of the network.  BootstrapNodes用于建立与网络其余部分的连接
	//
	// 种子节点
	BootstrapNodes []*discover.Node

	// BootstrapNodesV5 are used to establish connectivity
	// with the rest of the network using the V5 discovery
	// protocol.    BootstrapNodesV5 用于使用 V5发现协议 建立与网络其余部分的连接
	//
	// 使用 V5发现协议 的种子节点
	BootstrapNodesV5 []*discv5.Node `toml:",omitempty"`

	// Static nodes are used as pre-configured connections which are always
	// maintained and re-connected on disconnects.
	StaticNodes []*discover.Node		// todo  配置文件 的 静态节点

	// Trusted nodes are used as pre-configured connections which are always
	// allowed to connect, even above the peer limit.
	TrustedNodes []*discover.Node

	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	//
	//
	// 连接可以限制为某些IP网络
	// 如果将此选项设置为非nil值，则仅考虑与列表中包含的IP网络之一匹配的主机
	//
	//  一个 IP 白名单
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	NodeDatabase string `toml:",omitempty"`

	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	Protocols []Protocol `toml:"-"`

	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	ListenAddr string   // 例如L: "127.0.0.1:8080"  或者 "www.baidu.com"

	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	NAT nat.Interface `toml:",omitempty"`   // todo 这里的 nat 有两种实现: UPnP 和 NAT-PMP   (默认是 any; any 是同时兼容了 UPnP 和 NAT-PMP 两种实现)

	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	//
	// 如果Dialer设置为非nil值，则给定的Dialer用于 拨打出站  peer 连接    TCPDialer
	Dialer NodeDialer `toml:"-"`

	// If NoDial is true, the server will not dial any peers.
	//
	// 如果NoDial为true，则服务器将 不拨打任何 peer  (不连接 任何 peer)
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	EnableMsgEvents bool

	// Logger is a custom logger to use with the p2p.Server.
	Logger log.Logger `toml:",omitempty"`
}

// Server manages all peer connections.
//
//  Server 是 当前 node 的 p2p 服务,  管理着多有  peer 连接相关
type Server struct {
	// Config fields may not be modified while the server is running.
	Config

	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.
	//
	//用于测试的钩子函数.  这些很有用，因为我们可以禁止整个协议栈
	newTransport func(net.Conn) transport
	newPeerHook  func(*Peer)

	lock    sync.Mutex // protects running

	// p2p 服务是否已启动 标识
	running bool

	ntab         discoverTable
	listener     net.Listener
	ourHandshake *protoHandshake   // protoHandshake是协议握手的RLP结构
	lastLookup   time.Time
	DiscV5       *discv5.Network   // 对 V5发现协议的一些封装

	// These are for Peers, PeerCount (and nothing else).  这些是用于Peers，PeerCount（仅此而已）的
	peerOp     chan peerOpFunc
	peerOpDone chan struct{}

	quit          chan struct{}
	addstatic     chan *discover.Node
	removestatic  chan *discover.Node
	addtrusted    chan *discover.Node
	removetrusted chan *discover.Node
	posthandshake chan *conn		// 接收 rlpx 传输握手信号
	addpeer       chan *conn		// 有 新对端 peer 连进来时的信号
	delpeer       chan peerDrop		// 需要移除 某对端 peer 连接的信号
	loopWG        sync.WaitGroup // loop, listenLoop
	peerFeed      event.Feed    // peer 的事件监听. (用在 jsonrpc api 中查看 节点连接信息)
	log           log.Logger
}

type peerOpFunc func(map[discover.NodeID]*Peer)

type peerDrop struct {
	*Peer
	err       error
	requested bool // true if signaled by the peer
}

type connFlag int32

const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
	trustedConn
)

// conn wraps a network connection with information gathered
// during the two handshakes.
type conn struct {
	fd net.Conn
	transport
	flags connFlag
	cont  chan error      // The run loop uses cont to signal errors to SetupConn.
	id    discover.NodeID // valid after the encryption handshake
	caps  []Cap           // valid after the protocol handshake
	name  string          // valid after the protocol handshake
}

type transport interface {
	// The two handshakes.
	doEncHandshake(prv *ecdsa.PrivateKey, dialDest *discover.Node) (discover.NodeID, error)
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.
	MsgReadWriter
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because NsgPipe doesn't use it.
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.id != discover.NodeID{}) {
		s += " " + c.id.String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}

func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

func (c *conn) is(f connFlag) bool {
	flags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
	return flags&f != 0
}

func (c *conn) set(f connFlag, val bool) {
	for {
		oldFlags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
		flags := oldFlags
		if val {
			flags |= f
		} else {
			flags &= ^f
		}
		if atomic.CompareAndSwapInt32((*int32)(&c.flags), int32(oldFlags), int32(flags)) {
			return
		}
	}
}

// Peers returns all connected peers.
func (srv *Server) Peers() []*Peer {
	var ps []*Peer
	select {
	// Note: We'd love to put this function into a variable but
	// that seems to cause a weird compiler error in some
	// environments.
	case srv.peerOp <- func(peers map[discover.NodeID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	}:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return ps
}

// PeerCount returns the number of connected peers.
func (srv *Server) PeerCount() int {
	var count int
	select {
	case srv.peerOp <- func(ps map[discover.NodeID]*Peer) { count = len(ps) }:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return count
}

// AddPeer connects to the given node and maintains the connection until the
// server is shut down. If the connection fails for any reason, the server will
// attempt to reconnect the peer.
func (srv *Server) AddPeer(node *discover.Node) {
	select {
	case srv.addstatic <- node:
	case <-srv.quit:
	}
}

// RemovePeer disconnects from the given node
func (srv *Server) RemovePeer(node *discover.Node) {
	select {
	case srv.removestatic <- node:
	case <-srv.quit:
	}
}

// AddTrustedPeer adds the given node to a reserved whitelist which allows the
// node to always connect, even if the slot are full.
func (srv *Server) AddTrustedPeer(node *discover.Node) {
	select {
	case srv.addtrusted <- node:
	case <-srv.quit:
	}
}

// RemoveTrustedPeer removes the given node from the trusted peer set.
func (srv *Server) RemoveTrustedPeer(node *discover.Node) {
	select {
	case srv.removetrusted <- node:
	case <-srv.quit:
	}
}

// SubscribePeers subscribes the given channel to peer events
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}

// Self returns the local node's endpoint information.
func (srv *Server) Self() *discover.Node {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	if !srv.running {
		return &discover.Node{IP: net.ParseIP("0.0.0.0")}
	}
	return srv.makeSelf(srv.listener, srv.ntab)
}

func (srv *Server) makeSelf(listener net.Listener, ntab discoverTable) *discover.Node {
	// If the server's not running, return an empty node.
	// If the node is running but discovery is off, manually assemble the node infos.
	if ntab == nil {
		// Inbound connections disabled, use zero address.
		if listener == nil {
			return &discover.Node{IP: net.ParseIP("0.0.0.0"), ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
		}
		// Otherwise inject the listener address too
		addr := listener.Addr().(*net.TCPAddr)
		return &discover.Node{
			ID:  discover.PubkeyID(&srv.PrivateKey.PublicKey),
			IP:  addr.IP,
			TCP: uint16(addr.Port),
		}
	}
	// Otherwise return the discovery node.
	return ntab.Self()
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
func (srv *Server) Stop() {
	srv.lock.Lock()
	if !srv.running {
		srv.lock.Unlock()
		return
	}
	srv.running = false    // 将 p2p 服务的已 停止标识 设置为 false
	if srv.listener != nil {
		// this unblocks listener Accept
		srv.listener.Close()
	}
	close(srv.quit)
	srv.lock.Unlock()
	srv.loopWG.Wait()
}

// sharedUDPConn implements a shared connection. Write sends messages to the underlying connection while read returns
// messages that were found unprocessable and sent to the unhandled channel by the primary listener.
type sharedUDPConn struct {
	*net.UDPConn
	unhandled chan discover.ReadPacket
}

// ReadFromUDP implements discv5.conn
func (s *sharedUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	packet, ok := <-s.unhandled
	if !ok {
		return 0, nil, fmt.Errorf("Connection was closed")
	}
	l := len(packet.Data)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], packet.Data[:l])
	return l, packet.Addr, nil
}

// Close implements discv5.conn
func (s *sharedUDPConn) Close() error {
	return nil
}

// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true		// 将 p2p 服务的已启动标识 设置为 true   (一进来就 该状态,  函数结束时 再改一次???)
	srv.log = srv.Config.Logger
	if srv.log == nil {
		srv.log = log.New()
	}
	srv.log.Info("Starting P2P networking")

	// static fields
	if srv.PrivateKey == nil {
		return fmt.Errorf("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.newTransport == nil {   // 仅用于 测试的 rlpx 传输协议
		srv.newTransport = newRLPX
	}
	if srv.Dialer == nil {
		srv.Dialer = TCPDialer{&net.Dialer{Timeout: defaultDialTimeout}}   // 15s 超时
	}

	// 初始化 一些列 chan
	srv.quit = make(chan struct{})
	srv.addpeer = make(chan *conn)
	srv.delpeer = make(chan peerDrop)
	srv.posthandshake = make(chan *conn)
	srv.addstatic = make(chan *discover.Node)
	srv.removestatic = make(chan *discover.Node)
	srv.addtrusted = make(chan *discover.Node)
	srv.removetrusted = make(chan *discover.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})

	var (
		conn      *net.UDPConn
		sconn     *sharedUDPConn
		realaddr  *net.UDPAddr
		unhandled chan discover.ReadPacket
	)

	if !srv.NoDiscovery || srv.DiscoveryV5 {   // 如果启用了 peer 的 发现机制  或者  启用了V5发现协议

		addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)    // 获取udpaddr     (返回一个UDPAddr的指针类型)
		if err != nil {
			return err
		}
		conn, err = net.ListenUDP("udp", addr)		// 启动 UDP 服务端   (客户端需要用 net.DialUDP() 来连接)
		if err != nil {
			return err
		}
		realaddr = conn.LocalAddr().(*net.UDPAddr)		// 获取 本地网络的 UDP地址

		if srv.NAT != nil {  // todo 这里的 nat 有两种实现: UPnP 和 NAT-PMP   (可根据配置文件定; 默认是 any; any 是同时兼容了 UPnP 和 NAT-PMP 两种实现)
			// 127.0.0.1是回送地址，指本地机，一般用来测试使用.
			// 			回送地址（127.x.x.x）是本机回送地址, 即 主机IP堆栈内部的IP地址，
			// 			主要用于  网络软件测试  以及  本地机进程间通信，
			// 			无论什么程序，一旦使用回送地址发送数据，协议软件立即返回，不进行任何网络传输.
			if !realaddr.IP.IsLoopback() { // IsLoopback 报告ip 是否为  回送地址
				go nat.Map(srv.NAT, srv.quit, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")  // 将 内外网端口映射 追加到 NAT 映射表中
			}
			// TODO: react to external IP changes over time.
			//
			// ExternalIP 是在本机IP就是公网IP的情况下使用,  也就是无需端口映射的时候使用.
			// 				upnp 和 pmp 是对两种端口映射协议的使用封装
			if ext, err := srv.NAT.ExternalIP(); err == nil {   // todo 获取 NAT 用于对外的 公网 IP
				realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}   // 组装 用于对外的 NAT公网 IP:Port
			}
		}
	}

	if !srv.NoDiscovery && srv.DiscoveryV5 {  // 如果 启用了 peer 的 发现机制 且  启用了V5发现协议
		unhandled = make(chan discover.ReadPacket, 100)
		sconn = &sharedUDPConn{conn, unhandled}	// 封装 UDP 连接实例
	}

	// node table
	if !srv.NoDiscovery {  // 如果 启用了 peer 的 发现机制
		cfg := discover.Config{
			PrivateKey:   srv.PrivateKey,
			AnnounceAddr: realaddr,
			NodeDBPath:   srv.NodeDatabase,
			NetRestrict:  srv.NetRestrict,
			Bootnodes:    srv.BootstrapNodes,		// 配置文件的 种子节点  (非 V5发现协议的)
			Unhandled:    unhandled,
		}
		ntab, err := discover.ListenUDP(conn, cfg)  // 根据 配置文件返回一个新 table，该table 在laddr上侦听UDP数据包
		if err != nil {
			return err
		}
		srv.ntab = ntab
	}

	if srv.DiscoveryV5 {  // 如果 启用了 peer 的 V5发现机制
		var (
			ntab *discv5.Network
			err  error
		)
		if sconn != nil {
			ntab, err = discv5.ListenUDP(srv.PrivateKey, sconn, realaddr, "", srv.NetRestrict) //srv.NodeDatabase)
		} else { // 区别: 这个用的是 conn 上面用的是 sconn
			ntab, err = discv5.ListenUDP(srv.PrivateKey, conn, realaddr, "", srv.NetRestrict) //srv.NodeDatabase)
		}
		if err != nil {
			return err
		}
		if err := ntab.SetFallbackNodes(srv.BootstrapNodesV5); err != nil {   //  todo 设置 配置文件中的 种子节点   (关于 V5发现协议 的种子节点)
			return err
		}
		srv.DiscV5 = ntab
	}

	dynPeers := srv.maxDialedConns()  // 计算 允许的最大连接数
	dialer := newDialState(srv.StaticNodes, srv.BootstrapNodes, srv.ntab, dynPeers, srv.NetRestrict)  // 实例化 连接状态结构 (拨号状态结构)

	// handshake
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}
	// listen/dial
	if srv.ListenAddr != "" {
		if err := srv.startListening(); err != nil {  // 启动 TCP 服务监听
			return err
		}
	}
	if srv.NoDial && srv.ListenAddr == "" {
		srv.log.Warn("P2P server will be useless, neither dialing nor listening")
	}

	srv.loopWG.Add(1)

	go srv.run(dialer)  // todo 把p2p的服务run起来

	srv.running = true  // 将 p2p 服务的已启动标识 设置为 true   (一进来就 该状态,  函数结束时 再改一次???)
	return nil
}

func (srv *Server) startListening() error {   // 启动 TCP 服务 (服务器使用 Listen, 客户端使用 Dial )
	// Launch the TCP listener.
	listener, err := net.Listen("tcp", srv.ListenAddr)   // 启动 TCP 服务监听
	if err != nil {
		return err
	}
	laddr := listener.Addr().(*net.TCPAddr)
	srv.ListenAddr = laddr.String()  // 将 Addr 修改为  TCP 监听的 Addr   (可能会和之前 检点发现的 UDP 不一样哦)
	srv.listener = listener
	srv.loopWG.Add(1)

	go srv.listenLoop()   // 一直 for 处理这 客户端发来的 TCP 包 (对端 peer 发来的 TCP 包)  todo 里面会逐个处理 所有 对端peer连进来的 连接 conn

	// Map the TCP listening port if NAT is configured.
	if !laddr.IP.IsLoopback() && srv.NAT != nil {  // 如果当亲 IP 不是 送回地址 , 将 端口映射 加入 NAT 端口映射表中
		srv.loopWG.Add(1)
		go func() {
			nat.Map(srv.NAT, srv.quit, "tcp", laddr.Port, laddr.Port, "ethereum p2p")
			srv.loopWG.Done()
		}()
	}
	return nil
}

type dialer interface {
	newTasks(running int, peers map[discover.NodeID]*Peer, now time.Time) []task
	taskDone(task, time.Time)
	addStatic(*discover.Node)
	removeStatic(*discover.Node)
}
// todo 把p2p的服务run起来
func (srv *Server) run(dialstate dialer) {
	defer srv.loopWG.Done()
	var (

		// 记录 所有  连接中的  peer信息  ( nodeId => peer)
		peers        = make(map[discover.NodeID]*Peer)

		// 记录 被连接进来的  peer 数
		inboundCount = 0

		// 用来 标识 哪些 nodeId 是 信任节点
		trusted      = make(map[discover.NodeID]bool, len(srv.TrustedNodes))

		// 已完成的任务 信号通道
		taskdone     = make(chan task, maxActiveDialTasks)  // 16 个缓冲区

		// 记录 正在运行中 的任务
		runningTasks []task

		// 记录 还没有运行的 任务
		queuedTasks  []task // tasks that can't run yet
	)
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup or added via AddTrustedPeer RPC.
	//
	// 将 `受信任的peer` 放入 map 中以加快检查速度
	// `受信任的peer` 在启动时加载，或 通过AddTrustedPeer RPC添加
	for _, n := range srv.TrustedNodes {
		trusted[n.ID] = true
	}

	// removes t from runningTasks      从 正在运行中 的任务队列中 移除任务
	delTask := func(t task) {
		for i := range runningTasks {
			if runningTasks[i] == t {
				runningTasks = append(runningTasks[:i], runningTasks[i+1:]...)
				break
			}
		}
	}

	// starts until max number of active tasks is satisfied    逐个执行 任务, 任务完成时下发 任务完成信号
	startTasks := func(ts []task) (rest []task) {
		i := 0
		for ; len(runningTasks) < maxActiveDialTasks && i < len(ts); i++ {
			t := ts[i]
			srv.log.Trace("New dial task", "task", t)

			// todo 启动任务
			//
			//	todo 这里的任务有两种
			//
			//		discoverTask:  	节点发现任务 (最终只是做单纯的 k-bucket 刷桶)  (查看了源码 发现基本上只有 dialstate.newTasks() 会 new  空的 discoverTask)
			//
			//		dialTask: 		以 当前 peer 作为 客户端, 向 对端 peer 发起 拨号连接  (最终 也会做 k-bucket 刷桶)
			//
			//		(次要的任务: waitExpireTask) 处理 历史连接的 peer 的 等待超时处理
			//
			//		todo 所以 这里的  task 基本上只有  dialTask 是有实际用处的 ...
			//
			go func() { t.Do(srv); taskdone <- t }()
			runningTasks = append(runningTasks, t)
		}
		return ts[i:]
	}

	// todo 调度任务
	scheduleTasks := func() {
		// Start from queue first.    开始执行所有任务
		queuedTasks = append(queuedTasks[:0], startTasks(queuedTasks)...)
		// Query dialer for new tasks and start as many as possible now.
		// 查询拨号程序以查找新任务并立即启动尽可能多的任务
		if len(runningTasks) < maxActiveDialTasks {

			// 这里 添加的基本是  dialTask (基本是 向 【staticNode】  和 【bootstrapNode】 和 【当前节点发现查找到的node】 和 【配置文件中指定需要去连接的node】  发起  拨号连接的任务)
			// 					和 waitExpireTask
			nt := dialstate.newTasks(len(runningTasks)+len(queuedTasks), peers, time.Now())
			queuedTasks = append(queuedTasks, startTasks(nt)...)
		}
	}

running:
	for {

		// 每次 for 都先发起一波 任务执行的 调度
		scheduleTasks()

		select {

		// 收到 退出 p2p 信号
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running

		// 收到 添加 静态 peer 连接
		case n := <-srv.addstatic:
			// This channel is used by AddPeer to add to the
			// ephemeral static peer list. Add it to the dialer,
			// it will keep the node connected.
			srv.log.Trace("Adding static node", "node", n)
			dialstate.addStatic(n)

		// 收到 移除 静态 peer 连接
		case n := <-srv.removestatic:
			// This channel is used by RemovePeer to send a
			// disconnect request to a peer and begin the
			// stop keeping the node connected.
			srv.log.Trace("Removing static node", "node", n)
			dialstate.removeStatic(n)
			if p, ok := peers[n.ID]; ok {
				p.Disconnect(DiscRequested)
			}

		// 收到 添加 可信任 peer 连接
		case n := <-srv.addtrusted:
			// This channel is used by AddTrustedPeer to add an enode
			// to the trusted node set.
			srv.log.Trace("Adding trusted node", "node", n)
			trusted[n.ID] = true
			// Mark any already-connected peer as trusted
			if p, ok := peers[n.ID]; ok {
				p.rw.set(trustedConn, true)
			}

		// 收到 移除 可信任 peer 连接
		case n := <-srv.removetrusted:
			// This channel is used by RemoveTrustedPeer to remove an enode
			// from the trusted node set.
			srv.log.Trace("Removing trusted node", "node", n)
			if _, ok := trusted[n.ID]; ok {
				delete(trusted, n.ID)
			}
			// Unmark any already-connected peer as trusted
			if p, ok := peers[n.ID]; ok {
				p.rw.set(trustedConn, false)
			}

		// 这些是用于Peers，PeerCount（仅此而已）的
		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			op(peers)
			srv.peerOpDone <- struct{}{}

		// 接收  某个任务 已完成 信号
		case t := <-taskdone:
			// A task got done. Tell dialstate about it so it
			// can update its state and remove it from the active
			// tasks list.
			srv.log.Trace("Dial task done", "task", t)
			dialstate.taskDone(t, time.Now())
			delTask(t)

		// 	接收到 有 rlpx 握手信号    todo  rlpx 协议传输 是 可信任 peer 间用的 ??
		case c := <-srv.posthandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			if trusted[c.id] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				c.flags |= trustedConn
			}
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			select {
			case c.cont <- srv.encHandshakeChecks(peers, inboundCount, c):
			case <-srv.quit:
				break running
			}

		// 如果有 新的对端 peer 连接进来
		case c := <-srv.addpeer:
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			err := srv.protoHandshakeChecks(peers, inboundCount, c)
			if err == nil {
				// The handshakes are done and it passed all checks.
				p := newPeer(c, srv.Protocols)
				// If message events are enabled, pass the peerFeed
				// to the peer
				if srv.EnableMsgEvents {
					p.events = &srv.peerFeed
				}
				name := truncateName(c.name)
				srv.log.Debug("Adding p2p peer", "name", name, "addr", c.fd.RemoteAddr(), "peers", len(peers)+1)
				go srv.runPeer(p)  // todo 处理 当前 peer 和 某个对端 peer 的消息来往
				peers[c.id] = p    // 往全局容器记录 peer 信息
				if p.Inbound() {
					inboundCount++  // 记录 被连接进来的 peer 的数量
				}
			}
			// The dialer logic relies on the assumption that
			// dial tasks complete after the peer has been added or
			// discarded. Unblock the task last.
			select {
			case c.cont <- err:
			case <-srv.quit:
				break running
			}

		// 如果有 需要将对端 peer 连接 断掉信号
		case pd := <-srv.delpeer:
			// A peer disconnected.
			d := common.PrettyDuration(mclock.Now() - pd.created)
			pd.log.Debug("Removing p2p peer", "duration", d, "peers", len(peers)-1, "req", pd.requested, "err", pd.err)
			delete(peers, pd.ID())  // 从 peers 集合中移除  peer
			if pd.Inbound() {
				inboundCount--
			}
		}
	}

	srv.log.Trace("P2P networking is spinning down")

	// todo 网络关闭了 (可能是节点退出了, 需要清空所有 项)

	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	if srv.DiscV5 != nil {
		srv.DiscV5.Close()
	}
	// Disconnect all peers.
	for _, p := range peers {
		p.Disconnect(DiscQuitting)  // todo 逐个断开 和远端 peer 的连接
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)", "remainingTasks", len(runningTasks))
		delete(peers, p.ID())
	}
}

func (srv *Server) protoHandshakeChecks(peers map[discover.NodeID]*Peer, inboundCount int, c *conn) error {
	// Drop connections with no matching protocols.
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	// Repeat the encryption handshake checks because the
	// peer set might have changed between the handshakes.
	return srv.encHandshakeChecks(peers, inboundCount, c)
}

func (srv *Server) encHandshakeChecks(peers map[discover.NodeID]*Peer, inboundCount int, c *conn) error {
	switch {
	case !c.is(trustedConn|staticDialedConn) && len(peers) >= srv.MaxPeers:
		return DiscTooManyPeers
	case !c.is(trustedConn) && c.is(inboundConn) && inboundCount >= srv.maxInboundConns():
		return DiscTooManyPeers
	case peers[c.id] != nil:
		return DiscAlreadyConnected
	case c.id == srv.Self().ID:
		return DiscSelf
	default:
		return nil
	}
}

func (srv *Server) maxInboundConns() int {
	return srv.MaxPeers - srv.maxDialedConns()
}

func (srv *Server) maxDialedConns() int {  // 计算 允许的最大连接数
	if srv.NoDiscovery || srv.NoDial {  // 如果 禁用 发现机制 或者 禁用连接任何peer
		return 0
	}
	r := srv.DialRatio   // 入站与已拨连接 的比率
	if r == 0 {
		r = defaultDialRatio  // 如果 比率为0, 则默认改为 3
	}
	return srv.MaxPeers / r   // 最允许被节点连接数/ 比率  == 允许的最大连接数
}

type tempError interface {
	Temporary() bool
}

// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {   // todo 启动当前 peer 的 TCP 服务监听, 并逐个处理 连接进来的对端peer的连接 conn
	defer srv.loopWG.Done()
	srv.log.Info("RLPx listener up", "self", srv.makeSelf(srv.listener, srv.ntab))

	tokens := defaultMaxPendingPeers
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	// 外面 这个 for 是 处理 当前 peer  和 多个 对端 peer 的 conn 的
	for {
		// Wait for a handshake slot before accepting.      等待握手槽，然后接受   (用来限制 外面的for, 逐个处理 对端 peer 和当前 peer 的连接逻辑)
		<-slots

		var (
			fd  net.Conn   // 当前 peer  和  某个对端 peer 的连接实例 conn
			err error
		)

		// 里面 这个 for 是 处理 当前 peer  和  某个对端 peer 的连接消息 (内带当前 conn 实例)
		for {
			fd, err = srv.listener.Accept()  // 接收  客户端发来的 消息 <内带当前 conn 实例>  (对于当前 peer 来说,  对端 peer 就是 客户端)
			if tempErr, ok := err.(tempError); ok && tempErr.Temporary() {
				srv.log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				return
			}
			break
		}

		// Reject connections that do not match NetRestrict.
		if srv.NetRestrict != nil {
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok && !srv.NetRestrict.Contains(tcp.IP) {  // todo 对端 IP 不在 白名单内 则关闭连接
				srv.log.Debug("Rejected conn (not whitelisted in NetRestrict)", "addr", fd.RemoteAddr())
				fd.Close()
				slots <- struct{}{}
				continue
			}
		}

		fd = newMeteredConn(fd, true)
		srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())
		go func() {
			srv.SetupConn(fd, inboundConn, nil)  // 启用 一个连接 conn
			slots <- struct{}{}   // todo 处理完 这个对端peer 和当前peer的连接后,  将 连接槽 放行, 让外面的 for 处理 下一个 对端peer和当前peer的连接
		}()
	}
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *discover.Node) error {  // 启用 一个连接 conn
	self := srv.Self()
	if self == nil {
		return errors.New("shutdown")
	}
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}
	err := srv.setupConn(c, flags, dialDest)  // 启用 一个连接 conn
	if err != nil {
		c.close(err)
		srv.log.Trace("Setting up connection failed", "id", c.id, "err", err)
	}
	return err
}
// 启用 一个连接 conn
func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *discover.Node) error {
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}
	// Run the encryption handshake.
	var err error
	if c.id, err = c.doEncHandshake(srv.PrivateKey, dialDest); err != nil {  // todo  处理加密传输  (rlpx 协议)
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	clog := srv.log.New("id", c.id, "addr", c.fd.RemoteAddr(), "conn", c.flags)
	// For dialed connections, check that the remote public key matches.
	if dialDest != nil && c.id != dialDest.ID {
		clog.Trace("Dialed identity mismatch", "want", c, dialDest.ID)
		return DiscUnexpectedIdentity
	}
	err = srv.checkpoint(c, srv.posthandshake)  // 处理 握手
	if err != nil {
		clog.Trace("Rejected peer before protocol handshake", "err", err)
		return err
	}
	// Run the protocol handshake
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed proto handshake", "err", err)
		return err
	}
	if phs.ID != c.id {
		clog.Trace("Wrong devp2p handshake identity", "err", phs.ID)
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	err = srv.checkpoint(c, srv.addpeer)  // 将 连接实例  conn 发送到 chan 中
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}
	// If the checks completed successfully, runPeer has now been
	// launched by run.
	clog.Trace("connection set up", "inbound", dialDest == nil)
	return nil
}

func truncateName(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
func (srv *Server) checkpoint(c *conn, stage chan<- *conn) error {
	select {
	case stage <- c:  // 将连接 conn 实例发送到 chan 中
	case <-srv.quit:
		return errServerStopped
	}
	select {
	case err := <-c.cont:
		return err
	case <-srv.quit:
		return errServerStopped
	}
}

// runPeer runs in its own goroutine for each peer.
// it waits until the Peer logic returns and removes
// the peer.
func (srv *Server) runPeer(p *Peer) {  // 处理 当前 peer 和 某个对端 peer 的消息来往
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}

	// broadcast peer add     发送 新增 peer 事件 (用在 jsonrpc api 中查看 节点连接信息)
	srv.peerFeed.Send(&PeerEvent{
		Type: PeerEventTypeAdd,
		Peer: p.ID(),
	})

	// run the protocol
	remoteRequested, err := p.run()  // 这个才是 最终 最底层的 p2p run()   todo <处理 当前 peer 和 某个对端 peer 的消息来往>    只要好友消息来往, 这个方法就会阻塞

	// broadcast peer drop   发送 删除 peer 事件 (用在 jsonrpc api 中查看 节点连接信息)
	srv.peerFeed.Send(&PeerEvent{
		Type:  PeerEventTypeDrop,
		Peer:  p.ID(),
		Error: err.Error(),
	})

	// Note: run waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	srv.delpeer <- peerDrop{p, err, remoteRequested}   // 发送 移除 当前 peer 和 对端某个 peer 连接信号
}

// NodeInfo represents a short summary of the information known about the host.
type NodeInfo struct {
	ID    string `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Enode string `json:"enode"` // Enode URL for adding this peer from remote peers
	IP    string `json:"ip"`    // IP address of the node
	Ports struct {
		Discovery int `json:"discovery"` // UDP listening port for discovery protocol
		Listener  int `json:"listener"`  // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"`
}

// NodeInfo gathers and returns a collection of metadata known about the host.
func (srv *Server) NodeInfo() *NodeInfo {
	node := srv.Self()

	// Gather and assemble the generic node infos
	info := &NodeInfo{
		Name:       srv.Name,
		Enode:      node.String(),
		ID:         node.ID.String(),
		IP:         node.IP.String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]interface{}),
	}
	info.Ports.Discovery = int(node.UDP)
	info.Ports.Listener = int(node.TCP)

	// Gather all the running protocol infos (only once per protocol type)
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := interface{}("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}
	return info
}

// PeersInfo returns an array of metadata objects describing connected peers.
func (srv *Server) PeersInfo() []*PeerInfo {
	// Gather all the generic and sub-protocol specific infos
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			infos = append(infos, peer.Info())
		}
	}
	// Sort the result array alphabetically by node identifier
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].ID > infos[j].ID {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	return infos
}
