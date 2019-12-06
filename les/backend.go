// Copyright 2016 The github.com/go-ethereum-analysis Authors
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

// Package les implements the Light Ethereum Subprotocol.
package les

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/accounts"
	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/common/hexutil"
	"github.com/go-ethereum-analysis/consensus"
	"github.com/go-ethereum-analysis/core"
	"github.com/go-ethereum-analysis/core/bloombits"
	"github.com/go-ethereum-analysis/core/rawdb"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/eth"
	"github.com/go-ethereum-analysis/eth/downloader"
	"github.com/go-ethereum-analysis/eth/filters"
	"github.com/go-ethereum-analysis/eth/gasprice"
	"github.com/go-ethereum-analysis/event"
	"github.com/go-ethereum-analysis/internal/ethapi"
	"github.com/go-ethereum-analysis/light"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/node"
	"github.com/go-ethereum-analysis/p2p"
	"github.com/go-ethereum-analysis/p2p/discv5"
	"github.com/go-ethereum-analysis/params"
	rpc "github.com/go-ethereum-analysis/rpc"
)

type LightEthereum struct {
	lesCommons

	// 处理ODR检索类型的后端服务
	odr         *LesOdr
	// 交易中继器
	relay       *LesTxRelay
	chainConfig *params.ChainConfig
	// Channel for shutting down the service
	// 用于接收退出信号
	shutdownChan chan bool

	// Handlers
	peers      *peerSet
	// txpool 指针
	txPool     *light.TxPool
	// lightchain指针
	blockchain *light.LightChain

	// todo 这个东西,只有当前节点为 light 节点测 client端的时候才会有值
	// todo 里头记录的是和当前 client链接的 server 端
	serverPool *serverPool
	reqDist    *requestDistributor
	// 猎犬 (reqDist的更上一层)
	retriever  *retrieveManager

	// Channel receiving bloom data retrieval requests
	// chan接收Bloom数据检索请求
	bloomRequests chan chan *bloombits.Retrieval
	// 链 bloom索引器服务
	bloomIndexer  *core.ChainIndexer

	// api的封装
	ApiBackend *LesApiBackend

	eventMux       *event.TypeMux
	// 共识引擎
	engine         consensus.Engine

	// 账号管理器
	accountManager *accounts.Manager

	networkId     uint64

	// RPC API服务
	netRPCService *ethapi.PublicNetAPI

	wg sync.WaitGroup
}

/**
创建一个 轻节点服务
 */
func New(ctx *node.ServiceContext, config *eth.Config) (*LightEthereum, error) {
	/**
	创建 DB 实例 (注意了，全局的和 block 相关操作的 db 均是这个 db 的引用)
	其中，cfx 为命令行入参
	config 为配置项
	"lightchaindata" 为写死的 全节点的 chain 的数据目录名称
 	*/
	chainDb, err := eth.CreateDB(ctx, config, "lightchaindata")
	if err != nil {
		return nil, err
	}
	// 设置 genesis 信息，节点启动进来的
	// 所以 genesis 应该为 nil
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, isCompat := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !isCompat {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	// 实例化一个节点的set
	peers := newPeerSet()

	// 退出信号 chan
	quitSync := make(chan struct{})

	/**
	创建轻节点实例
	 */
	leth := &LightEthereum{
		lesCommons: lesCommons{
			chainDb: chainDb,
			config:  config,
		},
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux,
		peers:          peers,
		// 构建 请求req分发器
		reqDist:        newRequestDistributor(peers, quitSync),
		accountManager: ctx.AccountManager,
		// 构建共识引擎
		engine:         eth.CreateConsensusEngine(ctx, chainConfig, &config.Ethash, nil, chainDb),
		shutdownChan:   make(chan bool),
		networkId:      config.NetworkId,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		// 布隆服务器
		bloomIndexer:   eth.NewBloomIndexer(chainDb, light.BloomTrieFrequency, light.HelperTrieConfirmations),
	}

	// 交易中继器
	leth.relay = NewLesTxRelay(peers, leth.reqDist)
	// todo 这个东西,只有当前节点为 light 节点测 client端的时候才会有值
	// todo 里头记录的是和当前 client链接的 server 端
	leth.serverPool = newServerPool(chainDb, quitSync, &leth.wg)
	// 猎犬管理器 (额,请求分发器的更上一层)
	leth.retriever = newRetrieveManager(peers, leth.reqDist, leth.serverPool)

	// todo 处理ODR检索类型的后端服务 （这个只有 Client 端才会有）
	leth.odr = NewLesOdr(chainDb, leth.retriever)

	// todo cht 是轻节点相关的 checkpoint 索引器
	leth.chtIndexer = light.NewChtIndexer(chainDb, true, leth.odr)

	// todo 轻节点相关的 bloom trie 索引器
	leth.bloomTrieIndexer = light.NewBloomTrieIndexer(chainDb, true, leth.odr)
	// SetIndexers向ODR backend添加必要的链索引器
	leth.odr.SetIndexers(leth.chtIndexer, leth.bloomTrieIndexer, leth.bloomIndexer)

	// Note: NewLightChain adds the trusted checkpoint so it needs an ODR with
	// indexers already set but not started yet
	//
	// 注意：NewLightChain添加了受信任的检查点，因此需要已设置索引器但尚未启动的ODR
	if leth.blockchain, err = light.NewLightChain(leth.odr, leth.chainConfig, leth.engine); err != nil {
		return nil, err
	}
	// Note: AddChildIndexer starts the update process for the child
	//
	// 注意：AddChildIndexer启动 子索引器 的更新过程
	leth.bloomIndexer.AddChildIndexer(leth.bloomTrieIndexer)

	/** todo 启动 checkpoint 索引器 */
	// todo  这里可能 调用 newHead(), 引起 update 信号,更新 CHT
	leth.chtIndexer.Start(leth.blockchain)
	/** todo 启动 bloom 索引器 */
	// todo  这里可能 调用 newHead(), 引起 update 信号,更新 BloomTrie
	leth.bloomIndexer.Start(leth.blockchain)

	// Rewind the chain in case of an incompatible config upgrade.
	//
	// 如果配置升级不兼容，请倒回链。
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		leth.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}

	// 初始化 light txpool
	leth.txPool = light.NewTxPool(leth.chainConfig, leth.blockchain, leth.relay)

	/** TODO 这个是大头啊  p2p 管理 */
	if leth.protocolManager, err = NewProtocolManager(leth.chainConfig, true, config.NetworkId, leth.eventMux, leth.engine, leth.peers, leth.blockchain, nil, chainDb, leth.odr, leth.relay, leth.serverPool, quitSync, &leth.wg); err != nil {
		return nil, err
	}

	// light api backend
	leth.ApiBackend = &LesApiBackend{leth, nil}

	// 实例化 gasPrice预言机
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.MinerGasPrice
	}
	leth.ApiBackend.gpo = gasprice.NewOracle(leth.ApiBackend, gpoParams)
	return leth, nil
}

func lesTopic(genesisHash common.Hash, protocolVersion uint) discv5.Topic {
	var name string
	switch protocolVersion {
	case lpv1:
		name = "LES"
	case lpv2:
		name = "LES2"
	default:
		panic(nil)
	}
	return discv5.Topic(name + "@" + common.Bytes2Hex(genesisHash.Bytes()[0:8]))
}

type LightDummyAPI struct{}

// Etherbase is the address that mining rewards will be send to
func (s *LightDummyAPI) Etherbase() (common.Address, error) {
	return common.Address{}, fmt.Errorf("not supported")
}

// Coinbase is the address that mining rewards will be send to (alias for Etherbase)
func (s *LightDummyAPI) Coinbase() (common.Address, error) {
	return common.Address{}, fmt.Errorf("not supported")
}

// Hashrate returns the POW hashrate
func (s *LightDummyAPI) Hashrate() hexutil.Uint {
	return 0
}

// Mining returns an indication if this node is currently mining.
func (s *LightDummyAPI) Mining() bool {
	return false
}

// APIs returns the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *LightEthereum) APIs() []rpc.API {
	return append(ethapi.GetAPIs(s.ApiBackend), []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   &LightDummyAPI{},
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.ApiBackend, true),
			Public:    true,
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *LightEthereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *LightEthereum) BlockChain() *light.LightChain      { return s.blockchain }
func (s *LightEthereum) TxPool() *light.TxPool              { return s.txPool }
func (s *LightEthereum) Engine() consensus.Engine           { return s.engine }
func (s *LightEthereum) LesVersion() int                    { return int(ClientProtocolVersions[0]) }
func (s *LightEthereum) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *LightEthereum) EventMux() *event.TypeMux           { return s.eventMux }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
// todo ##############################
// todo ##############################
// todo ##############################
// todo ##############################
// todo ##############################
// todo ##############################
// todo 启动轻节点 Client 端
func (s *LightEthereum) Protocols() []p2p.Protocol {

	// 这边才是创建
	return s.makeProtocols(ClientProtocolVersions)
}

// Start implements node.Service, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *LightEthereum) Start(srvr *p2p.Server) error {
	// todo 启动Bloom过滤器 <这是轻节点的bloom过滤器和block中的那个不是一回事>
	// todo 这个bloom是为了检索 `Canonical Hash Trie` 的
	s.startBloomHandlers()
	log.Warn("Light client mode is an experimental feature")
	s.netRPCService = ethapi.NewPublicNetAPI(srvr, s.networkId)
	// clients are searching for the first advertised protocol in the list
	protocolVersion := AdvertiseProtocolVersions[0]

	// todo 启动 当前Client 中记录的 Serverpool
	s.serverPool.start(srvr, lesTopic(s.blockchain.Genesis().Hash(), protocolVersion))

	// todo 启动轻节点的 Client 端
	s.protocolManager.Start(s.config.LightPeers)
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *LightEthereum) Stop() error {
	s.odr.Stop()
	s.bloomIndexer.Close()
	s.chtIndexer.Close()
	s.blockchain.Stop()
	s.protocolManager.Stop()
	s.txPool.Stop()
	s.engine.Close()

	s.eventMux.Stop()

	time.Sleep(time.Millisecond * 200)
	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}
