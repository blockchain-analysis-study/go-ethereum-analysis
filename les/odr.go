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

package les

import (
	"context"

	"github.com/go-ethereum-analysis/core"
	"github.com/go-ethereum-analysis/ethdb"
	"github.com/go-ethereum-analysis/light"
	"github.com/go-ethereum-analysis/log"
)

// LesOdr implements light.OdrBackend
type LesOdr struct {
	db                                         ethdb.Database
	chtIndexer, bloomTrieIndexer, bloomIndexer *core.ChainIndexer
	retriever                                  *retrieveManager
	stop                                       chan struct{}
}

func NewLesOdr(db ethdb.Database, retriever *retrieveManager) *LesOdr {
	return &LesOdr{
		db:        db,
		retriever: retriever,
		stop:      make(chan struct{}),
	}
}

// Stop cancels all pending retrievals
func (odr *LesOdr) Stop() {
	close(odr.stop)
}

// Database returns the backing database
func (odr *LesOdr) Database() ethdb.Database {
	return odr.db
}

// SetIndexers adds the necessary chain indexers to the ODR backend
//
// SetIndexers向ODR backend添加必要的链索引器
func (odr *LesOdr) SetIndexers(chtIndexer, bloomTrieIndexer, bloomIndexer *core.ChainIndexer) {
	odr.chtIndexer = chtIndexer
	odr.bloomTrieIndexer = bloomTrieIndexer
	odr.bloomIndexer = bloomIndexer
}

// ChtIndexer returns the CHT chain indexer
func (odr *LesOdr) ChtIndexer() *core.ChainIndexer {
	return odr.chtIndexer
}

// BloomTrieIndexer returns the bloom trie chain indexer
func (odr *LesOdr) BloomTrieIndexer() *core.ChainIndexer {
	return odr.bloomTrieIndexer
}

// BloomIndexer returns the bloombits chain indexer
func (odr *LesOdr) BloomIndexer() *core.ChainIndexer {
	return odr.bloomIndexer
}

const (
	MsgBlockBodies = iota
	MsgCode
	MsgReceipts
	MsgProofsV1
	MsgProofsV2
	MsgHeaderProofs
	MsgHelperTrieProofs
)

// Msg encodes a LES message that delivers reply data for a request
type Msg struct {
	MsgType int
	ReqID   uint64
	Obj     interface{}
}

// Retrieve tries to fetch an object from the LES network.
// If the network retrieval was successful, it stores the object in local db.
//
/**
Retrieve: 尝试从LES网络中获取对象。 如果网络检索成功，它将对象存储在本地数据库中.

TODO 一般只有两个 Indexer 需要用到
todo 一) BloomTrieIndexer
todo 二) ChtIndexer
 */
func (odr *LesOdr) Retrieve(ctx context.Context, req light.OdrRequest) (err error) {

	// 如果是BloomTrieIndexer的话, 那么 req是 `BloomRequest`
	// 如果是ChtIndexer的话, 那么 req是 `ChtRequest`
	// 类型强转处理
	lreq := LesRequest(req)

	// 随机生成一个reqId
	reqID := genReqID()
	// 构造对应的req体
	rq := &distReq{

		//
		getCost: func(dp distPeer) uint64 {
			return lreq.GetCost(dp.(*peer))
		},
		canSend: func(dp distPeer) bool {
			p := dp.(*peer)
			return lreq.CanSend(p)
		},

		// TODO 这个方法,最终会在 odr.loop() 中被调用
		request: func(dp distPeer) func() {
			p := dp.(*peer)
			cost := lreq.GetCost(p)

			// 对端server peer 的req排序!?
			p.fcServer.QueueRequest(reqID, cost)


			/**
			TODO  ChtRequest 和 BloomRequest 都会发起 拉取Header 的req
			 */
			return func() { lreq.Request(reqID, p) }
		},
	}


	/**
	todo  将构建好的 req 发起拉取
	 */
	if err = odr.retriever.retrieve(ctx, reqID, rq, func(p distPeer, msg *Msg) error { return lreq.Validate(odr.db, msg) }, odr.stop); err == nil {
		// retrieved from network, store in db
		//
		// todo 从网络检索，存储在数据库中
		req.StoreResult(odr.db)
	} else {
		log.Debug("Failed to retrieve data from network", "err", err)
	}
	return
}
