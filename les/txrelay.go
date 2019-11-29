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
	"sync"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core/types"
)

type ltrInfo struct {
	// tx详情
	tx     *types.Transaction
	// 被发送给了哪些节点
	sentTo map[*peer]struct{}
}

// peerSetNotify 的一个实现
type LesTxRelay struct {
	// 记录已发送的tx
	txSent       map[common.Hash]*ltrInfo
	// 记录还没发送的tx
	txPending    map[common.Hash]struct{}
	// 和当前节点互联的对端节点集
	ps           *peerSet
	//
	peerList     []*peer
	peerStartPos int
	lock         sync.RWMutex

	// 请求分发器的指针
	reqDist *requestDistributor
}

func NewLesTxRelay(ps *peerSet, reqDist *requestDistributor) *LesTxRelay {
	r := &LesTxRelay{
		//
		txSent:    make(map[common.Hash]*ltrInfo),
		txPending: make(map[common.Hash]struct{}),
		ps:        ps,
		reqDist:   reqDist,
	}
	ps.notify(r)
	return r
}

func (self *LesTxRelay) registerPeer(p *peer) {
	self.lock.Lock()
	defer self.lock.Unlock()

	self.peerList = self.ps.AllPeers()
}

func (self *LesTxRelay) unregisterPeer(p *peer) {
	self.lock.Lock()
	defer self.lock.Unlock()

	self.peerList = self.ps.AllPeers()
}

// send sends a list of transactions to at most a given number of peers at
// once, never resending any particular transaction to the same peer twice
//
/**
send:
一次将 tx 列表最多发送给给定数量的 peer，而从未两次将任何特定 tx 重新发送给同一 peer
 */
func (self *LesTxRelay) send(txs types.Transactions, count int) {
	sendTo := make(map[*peer]types.Transactions)

	self.peerStartPos++ // rotate the starting position of the peer list
	if self.peerStartPos >= len(self.peerList) {
		self.peerStartPos = 0
	}

	for _, tx := range txs {
		hash := tx.Hash()
		ltr, ok := self.txSent[hash]
		if !ok {
			ltr = &ltrInfo{
				tx:     tx,
				sentTo: make(map[*peer]struct{}),
			}
			self.txSent[hash] = ltr
			self.txPending[hash] = struct{}{}
		}

		if len(self.peerList) > 0 {
			cnt := count
			pos := self.peerStartPos
			for {
				peer := self.peerList[pos]
				if _, ok := ltr.sentTo[peer]; !ok {
					sendTo[peer] = append(sendTo[peer], tx)
					ltr.sentTo[peer] = struct{}{}
					cnt--
				}
				if cnt == 0 {
					break // sent it to the desired number of peers
				}
				pos++
				if pos == len(self.peerList) {
					pos = 0
				}
				if pos == self.peerStartPos {
					break // tried all available peers
				}
			}
		}
	}

	for p, list := range sendTo {
		pp := p
		ll := list

		reqID := genReqID()
		rq := &distReq{
			getCost: func(dp distPeer) uint64 {
				peer := dp.(*peer)
				return peer.GetRequestCost(SendTxMsg, len(ll))
			},
			canSend: func(dp distPeer) bool {
				return dp.(*peer) == pp
			},
			request: func(dp distPeer) func() {
				peer := dp.(*peer)
				cost := peer.GetRequestCost(SendTxMsg, len(ll))
				peer.fcServer.QueueRequest(reqID, cost)

				// todo 发送一个 txs req
				return func() { peer.SendTxs(reqID, cost, ll) }
			},
		}
		self.reqDist.queue(rq)
	}
}

func (self *LesTxRelay) Send(txs types.Transactions) {
	self.lock.Lock()
	defer self.lock.Unlock()

	// todo 发给 对端peer (les server)
	self.send(txs, 3)
}

func (self *LesTxRelay) NewHead(head common.Hash, mined []common.Hash, rollback []common.Hash) {
	self.lock.Lock()
	defer self.lock.Unlock()

	for _, hash := range mined {
		delete(self.txPending, hash)
	}

	for _, hash := range rollback {
		self.txPending[hash] = struct{}{}
	}

	if len(self.txPending) > 0 {
		txs := make(types.Transactions, len(self.txPending))
		i := 0
		for hash := range self.txPending {
			txs[i] = self.txSent[hash].tx
			i++
		}

		// todo 发给对端 peer (les server)
		self.send(txs, 1)
	}
}

func (self *LesTxRelay) Discard(hashes []common.Hash) {
	self.lock.Lock()
	defer self.lock.Unlock()

	for _, hash := range hashes {
		delete(self.txSent, hash)
		delete(self.txPending, hash)
	}
}
