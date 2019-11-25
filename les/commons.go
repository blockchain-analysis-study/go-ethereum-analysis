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

package les

import (
	"fmt"
	"math/big"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core"
	"github.com/go-ethereum-analysis/eth"
	"github.com/go-ethereum-analysis/ethdb"
	"github.com/go-ethereum-analysis/light"
	"github.com/go-ethereum-analysis/p2p"
	"github.com/go-ethereum-analysis/p2p/discover"
	"github.com/go-ethereum-analysis/params"
)

// lesCommons contains fields needed by both server and client.
type lesCommons struct {
	config                       *eth.Config
	chainDb                      ethdb.Database
	protocolManager              *ProtocolManager
	chtIndexer, bloomTrieIndexer *core.ChainIndexer
}

// NodeInfo represents a short summary of the Ethereum sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Network    uint64                  `json:"network"`    // Ethereum network ID (1=Frontier, 2=Morden, Ropsten=3, Rinkeby=4)
	Difficulty *big.Int                `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis    common.Hash             `json:"genesis"`    // SHA3 hash of the host's genesis block
	Config     *params.ChainConfig     `json:"config"`     // Chain configuration for the fork rules
	Head       common.Hash             `json:"head"`       // SHA3 hash of the host's best owned block
	CHT        light.TrustedCheckpoint `json:"cht"`        // Trused CHT checkpoint for fast catchup
}

// makeProtocols creates protocol descriptors for the given LES versions.
//
// makeProtocols: 为给定的LES版本创建协议描述符
func (c *lesCommons) makeProtocols(versions []uint) []p2p.Protocol {
	protos := make([]p2p.Protocol, len(versions))
	for i, version := range versions {
		version := version
		protos[i] = p2p.Protocol{
			Name:     "les",
			Version:  version,
			Length:   ProtocolLengths[version],
			NodeInfo: c.nodeInfo,

			/**
			todo 启动当前节点
			 */
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {

				/**
				TODO 这里相当的重要
				todo 运行 轻节点
				todo 轻节点就是从这里为入口的啦
				 */
				return c.protocolManager.runPeer(version, p, rw)
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := c.protocolManager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		}
	}
	return protos
}

// nodeInfo retrieves some protocol metadata about the running host node.
func (c *lesCommons) nodeInfo() interface{} {
	var cht light.TrustedCheckpoint
	sections, _, _ := c.chtIndexer.Sections()
	sections2, _, _ := c.bloomTrieIndexer.Sections()

	if !c.protocolManager.lightSync {
		// convert to client section size if running in server mode
		sections /= light.CHTFrequencyClient / light.CHTFrequencyServer
	}

	if sections2 < sections {
		sections = sections2
	}
	if sections > 0 {
		sectionIndex := sections - 1
		sectionHead := c.bloomTrieIndexer.SectionHead(sectionIndex)
		var chtRoot common.Hash
		if c.protocolManager.lightSync {
			chtRoot = light.GetChtRoot(c.chainDb, sectionIndex, sectionHead)
		} else {
			chtRoot = light.GetChtV2Root(c.chainDb, sectionIndex, sectionHead)
		}
		cht = light.TrustedCheckpoint{
			SectionIdx:  sectionIndex,
			SectionHead: sectionHead,
			CHTRoot:     chtRoot,
			BloomRoot:   light.GetBloomTrieRoot(c.chainDb, sectionIndex, sectionHead),
		}
	}

	chain := c.protocolManager.blockchain
	head := chain.CurrentHeader()
	hash := head.Hash()
	return &NodeInfo{
		Network:    c.config.NetworkId,
		Difficulty: chain.GetTd(hash, head.Number.Uint64()),
		Genesis:    chain.Genesis().Hash(),
		Config:     chain.Config(),
		Head:       chain.CurrentHeader().Hash(),
		CHT:        cht,
	}
}
