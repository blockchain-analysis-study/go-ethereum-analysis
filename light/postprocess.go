// Copyright 2017 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package light

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/common/bitutil"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/rawdb"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/types"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/ethdb"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/params"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rlp"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/trie"
)

const (
	// CHTFrequencyClient is the block frequency for creating CHTs on the client side.
	//
	// TODO CHTFrequencyClient: 是在(轻节点)客户端上创建CHT的block频率
	CHTFrequencyClient = 32768  // todo 用于Client

	// CHTFrequencyServer is the block frequency for creating CHTs on the server side.
	// Eventually this can be merged back with the client version, but that requires a
	// full database upgrade, so that should be left for a suitable moment.
	//
	// todo CHTFrequencyServer: 是在(轻节点)服务器端创建CHT的block频率
	//  最终，可以将其与客户端版本合并，但是这需要对数据库进行全面升级，因此应保留适当的时间.
	CHTFrequencyServer = 4096  // todo 用于 Server

	// number of confirmations before a server is expected to have the given HelperTrie available
	//
	// 预期服务器使给定的HelperTrie `可用` 之前的确认次数
	// todo 因为: CHT仅在2048次确认后生成，以确保不会被链重组更改
	/**
	CHT仅在2048次确认后生成，以确保不会被链重组更改
	 */
	HelperTrieConfirmations        = 2048  // todo 主要用于 Client 端 !?
	// number of confirmations before a HelperTrie is generated
	//
	// HelperTrie `生成` 之前的确认次数
	HelperTrieProcessConfirmations = 256  // todo 重要用于 Server 端?
)

// TrustedCheckpoint represents a set of post-processed trie roots (CHT and BloomTrie) associated with
// the appropriate section index and head hash. It is used to start light syncing from this checkpoint
// and avoid downloading the entire header chain while still being able to securely access old headers/logs.
//
/**
TrustedCheckpoint:
	表示一组与适当的 section 索引和 header hash 关联的后处理的trie根（CHT和BloomTrie）。
	它用于从此 checkpoint 开始进行 light 同步，并避免下载整个 header chain，
	同时仍然能够安全地访问旧的headers/logs.

 */
type TrustedCheckpoint struct {
	name                            string
	SectionIdx                      uint64
	SectionHead, CHTRoot, BloomRoot common.Hash
}

// trustedCheckpoints associates each known checkpoint with the genesis hash of the chain it belongs to
//
// trustedCheckpoints: 将每个已知 checkpoint 与其所属 chain 的 genesis hash 关联
var trustedCheckpoints = map[common.Hash]TrustedCheckpoint{
	params.MainnetGenesisHash: {
		name:        "mainnet",
		SectionIdx:  187,
		SectionHead: common.HexToHash("e6baa034efa31562d71ff23676512dec6562c1ad0301e08843b907e81958c696"),
		CHTRoot:     common.HexToHash("28001955219719cf06de1b08648969139d123a9835fc760547a1e4dabdabc15a"),
		BloomRoot:   common.HexToHash("395ca2373fc662720ac6b58b3bbe71f68aa0f38b63b2d3553dd32ff3c51eebc4"),
	},
	params.TestnetGenesisHash: {
		name:        "ropsten",
		SectionIdx:  117,
		SectionHead: common.HexToHash("9529b38631ae30783f56cbe4c3b9f07575b770ecba4f6e20a274b1e2f40fede1"),
		CHTRoot:     common.HexToHash("6f48e9f101f1fac98e7d74fbbcc4fda138358271ffd974d40d2506f0308bb363"),
		BloomRoot:   common.HexToHash("8242342e66e942c0cd893484e6736b9862ceb88b43ca344bb06a8285ac1b6d64"),
	},
	params.RinkebyGenesisHash: {
		name:        "rinkeby",
		SectionIdx:  85,
		SectionHead: common.HexToHash("92cfa67afc4ad8ab0dcbc6fa49efd14b5b19402442e7317e6bc879d85f89d64d"),
		CHTRoot:     common.HexToHash("2802ec92cd7a54a75bca96afdc666ae7b99e5d96cf8192dcfb09588812f51564"),
		BloomRoot:   common.HexToHash("ebefeb31a9a42866d8cf2d2477704b4c3d7c20d0e4e9b5aaa77f396e016a1263"),
	},
}

var (
	ErrNoTrustedCht       = errors.New("No trusted canonical hash trie")
	ErrNoTrustedBloomTrie = errors.New("No trusted bloom trie")
	ErrNoHeader           = errors.New("Header not found")

	/**
	todo 轻节点的 规范 hash trie 相关的key前缀
	 */
	chtPrefix             = []byte("chtRoot-") // chtPrefix + chtNum (uint64 big endian) -> trie root hash
	ChtTablePrefix        = "cht-"  // todo 规范hash trie 的相关node 的key的prefix
)

// ChtNode structures are stored in the Canonical Hash Trie in an RLP encoded format
type ChtNode struct {
	Hash common.Hash
	Td   *big.Int
}

// GetChtRoot reads the CHT root assoctiated to the given section from the database
// Note that sectionIdx is specified according to LES/1 CHT section size
//
/**
GetChtRoot:
从 db 中读取分配给给定 section 的CHT root。
请注意，sectionIdx 是遵循 LES/1 CHT section 大小指定的

入参 :
	sectionIdx: 第几个 section !? (从 0 开始 !?)
	sectionHead: section的第一个 block header Hash !?
 */
func GetChtRoot(db ethdb.Database, sectionIdx uint64, sectionHead common.Hash) common.Hash {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], sectionIdx)
	data, _ := db.Get(append(append(chtPrefix, encNumber[:]...), sectionHead.Bytes()...))
	return common.BytesToHash(data)
}

// GetChtV2Root reads the CHT root assoctiated to the given section from the database
// Note that sectionIdx is specified according to LES/2 CHT section size
//
/**
GetChtV2Root:
从数据库中读取分配给给定节的CHT根。请注意，sectionIdx是根据 LES/2 CHT section大小指定的

 */
func GetChtV2Root(db ethdb.Database, sectionIdx uint64, sectionHead common.Hash) common.Hash {
	return GetChtRoot(db, (sectionIdx+1)*(CHTFrequencyClient/CHTFrequencyServer)-1, sectionHead)
}

// StoreChtRoot writes the CHT root assoctiated to the given section into the database
// Note that sectionIdx is specified according to LES/1 CHT section size
//
// todo 重要
func StoreChtRoot(db ethdb.Database, sectionIdx uint64, sectionHead, root common.Hash) {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], sectionIdx)
	db.Put(append(append(chtPrefix, encNumber[:]...), sectionHead.Bytes()...), root.Bytes())
}

// ChtIndexerBackend implements core.ChainIndexerBackend
type ChtIndexerBackend struct {
	// diskdb: 操作 Root 和存储 Hash 的db
	// trieTable: 这个操作存储 Proof的 db
	diskdb, trieTable    ethdb.Database
	odr                  OdrBackend
	// 这个操作 trie 的db
	triedb               *trie.Database

	// section: 目前最新 section
	// sectionSize: 当前每个章节的宽度
	section, sectionSize uint64
	// 本section 中的最后一个block的hash
	lastHash             common.Hash

	// 这颗就是 CHT 树
	trie                 *trie.Trie
}


func NewChtIndexer(db ethdb.Database, clientMode bool, odr OdrBackend) *core.ChainIndexer {
	var sectionSize, confirmReq uint64

	// TODO 设置 Client 和 server 记录CHT 区别
	if clientMode {

		// Client  每 32768 一次记录
		sectionSize = CHTFrequencyClient
		// 需要等 2048 块才算确认
		confirmReq = HelperTrieConfirmations
	} else {

		// Server 每4096 一次记录
		sectionSize = CHTFrequencyServer
		// 需要 256 块才算确认
		confirmReq = HelperTrieProcessConfirmations
	}
	idb := ethdb.NewTable(db, "chtIndex-")
	trieTable := ethdb.NewTable(db, ChtTablePrefix)

	/**
	todo
	 这个是 Canonical Hash Trie, 规范哈希树
	 */
	backend := &ChtIndexerBackend{
		diskdb:      db,

		// todo 注意：这里的odr只有在 LightEthereum 实例化的时候才会传入
		// 		在LesServer 实例化的时候，没有传入

		odr:         odr,
		trieTable:   trieTable,
		triedb:      trie.NewDatabase(trieTable),
		sectionSize: sectionSize,
	}

	// TODO 启动 ChtIndexer
	return core.NewChainIndexer(db, idb, backend, sectionSize, confirmReq, time.Millisecond*100, "cht")
}

// fetchMissingNodes tries to retrieve the last entry of the latest trusted CHT from the
// ODR backend in order to be able to add new entries and calculate subsequent root hashes
//
/**
fetchMissingNodes:
尝试从ODR后端检索最新的受信任CHT的最后一个条目，以便能够添加新条目并计算后续的根哈希.
 */
func (c *ChtIndexerBackend) fetchMissingNodes(ctx context.Context, section uint64, root common.Hash) error {
	batch := c.trieTable.NewBatch()
	r := &ChtRequest{ChtRoot: root, ChtNum: section - 1, BlockNum: section*c.sectionSize - 1}
	for {
		/**
		todo 构建 发起 检索拉取 证明的 req 并将 result 存储在本地 <里面调用了 StoreResult()>
		*/
		err := c.odr.Retrieve(ctx, r)
		switch err {
		case nil:

			// todo 并将 proof 写入db
			r.Proof.Store(batch)
			return batch.Write()
		case ErrNoPeers:
			// if there are no peers to serve, retry later
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second * 10):
				// stay in the loop and try again
			}
		default:
			return err
		}
	}
}

// Reset implements core.ChainIndexerBackend
func (c *ChtIndexerBackend) Reset(ctx context.Context, section uint64, lastSectionHead common.Hash) error {
	var root common.Hash
	if section > 0 {
		root = GetChtRoot(c.diskdb, section-1, lastSectionHead)
	}
	var err error
	c.trie, err = trie.New(root, c.triedb)

	// todo 注意， c.ord 如果是 Server端的c，则 c.odr 为nil的，
	//    因为在 NewLesServer中 new ChtRequest 和 new BloomRequest时，传入的 odr 为nil
	if err != nil && c.odr != nil {
		err = c.fetchMissingNodes(ctx, section, root)
		if err == nil {
			c.trie, err = trie.New(root, c.triedb)
		}
	}

	c.section = section
	return err
}

// Process implements core.ChainIndexerBackend
//
// 根据 header的 num, hash 和 td 插入 trie 中
// key: num  -> value: hash+td
func (c *ChtIndexerBackend) Process(ctx context.Context, header *types.Header) error {
	hash, num := header.Hash(), header.Number.Uint64()
	c.lastHash = hash

	td := rawdb.ReadTd(c.diskdb, hash, num)
	if td == nil {
		panic(nil)
	}
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], num)
	data, _ := rlp.EncodeToBytes(ChtNode{hash, td})

	// todo 更新树, key: num  -> value: hash+td
	// todo 这个就是  CHT 数的 k-v
	c.trie.Update(encNumber[:], data)
	return nil
}

// Commit implements core.ChainIndexerBackend
func (c *ChtIndexerBackend) Commit() error {

	// 提交/更新/折叠　trie
	root, err := c.trie.Commit(nil)
	if err != nil {
		return err
	}

	// 提交 node 至 db.nodes
	c.triedb.Commit(root, false)

	if ((c.section+1)*c.sectionSize)%CHTFrequencyClient == 0 {
		log.Info("Storing CHT", "section", c.section*c.sectionSize/CHTFrequencyClient, "head", fmt.Sprintf("%064x", c.lastHash), "root", fmt.Sprintf("%064x", root))
	}

	// todo 在Commit 时 提交root
	StoreChtRoot(c.diskdb, c.section, c.lastHash, root)
	return nil
}

const (
	// 这个是 Client 每隔 32768 组一个 BloomTrie
	BloomTrieFrequency  = 32768

	// 这个是 Server 每隔 4096 组一个 BloomTrie
	ethBloomBitsSection = 4096
)

var (
	bloomTriePrefix      = []byte("bltRoot-") // bloomTriePrefix + bloomTrieNum (uint64 big endian) -> trie root hash
	BloomTrieTablePrefix = "blt-"
)

// GetBloomTrieRoot reads the BloomTrie root assoctiated to the given section from the database
func GetBloomTrieRoot(db ethdb.Database, sectionIdx uint64, sectionHead common.Hash) common.Hash {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], sectionIdx)
	data, _ := db.Get(append(append(bloomTriePrefix, encNumber[:]...), sectionHead.Bytes()...))
	return common.BytesToHash(data)
}

// StoreBloomTrieRoot writes the BloomTrie root assoctiated to the given section into the database
func StoreBloomTrieRoot(db ethdb.Database, sectionIdx uint64, sectionHead, root common.Hash) {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], sectionIdx)
	db.Put(append(append(bloomTriePrefix, encNumber[:]...), sectionHead.Bytes()...), root.Bytes())
}

// BloomTrieIndexerBackend implements core.ChainIndexerBackend
//
// todo 块分为固定长度的部分（LES BloomBits Trie的部分大小为32768块），
//  BloomBits[bitIdx][sectionIdx]是一个32768位（4096字节）长的位向量，
//  其中包含来自块范围的每个Bloom过滤器的单个位 sectionIdx*SectionSize ... (sectionIdx+1)*SectionSize-1
type BloomTrieIndexerBackend struct {

	// diskdb: 操作 Root 和 Hash 的db
	// trieTable: 操作 proof 的db
	diskdb, trieTable                          ethdb.Database

	// 这个重要, 按需检索的实例
	odr                                        OdrBackend
	// 这个是操作树的db
	triedb                                     *trie.Database
	//
	section, parentSectionSize, bloomTrieRatio uint64

	// 这颗是 BloomTrie
	trie                                       *trie.Trie
	// 这里记录 section 的所有 head !?
	sectionHeads                               []common.Hash
}

// NewBloomTrieIndexer creates a BloomTrie chain indexer
//
// NewBloomTrieIndexer: 创建一个BloomTrie链索引器
func NewBloomTrieIndexer(db ethdb.Database, clientMode bool, odr OdrBackend) *core.ChainIndexer {
	trieTable := ethdb.NewTable(db, BloomTrieTablePrefix)


	backend := &BloomTrieIndexerBackend{
		diskdb:    db,

		// todo 注意：这里的odr只有在 LightEthereum 实例化的时候才会传入
		// 		在LesServer 实例化的时候，没有传入
		odr:       odr,
		trieTable: trieTable,
		triedb:    trie.NewDatabase(trieTable),
	}
	idb := ethdb.NewTable(db, "bltIndex-")

	if clientMode {

		// 这个是 Client 每隔 32768 组一个 BloomTrie
		backend.parentSectionSize = BloomTrieFrequency
	} else {
		// 这个是 Server 每隔 4096 组一个 BloomTrie
		backend.parentSectionSize = ethBloomBitsSection
	}
	backend.bloomTrieRatio = BloomTrieFrequency / backend.parentSectionSize
	backend.sectionHeads = make([]common.Hash, backend.bloomTrieRatio)

	// TODO 启动 `BloomTrieIndexer`
	return core.NewChainIndexer(db, idb, backend, BloomTrieFrequency, 0, time.Millisecond*100, "bloomtrie")
}

// fetchMissingNodes tries to retrieve the last entries of the latest trusted bloom trie from the
// ODR backend in order to be able to add new entries and calculate subsequent root hashes
//
/**
fetchMissingNodes:
尝试从ODR后端检索最新的可信任Bloom Trie的最后一个条目，以便能够添加新条目并计算后续的根哈希.
 */
func (b *BloomTrieIndexerBackend) fetchMissingNodes(ctx context.Context, section uint64, root common.Hash) error {
	indexCh := make(chan uint, types.BloomBitLength)
	type res struct {
		nodes *NodeSet
		err   error
	}
	resCh := make(chan res, types.BloomBitLength)
	for i := 0; i < 20; i++ {
		go func() {

			// 根据 chan中传过来 bit 的索引,构建req
			for bitIndex := range indexCh {
				// todo 查看当前 section <section - 1: 表示 section的索引是从0开始的> 中的 各个 bit
				r := &BloomRequest{BloomTrieRoot: root, BloomTrieNum: section - 1, BitIdx: bitIndex, SectionIdxList: []uint64{section - 1}}
				for {

					/**
					todo 构建 发起 检索拉取 证明的 req 并将result存储在本地 (里面调用了 StoreResult())
					 */
					if err := b.odr.Retrieve(ctx, r); err == ErrNoPeers {
						// if there are no peers to serve, retry later
						select {
						case <-ctx.Done():
							resCh <- res{nil, ctx.Err()}
							return
						case <-time.After(time.Second * 10):
							// stay in the loop and try again
						}
					} else {

						// 将 proof 发送 resCh <往下的代码有用>
						resCh <- res{r.Proofs, err}
						break
					}
				}
			}
		}()
	}

	// 按照 Bloom 的bit,一个一个的遍历
	for i := uint(0); i < types.BloomBitLength; i++ {
		indexCh <- i
	}
	close(indexCh)
	batch := b.trieTable.NewBatch()
	for i := uint(0); i < types.BloomBitLength; i++ {
		res := <-resCh
		if res.err != nil {
			return res.err
		}

		// 最后将  nodeSet <proof: 也是由这个额转换而成的> 写入 db
		res.nodes.Store(batch)
	}
	return batch.Write()
}

// Reset implements core.ChainIndexerBackend
func (b *BloomTrieIndexerBackend) Reset(ctx context.Context, section uint64, lastSectionHead common.Hash) error {
	var root common.Hash
	if section > 0 {
		root = GetBloomTrieRoot(b.diskdb, section-1, lastSectionHead)
	}
	var err error
	b.trie, err = trie.New(root, b.triedb)
	if err != nil && b.odr != nil {
		err = b.fetchMissingNodes(ctx, section, root)
		if err == nil {
			b.trie, err = trie.New(root, b.triedb)
		}
	}
	b.section = section
	return err
}

// Process implements core.ChainIndexerBackend
//
// 这个就做一件事, 将 bloomtrie 旋转 90° !?
// BloomBits结构通过Bloom过滤器的“按位90度旋转”来优化Bloom过滤器查找 !?
func (b *BloomTrieIndexerBackend) Process(ctx context.Context, header *types.Header) error {
	num := header.Number.Uint64() - b.section*BloomTrieFrequency
	if (num+1)%b.parentSectionSize == 0 {
		b.sectionHeads[num/b.parentSectionSize] = header.Hash()
	}
	return nil
}

// Commit implements core.ChainIndexerBackend
func (b *BloomTrieIndexerBackend) Commit() error {
	var compSize, decompSize uint64

	for i := uint(0); i < types.BloomBitLength; i++ {
		var encKey [10]byte
		binary.BigEndian.PutUint16(encKey[0:2], uint16(i))
		binary.BigEndian.PutUint64(encKey[2:10], b.section)
		var decomp []byte
		for j := uint64(0); j < b.bloomTrieRatio; j++ {
			data, err := rawdb.ReadBloomBits(b.diskdb, i, b.section*b.bloomTrieRatio+j, b.sectionHeads[j])
			if err != nil {
				return err
			}
			decompData, err2 := bitutil.DecompressBytes(data, int(b.parentSectionSize/8))
			if err2 != nil {
				return err2
			}
			decomp = append(decomp, decompData...)
		}
		comp := bitutil.CompressBytes(decomp)

		decompSize += uint64(len(decomp))
		compSize += uint64(len(comp))
		if len(comp) > 0 {
			b.trie.Update(encKey[:], comp)
		} else {
			b.trie.Delete(encKey[:])
		}
	}

	// todo 超级重要  提交/更新/折叠 树
	root, err := b.trie.Commit(nil)
	if err != nil {
		return err
	}

	// todo 重要 将node提交到 db.nodes
	b.triedb.Commit(root, false)

	sectionHead := b.sectionHeads[b.bloomTrieRatio-1]
	log.Info("Storing bloom trie", "section", b.section, "head", fmt.Sprintf("%064x", sectionHead), "root", fmt.Sprintf("%064x", root), "compression", float64(compSize)/float64(decompSize))
	StoreBloomTrieRoot(b.diskdb, b.section, sectionHead, root)

	return nil
}
