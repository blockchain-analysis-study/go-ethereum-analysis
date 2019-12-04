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

// Package light implements on-demand retrieval capable state and chain objects
// for the Ethereum Light Client.

// todo Package light实现 `可按需检索` 的状态和链对象

/**
todo ODR: on-demand retrieva, 按需检索
 */
package light

import (
	"context"
	"errors"
	"math/big"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core"
	"github.com/go-ethereum-analysis/core/rawdb"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/ethdb"
)

// NoOdr is the default context passed to an ODR capable function when the ODR
// service is not required.
//
// NoOdr是不需要ODR服务时传递给支持ODR的功能的默认上下文
var NoOdr = context.Background()

// ErrNoPeers is returned if no peers capable of serving a queued request are available
var ErrNoPeers = errors.New("no suitable peers available")

// OdrBackend is an interface to a backend service that handles ODR retrievals type
//
// OdrBackend是处理ODR检索类型的后端服务的接口
type OdrBackend interface {
	Database() ethdb.Database
	ChtIndexer() *core.ChainIndexer
	BloomTrieIndexer() *core.ChainIndexer
	BloomIndexer() *core.ChainIndexer
	Retrieve(ctx context.Context, req OdrRequest) error
}

// OdrRequest is an interface for retrieval requests
type OdrRequest interface {
	StoreResult(db ethdb.Database)
}

// TrieID identifies a state or account storage trie
type TrieID struct {
	BlockHash, Root common.Hash
	BlockNumber     uint64
	AccKey          []byte
}

// StateTrieID returns a TrieID for a state trie belonging to a certain block
// header.
func StateTrieID(header *types.Header) *TrieID {
	return &TrieID{
		BlockHash:   header.Hash(),
		BlockNumber: header.Number.Uint64(),
		AccKey:      nil,
		Root:        header.Root,
	}
}

// StorageTrieID returns a TrieID for a contract storage trie at a given account
// of a given state trie. It also requires the root hash of the trie for
// checking Merkle proofs.
func StorageTrieID(state *TrieID, addrHash, root common.Hash) *TrieID {
	return &TrieID{
		BlockHash:   state.BlockHash,
		BlockNumber: state.BlockNumber,
		AccKey:      addrHash[:],
		Root:        root,
	}
}

// TrieRequest is the ODR request type for state/storage trie entries
type TrieRequest struct {
	OdrRequest
	Id    *TrieID
	Key   []byte
	Proof *NodeSet
}

// StoreResult stores the retrieved data in local database
func (req *TrieRequest) StoreResult(db ethdb.Database) {
	req.Proof.Store(db)
}

// CodeRequest is the ODR request type for retrieving contract code
type CodeRequest struct {
	OdrRequest

	// 引用帐户的存储树
	Id   *TrieID // references storage trie of the account
	Hash common.Hash // 这个是对端节点发回来的code hash
	Data []byte // 这个是对端节点发回来的 Code 内容
}

// StoreResult stores the retrieved data in local database
func (req *CodeRequest) StoreResult(db ethdb.Database) {
	db.Put(req.Hash[:], req.Data)
}

// BlockRequest is the ODR request type for retrieving block bodies
type BlockRequest struct {
	OdrRequest
	Hash   common.Hash
	Number uint64
	Rlp    []byte
}

// StoreResult stores the retrieved data in local database
func (req *BlockRequest) StoreResult(db ethdb.Database) {
	rawdb.WriteBodyRLP(db, req.Hash, req.Number, req.Rlp)
}

// ReceiptsRequest is the ODR request type for retrieving block bodies
type ReceiptsRequest struct {
	OdrRequest
	Hash     common.Hash
	Number   uint64
	Receipts types.Receipts
}

// StoreResult stores the retrieved data in local database
func (req *ReceiptsRequest) StoreResult(db ethdb.Database) {
	rawdb.WriteReceipts(db, req.Hash, req.Number, req.Receipts)
}

// ChtRequest is the ODR request type for state/storage trie entries
//
/**
ChtRequest:
是 state/storage Trie条目的ODR req类型
 */
type ChtRequest struct {
	OdrRequest
	// ChtNum: 表示 section num <第几个章节, 从0开始>
	// BlockNum: 表示被包含在 这 section 中的某个 blockNum
	ChtNum, BlockNum uint64

	// 本 章节的 Cht trie 的 root
	ChtRoot          common.Hash

	// 这个就是去请求的header 引用,最终根据这个的 num 和 hash 进行存储
	Header           *types.Header

	// 下面这两个值基本是对应的resp回来时被回填的
	Td               *big.Int
	Proof            *NodeSet
}

// StoreResult stores the retrieved data in local database
//
// StoreResult: 将检索到的 <ChtRequest> 数据存储在本地数据库中
func (req *ChtRequest) StoreResult(db ethdb.Database) {
	hash, num := req.Header.Hash(), req.Header.Number.Uint64()

	// 往db中写 block Header
	rawdb.WriteHeader(db, req.Header)
	// 往db中写 td
	rawdb.WriteTd(db, hash, num, req.Td)

	// 往db中写 CanonicalHash
	// todo `h` + num (uint64 big endian) + `n` -> hash
	rawdb.WriteCanonicalHash(db, hash, num)
}

// BloomRequest is the ODR request type for retrieving bloom filters from a CHT structure
//
// BloomRequest: 是ODR请求类型，用于从CHT结构中检索的 Bloom过滤器
type BloomRequest struct {
	// 这个只是为了继承 OdrRequest 的方法
	// 但是并没有看到赋值的地方
	OdrRequest
	BloomTrieNum   uint64  // 表示第几个section所对应的 bloomtrie
	BitIdx         uint    // 表示 查询该 bloom 中的bit 的index
	SectionIdxList []uint64// 表示Section的index
	BloomTrieRoot  common.Hash // trie 的 root
	BloomBits      [][]byte // 整个 bloom bit vector
	Proofs         *NodeSet  // 校验结果的 proof
}

// StoreResult stores the retrieved data in local database
//
// StoreResult: 将检索到的 <BloomRequest> 数据存储在本地数据库中
// todo 这里做旋转!?
func (req *BloomRequest) StoreResult(db ethdb.Database) {

	// 遍历所有 sectionId
	for i, sectionIdx := range req.SectionIdxList {

		// TODO 这里为什么 sectionIdx+1 !?
		sectionHead := rawdb.ReadCanonicalHash(db, (sectionIdx+1)*BloomTrieFrequency-1)
		// if we don't have the canonical hash stored for this section head number, we'll still store it under
		// a key with a zero sectionHead. GetBloomBits will look there too if we still don't have the canonical
		// hash. In the unlikely case we've retrieved the section head hash since then, we'll just retrieve the
		// bit vector again from the network.
		//
		/**
		如果我们没有为该section head number存储canonical hash，
		则仍将其存储在具有零section head的键下。

		如果我们仍然没有 canonical hash，GetBloomBits也会在那寻找。
		从那时起，在极少数情况下，我们将检索 section head hash，我们将仅从网络中再次检索 bit vector <位图>。
		 */
		/**
		BloomBits数据结构通过进行按位转换来优化日志搜索，这使得检索与特定过滤器相关的Bloom过滤器数据更便宜.

		在较长的块历史记录中进行搜索时，我们正在检查每个查询地址/主题的每个布隆过滤器的三个特定位.



		BloomBits结构通过Bloom过滤器的“按位90度旋转”来优化Bloom过滤器查找。
		块分为固定长度的部分（LES BloomBits Trie的部分大小为32768块），
		BloomBits[bitIdx][sectionIdx]是一个32768位（4096字节）长的位向量，
		其中包含来自块范围的每个Bloom过滤器的单个位sectionIdx*SectionSize ... (sectionIdx+1)*SectionSize-1。
		由于布隆过滤器通常比较稀疏，因此简单的数据压缩使该结构更加有效，尤其是按需检索。
		通过读取和对三个BloomBits部分进行二进制“与”运算，
		我们可以一次过滤32768个块中的地址/主题（二进制AND结果均值Bloom匹配中的“ 1”位.
		*/
		rawdb.WriteBloomBits(db, req.BitIdx, sectionIdx, sectionHead, req.BloomBits[i])
	}
}
