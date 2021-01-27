// Copyright 2016 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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
	"bytes"
	"context"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/rawdb"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/types"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rlp"
)

var sha3_nil = crypto.Keccak256Hash(nil)

func GetHeaderByNumber(ctx context.Context, odr OdrBackend, number uint64) (*types.Header, error) {
	db := odr.Database()

	// todo 这里先根据 number 获取 规范block 的Hash, 再做一波尝试
	hash := rawdb.ReadCanonicalHash(db, number)
	// 如果本地有 规范block hash,则可以从 本地拉取  header
	if (hash != common.Hash{}) {
		// if there is a canonical hash, there is a header too
		//
		// 如果有规范的哈希，也肯定有 header
		header := rawdb.ReadHeader(db, hash, number)
		if header == nil {
			panic("Canonical hash present but header not found")
		}
		return header, nil
	}


	// todo 否则,去对端 server 上拉取 header
	var (
		chtCount, sectionHeadNum uint64
		sectionHead              common.Hash
	)
	if odr.ChtIndexer() != nil {

		//  成功索引到数据库中的section数
		//  section中的最后一个的那个block number
		//  最后一个 head的Hash
		chtCount, sectionHeadNum, sectionHead = odr.ChtIndexer().Sections()

		// 先获取最后一个hash
		canonicalHash := rawdb.ReadCanonicalHash(db, sectionHeadNum)
		// if the CHT was injected as a trusted checkpoint, we have no canonical hash yet so we accept zero hash too
		//
		// 如果将CHT注入 成为受信任的 checkpoint，则我们尚无规范哈希，因此我们也接受零哈希
		for chtCount > 0 && canonicalHash != sectionHead && canonicalHash != (common.Hash{}) {
			chtCount--
			if chtCount > 0 {
				//  todo 一段一段的根据 chtCount <成功索引到数据库中的section数> 往回找
				sectionHeadNum = chtCount*CHTFrequencyClient - 1

				// todo 就是在找 这个 sectionHead
				sectionHead = odr.ChtIndexer().SectionHead(chtCount - 1)
				canonicalHash = rawdb.ReadCanonicalHash(db, sectionHeadNum)
			}
		}
	}

	// 如果, 当前 number > 所有已经 检查过的 section
	// 则, 有问题啊
	if number >= chtCount*CHTFrequencyClient {
		return nil, ErrNoTrustedCht
	}

	// todo 如果,处于 checkpoint 的section中的 (section从0开始, chtCount - 1)
	// 根据 odr trie 去拉
	r := &ChtRequest{ChtRoot: GetChtRoot(db, chtCount-1, sectionHead), ChtNum: chtCount - 1, BlockNum: number}

	// todo 这时候回去对端 peer 上拉取 这个 CHT section 区间的这个 header
	if err := odr.Retrieve(ctx, r); err != nil {
		return nil, err
	}
	return r.Header, nil
}

func GetCanonicalHash(ctx context.Context, odr OdrBackend, number uint64) (common.Hash, error) {
	hash := rawdb.ReadCanonicalHash(odr.Database(), number)
	if (hash != common.Hash{}) {
		return hash, nil
	}
	header, err := GetHeaderByNumber(ctx, odr, number)
	if header != nil {
		return header.Hash(), nil
	}
	return common.Hash{}, err
}

// GetBodyRLP retrieves the block body (transactions and uncles) in RLP encoding.
func GetBodyRLP(ctx context.Context, odr OdrBackend, hash common.Hash, number uint64) (rlp.RawValue, error) {
	if data := rawdb.ReadBodyRLP(odr.Database(), hash, number); data != nil {
		return data, nil
	}
	r := &BlockRequest{Hash: hash, Number: number}
	if err := odr.Retrieve(ctx, r); err != nil {
		return nil, err
	} else {
		return r.Rlp, nil
	}
}

// GetBody retrieves the block body (transactons, uncles) corresponding to the
// hash.
func GetBody(ctx context.Context, odr OdrBackend, hash common.Hash, number uint64) (*types.Body, error) {
	data, err := GetBodyRLP(ctx, odr, hash, number)
	if err != nil {
		return nil, err
	}
	body := new(types.Body)
	if err := rlp.Decode(bytes.NewReader(data), body); err != nil {
		return nil, err
	}
	return body, nil
}

// GetBlock retrieves an entire block corresponding to the hash, assembling it
// back from the stored header and body.
func GetBlock(ctx context.Context, odr OdrBackend, hash common.Hash, number uint64) (*types.Block, error) {
	// Retrieve the block header and body contents
	header := rawdb.ReadHeader(odr.Database(), hash, number)
	if header == nil {
		return nil, ErrNoHeader
	}
	body, err := GetBody(ctx, odr, hash, number)
	if err != nil {
		return nil, err
	}
	// Reassemble the block and return
	return types.NewBlockWithHeader(header).WithBody(body.Transactions, body.Uncles), nil
}

// GetBlockReceipts retrieves the receipts generated by the transactions included
// in a block given by its hash.
func GetBlockReceipts(ctx context.Context, odr OdrBackend, hash common.Hash, number uint64) (types.Receipts, error) {
	// Retrieve the potentially incomplete receipts from disk or network
	receipts := rawdb.ReadReceipts(odr.Database(), hash, number)
	if receipts == nil {
		r := &ReceiptsRequest{Hash: hash, Number: number}
		if err := odr.Retrieve(ctx, r); err != nil {
			return nil, err
		}
		receipts = r.Receipts
	}
	// If the receipts are incomplete, fill the derived fields
	if len(receipts) > 0 && receipts[0].TxHash == (common.Hash{}) {
		block, err := GetBlock(ctx, odr, hash, number)
		if err != nil {
			return nil, err
		}
		genesis := rawdb.ReadCanonicalHash(odr.Database(), 0)
		config := rawdb.ReadChainConfig(odr.Database(), genesis)

		if err := core.SetReceiptsData(config, block, receipts); err != nil {
			return nil, err
		}
		rawdb.WriteReceipts(odr.Database(), hash, number, receipts)
	}
	return receipts, nil
}

// GetBlockLogs retrieves the logs generated by the transactions included in a
// block given by its hash.
func GetBlockLogs(ctx context.Context, odr OdrBackend, hash common.Hash, number uint64) ([][]*types.Log, error) {
	// Retrieve the potentially incomplete receipts from disk or network
	receipts := rawdb.ReadReceipts(odr.Database(), hash, number)
	if receipts == nil {
		r := &ReceiptsRequest{Hash: hash, Number: number}
		if err := odr.Retrieve(ctx, r); err != nil {
			return nil, err
		}
		receipts = r.Receipts
	}
	// Return the logs without deriving any computed fields on the receipts
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

// GetBloomBits retrieves a batch of compressed bloomBits vectors belonging to the given bit index and section indexes
//
// GetBloomBits: 检索一批属于给 定位索引 <given bit index> 和 section索引的 压缩bloomBits 集合
func GetBloomBits(ctx context.Context, odr OdrBackend, bitIdx uint, sectionIdxList []uint64) ([][]byte, error) {

	// 先拿本地的 odrDB
	db := odr.Database()
	result := make([][]byte, len(sectionIdxList))
	var (
		reqList []uint64
		reqIdx  []int
	)

	var (
		bloomTrieCount, sectionHeadNum uint64
		sectionHead                    common.Hash
	)


	// todo 返回Bloom Trie链索引器
	if odr.BloomTrieIndexer() != nil {

		/**
		todo 注意了
			bloomTrieCount: 从索引器上获取 Section的数目(bloomTrie是Section的bloomTrie, 所以Section的数目就是bloomTrieCount)
			sectionHeadNum: section中的最后一个的那个block number
			sectionHead: 最后一个 head的Hash
		 */
		bloomTrieCount, sectionHeadNum, sectionHead = odr.BloomTrieIndexer().Sections()

		// 先去本地 db 根据 num查Hash
		canonicalHash := rawdb.ReadCanonicalHash(db, sectionHeadNum)
		// if the BloomTrie was injected as a trusted checkpoint, we have no canonical hash yet so we accept zero hash too
		//
		// 如果将BloomTrie注入为受信任的 checkpoint，则我们尚无规范哈希，因此我们也接受零哈希
		//
		// TODO 即:
		// 		当 bloomTrieCount > 0, 存在 section 时,
		// 		且 存在本地存储的 canonicalHash (`h` + num (uint64 big endian) + hash -> header)
		// 		和  bloom索引器记录在本地的 sectionHead Hash (`shead` + section index (uint64 big endian) -> header Hash)
		//		不一致时
		for bloomTrieCount > 0 && canonicalHash != sectionHead && canonicalHash != (common.Hash{}) {
			// 则, 将section一直往前找 (这时候,可能 只是更新了 bloom 中的 hash 而 存储 db的却还是旧的)
			bloomTrieCount--
			if bloomTrieCount > 0 {

				// 重新拿 新的一个section的最后一个blocknum
				sectionHeadNum = bloomTrieCount*BloomTrieFrequency - 1

				// 分别取回 bloom中的 sectionHead Hash
				sectionHead = odr.BloomTrieIndexer().SectionHead(bloomTrieCount - 1)
				// 和本地存储的 canonicalHash
				canonicalHash = rawdb.ReadCanonicalHash(db, sectionHeadNum)
			}
		}

		//  todo 就这么一直找到最后, 也不管最终有没有找到了, 找到哪,是哪
	}


	// todo 这里又根据 入参的 section index集做处理
	//
	// 遍历sectionId集
	for i, sectionIdx := range sectionIdxList {

		// 现在本地获取对应的 CanonicalHash
		//
		// what? 这里为什么使用 sectionIdx+1 !?
		sectionHead := rawdb.ReadCanonicalHash(db, (sectionIdx+1)*BloomTrieFrequency-1)
		// if we don't have the canonical hash stored for this section head number, we'll still look for
		// an entry with a zero sectionHead (we store it with zero section head too if we don't know it
		// at the time of the retrieval)
		//
		/**
		如果我们没有为该  section head num 存储的 CanonicalHash,
		我们仍将寻找一个带有 零sectionHead hash 的条目
		[如果在检索时我们不知道它,我们也将其存储为零 section head]
		 */
		// 检索来自给定section和bit索引的压缩bloom bit vector (入参, bit index sectionindex, CanonicalHash)
		bloomBits, err := rawdb.ReadBloomBits(db, bitIdx, sectionIdx, sectionHead)
		if err == nil {
			result[i] = bloomBits
		} else {

			// 如果 没查到或者报错了, 首先校验下 sectionIndex 是不是 大于 本地第bloomTrieCount section的num
			//
			// 如果 >= 则,报错,因为没有本地并没有存到 trust checkpoint 的 section 相关信息
			if sectionIdx >= bloomTrieCount {
				return nil, ErrNoTrustedBloomTrie
			}

			// 否则,表示 有trustcheckpoint 但是只是自己本地没查到对应的 bloom bit (可能之前么在本地做过查询该 section bloom 的操作)
			// 则,需要发起 req去server 端 查询
			reqList = append(reqList, sectionIdx)
			reqIdx = append(reqIdx, i)
		}
	}
	if reqList == nil {
		return result, nil
	}


	// TODO 构建 需要server 端查询的 bloomindex req
	r := &BloomRequest{BloomTrieRoot: GetBloomTrieRoot(db, bloomTrieCount-1, sectionHead), BloomTrieNum: bloomTrieCount - 1, BitIdx: bitIdx, SectionIdxList: reqList}

	// todo 发起查询并存储result (里面调用了 StoreResult())
	if err := odr.Retrieve(ctx, r); err != nil {
		return nil, err
	} else {
		for i, idx := range reqIdx {
			result[idx] = r.BloomBits[i]
		}

		// 并将result 返回出去
		return result, nil
	}
}
