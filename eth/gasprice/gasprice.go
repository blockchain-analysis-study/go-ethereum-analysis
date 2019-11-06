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

package gasprice

import (
	"context"
	"math/big"
	"sort"
	"sync"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core/types"
	"github.com/go-ethereum-analysis/internal/ethapi"
	"github.com/go-ethereum-analysis/params"
	"github.com/go-ethereum-analysis/rpc"
)

var maxPrice = big.NewInt(500 * params.Shannon)

type Config struct {
	Blocks     int // 表示 多少个block ， 默认20个， 给预言机用
	Percentile int // 表示 百分比，默认 60， 预言机用
	Default    *big.Int `toml:",omitempty"`
}

// Oracle recommends gas prices based on the content of recent
// blocks. Suitable for both light and full clients.
/**
预言机

根据最近数据块的内容建议gas价格。 适用于轻量级客户和全面客户。
 */
type Oracle struct {
	backend   ethapi.Backend
	lastHead  common.Hash
	lastPrice *big.Int
	cacheLock sync.RWMutex
	fetchLock sync.Mutex

	checkBlocks, maxEmpty, maxBlocks int
	percentile                       int
}

// NewOracle returns a new oracle.
func NewOracle(backend ethapi.Backend, params Config) *Oracle {

	// 获取 blocks 个数， 为了做gasPrice 建议时，预言机 计算用
	blocks := params.Blocks
	if blocks < 1 {
		blocks = 1
	}
	percent := params.Percentile
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return &Oracle{
		backend:     backend,
		lastPrice:   params.Default,
		checkBlocks: blocks, // 最多往前遍历多少个block
		maxEmpty:    blocks / 2,  // 最多允许多少个 empty 的gasPrice结果
		maxBlocks:   blocks * 5,  // 假设需要继续遍历，则做多遍历到多少个block 的上限
		percentile:  percent, // 累加block中txs 的gasPrice 的百分比
	}
}

// SuggestPrice returns the recommended gas price.
// 返回交易的gasPrice
//
// 有点 概率学和统计学的意思
func (gpo *Oracle) SuggestPrice(ctx context.Context) (*big.Int, error) {
	gpo.cacheLock.RLock()
	lastHead := gpo.lastHead
	lastPrice := gpo.lastPrice
	gpo.cacheLock.RUnlock()

	// 返回链上最高块header
	head, _ := gpo.backend.HeaderByNumber(ctx, rpc.LatestBlockNumber)
	headHash := head.Hash()
	// 如果当前最高块没变，则不需要重新计算
	if headHash == lastHead {
		return lastPrice, nil
	}

	gpo.fetchLock.Lock()
	defer gpo.fetchLock.Unlock()

	// try checking the cache again, maybe the last fetch fetched what we need
	// 尝试再次检查缓存，也许最后一次提取获取了我们需要的内容
	// TODO 防止并发时的脏读?
	gpo.cacheLock.RLock()
	lastHead = gpo.lastHead
	lastPrice = gpo.lastPrice
	gpo.cacheLock.RUnlock()
	if headHash == lastHead {
		return lastPrice, nil
	}

	blockNum := head.Number.Uint64()
	ch := make(chan getBlockPricesResult, gpo.checkBlocks)
	sent := 0 // 计数器
	exp := 0  // 计数器

	// 收集 前checkBlocks个区块中的tx 的gasPrice
	var blockPrices []*big.Int

	// 一直从当前块往前遍历 checkBlocks 个区块的tx 中的gasPrice
	for sent < gpo.checkBlocks && blockNum > 0 {

		// 使用了 chan ，则增加了gasPrice 到达的随机性，进而做到随机 预言gasPrice
		go gpo.getBlockPrices(ctx, types.MakeSigner(gpo.backend.ChainConfig(), big.NewInt(int64(blockNum))), blockNum, ch)
		sent++
		exp++
		blockNum--
	}
	maxEmpty := gpo.maxEmpty // 最多允许多少个 empty 的gasPrice结果到达
	for exp > 0 {
		res := <-ch
		if res.err != nil {
			return lastPrice, res.err
		}
		exp--

		// 根据随机到达的gasPrice 收集起来
		if res.price != nil {
			blockPrices = append(blockPrices, res.price)
			continue
		}

		// 如果遇到 nil 的gasPrice， 则递减 允许空 的计数器
		if maxEmpty > 0 {
			maxEmpty--
			continue
		}

		// 如果存在太多为empty 的gasPrice ，则我们需要继续遍历block
		if blockNum > 0 && sent < gpo.maxBlocks {
			// 从上次最后遍历到的block 作为新的起点继续往前遍历 到maxBlocks 为止
			go gpo.getBlockPrices(ctx, types.MakeSigner(gpo.backend.ChainConfig(), big.NewInt(int64(blockNum))), blockNum, ch)
			sent++
			exp++
			blockNum--
		}
	}


	price := lastPrice  // 获取当前链上最高块的gasPrice 作为计算基准默认值

	// 如果获取到了前N个block中的txs 的gasPrice的和，则中百分比出取出一个gasPrice 作为新的计算基准
	if len(blockPrices) > 0 {
		sort.Sort(bigIntArray(blockPrices))
		price = blockPrices[(len(blockPrices)-1)*gpo.percentile/100]
	}
	// 比较边界值，刷新 计算基准
	if price.Cmp(maxPrice) > 0 {
		price = new(big.Int).Set(maxPrice)
	}

	gpo.cacheLock.Lock()
	// 更新 预言机中记录的 header
	gpo.lastHead = headHash
	gpo.lastPrice = price // 得到 建议的gasPrice
	gpo.cacheLock.Unlock()
	return price, nil
}

type getBlockPricesResult struct {
	price *big.Int
	err   error
}

type transactionsByGasPrice []*types.Transaction

func (t transactionsByGasPrice) Len() int           { return len(t) }
func (t transactionsByGasPrice) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }
func (t transactionsByGasPrice) Less(i, j int) bool { return t[i].GasPrice().Cmp(t[j].GasPrice()) < 0 }

// getBlockPrices calculates the lowest transaction gas price in a given block
// and sends it to the result channel. If the block is empty, price is nil.
//
// getBlockPrices计算给定区块中的最低交易天然气价格，并将其发送到结果 chan。 如果该块为空，则价格为零。
func (gpo *Oracle) getBlockPrices(ctx context.Context, signer types.Signer, blockNum uint64, ch chan getBlockPricesResult) {

	// 根据 number 返回 block
	block, err := gpo.backend.BlockByNumber(ctx, rpc.BlockNumber(blockNum))
	if block == nil {
		ch <- getBlockPricesResult{nil, err}
		return
	}

	blockTxs := block.Transactions()
	txs := make([]*types.Transaction, len(blockTxs))
	copy(txs, blockTxs)
	// 将 block 中的txs 根据 gasPrice 做排序
	sort.Sort(transactionsByGasPrice(txs))

	// 遍历所有 txs ，并收集非该block coinbase 的tx  sender的tx 的gasPrice
	for _, tx := range txs {
		sender, err := types.Sender(signer, tx)
		if err == nil && sender != block.Coinbase() {

			// 每一笔tx 都发一次
			ch <- getBlockPricesResult{tx.GasPrice(), nil}
			return
		}
	}
	ch <- getBlockPricesResult{nil, nil}
}

type bigIntArray []*big.Int

func (s bigIntArray) Len() int           { return len(s) }
func (s bigIntArray) Less(i, j int) bool { return s[i].Cmp(s[j]) < 0 }
func (s bigIntArray) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
