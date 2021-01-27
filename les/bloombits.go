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

package les

import (
	"time"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common/bitutil"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/light"
)

const (
	// bloomServiceThreads is the number of goroutines used globally by an Ethereum
	// instance to service bloombits lookups for all running filters.
	//
	// bloomServiceThreads: 是以太坊实例全局用于为所有正在运行的过滤器提供Bloombits查找服务的goroutine数量
	bloomServiceThreads = 16

	// bloomFilterThreads is the number of goroutines used locally per filter to
	// multiplex requests onto the global servicing goroutines.
	//
	// bloomFilterThreads: 是每个过滤器本地用于将请求多路复用到全局服务goroutine的goroutine的数量
	bloomFilterThreads = 3

	// bloomRetrievalBatch is the maximum number of bloom bit retrievals to service
	// in a single batch.
	//
	// bloomRetrievalBatch: 是单个批处理中可服务的最大bloom位检索数
	bloomRetrievalBatch = 16

	// bloomRetrievalWait is the maximum time to wait for enough bloom bit requests
	// to accumulate request an entire batch (avoiding hysteresis).
	//
	// bloomRetrievalWait: 是等待足够的bloom位请求以累积整个批次请求的最大时间（避免滞后）
	bloomRetrievalWait = time.Microsecond * 100
)

// startBloomHandlers starts a batch of goroutines to accept bloom bit database
// retrievals from possibly a range of filters and serving the data to satisfy.
func (eth *LightEthereum) startBloomHandlers() {

	// 默认全局开启 16 个 goroutine
	for i := 0; i < bloomServiceThreads; i++ {
		go func() {
			for {
				select {
				case <-eth.shutdownChan:
					return

				// todo 接收到 bloom过滤器 bit 检索的 req
				case request := <-eth.bloomRequests:
					task := <-request
					task.Bitsets = make([][]byte, len(task.Sections))

					// 拉取响应的 Bloom bits
					compVectors, err := light.GetBloomBits(task.Context, eth.odr, task.Bit, task.Sections)
					if err == nil {
						for i := range task.Sections {
							if blob, err := bitutil.DecompressBytes(compVectors[i], int(light.BloomTrieFrequency/8)); err == nil {
								task.Bitsets[i] = blob
							} else {
								task.Error = err
							}
						}
					} else {
						task.Error = err
					}

					// todo 将 结果,发送回去
					request <- task
				}
			}
		}()
	}
}
