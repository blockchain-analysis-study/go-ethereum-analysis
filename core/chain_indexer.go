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

package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/rawdb"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/types"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/ethdb"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/event"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
)

// ChainIndexerBackend defines the methods needed to process chain segments in
// the background and write the segment results into the database. These can be
// used to create filter blooms or CHTs.
type ChainIndexerBackend interface {
	// Reset initiates the processing of a new chain segment, potentially terminating
	// any partially completed operations (in case of a reorg).
	Reset(ctx context.Context, section uint64, prevHead common.Hash) error

	// Process crunches through the next header in the chain segment. The caller
	// will ensure a sequential order of headers.
	Process(ctx context.Context, header *types.Header) error

	// Commit finalizes the section metadata and stores it into the database.
	Commit() error
}

// ChainIndexerChain interface is used for connecting the indexer to a blockchain
type ChainIndexerChain interface {
	// CurrentHeader retrieves the latest locally known header.
	CurrentHeader() *types.Header

	// SubscribeChainEvent subscribes to new head header notifications.
	SubscribeChainEvent(ch chan<- ChainEvent) event.Subscription
}

// ChainIndexer does a post-processing job for equally sized sections of the
// canonical chain (like BlooomBits and CHT structures). A ChainIndexer is
// connected to the blockchain through the event system by starting a
// ChainEventLoop in a goroutine.
//
// Further child ChainIndexers can be added which use the output of the parent
// section indexer. These child indexers receive new head notifications only
// after an entire section has been finished or in case of rollbacks that might
// affect already finished sections.
//
/**
ChainIndexer:
对 规范chain 的大小相等的 section（例如BlooomBits和CHT结构）进行 后置处理。
通过在goroutine中启动 ChainEventLoop() ，ChainIndexer通过事件系统连接到区块链。


可以添加其他子链索引器，这些子链索引器使用父 section索引器的输出。
这些子索引器仅在整个 section 结束或回滚可能影响已经完成的 section 后才接收新的头通知。
 */
type ChainIndexer struct {

	// lightchain的 db
	chainDb  ethdb.Database      // Chain database to index the data from

	// 用于将索引元数据 (light节点相关的索引) 写入数据库
	indexDb  ethdb.Database      // Prefixed table-view of the db to write index metadata into

	// 后台处理器生成索引数据内容
	//
	// todo 三种实现
	// 		BloomIndexer
	// 		BloomTrieIndexer
	//    	ChtIndexer
	backend  ChainIndexerBackend // Background processor generating the index data content

	// 子索引器将链的更新关联起来
	children []*ChainIndexer     // Child indexers to cascade chain updates to

	// 标记事件循环是否已开始
	active    uint32          // Flag whether the event loop was started

	// 通知 headers 应处理的chan
	// 在 `(c *ChainIndexer) newHead()` 和 `(c *ChainIndexer) updateLoop()` 均有发送这个 update 信号
	update    chan struct{}   // Notification channel that headers should be processed

	// 退出信号的chan
	quit      chan chan error // Quit channel to tear down running goroutines
	ctx       context.Context
	ctxCancel func()

	// 单个chain段中要处理的block数 (即: section 多少个block, 一般是 32768个)
	sectionSize uint64 // Number of blocks in a single chain segment to process
	// 处理完成的段之前的确认数 (block的确认数)
	confirmsReq uint64 // Number of confirmations before processing a completed segment

	// todo 成功索引到数据库中的section数
	storedSections uint64 // Number of sections successfully indexed into the database

	// todo 已知要完成的 section 数（按块计算）
	knownSections  uint64 // Number of sections known to be complete (block wise)

	// 最后完成的 section 的 Block number `级联` 到子索引器
	cascadedHead   uint64 // Block number of the last completed section cascaded to subindexers

	// 磁盘节流以防止大量升级占用资源
	throttling time.Duration // Disk throttling to prevent a heavy upgrade from hogging resources

	log  log.Logger
	lock sync.RWMutex
}

// NewChainIndexer creates a new chain indexer to do background processing on
// chain segments of a given size after certain number of confirmations passed.
// The throttling parameter might be used to prevent database thrashing.
/**
NewChainIndexer 函数：
创建一个新的链索引器，在经过一定数量的确认后，
对给定大小的链段进行 `backend` 处理。 限制参数可用于防止数据库抖动。

todo `backend` 主要3种实现
		BloomIndexer
		ChtIndexer  <轻节点需要>
		BloomTrieIndexer <轻节点需要>
 */
func NewChainIndexer(chainDb, indexDb ethdb.Database, backend ChainIndexerBackend, section, confirm uint64, throttling time.Duration, kind string) *ChainIndexer {
	c := &ChainIndexer{
		chainDb:     chainDb,
		indexDb:     indexDb,
		backend:     backend,
		update:      make(chan struct{}, 1),
		quit:        make(chan chan error),
		sectionSize: section,
		confirmsReq: confirm,
		throttling:  throttling,
		log:         log.New("type", kind),
	}
	// Initialize database dependent fields and start the updater
	//
	// 初始化数据库相关字段并启动更新程序
	// todo 从索引数据库中读取有效 section 的数量
	c.loadValidSections()
	c.ctx, c.ctxCancel = context.WithCancel(context.Background())


	// TODO 这里就是 server 和 client 间的相互同步更新的起点
	// todo 实时的处理 新的Bloom Trie 和 CHT Trie
	go c.updateLoop()

	return c
}

// AddKnownSectionHead marks a new section head as known/processed if it is newer
// than the already known best section head
func (c *ChainIndexer) AddKnownSectionHead(section uint64, shead common.Hash) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if section < c.storedSections {
		return
	}

	// 更新最后一个section head:   `shead` + section (uint64 BigEndian) -> hash
	c.setSectionHead(section, shead)
	// 设置数据库中当前有效 sections 的数量
	c.setValidSections(section + 1)
}

// Start creates a goroutine to feed chain head events into the indexer for
// cascading background processing. Children do not need to be started, they
// are notified about new events by their parents.
//
/**
Start:
创建一个goroutine，将 chain head event 馈入 索引器以进行级联后台处理。
孩子不需要开始，父母会通知他们新的活动
 */
func (c *ChainIndexer) Start(chain ChainIndexerChain) {
	events := make(chan ChainEvent, 10)

	// 订阅 new chain header event
	sub := chain.SubscribeChainEvent(events)


	// TODO 监听 update 更新本地 CHT 和 BloomTrie 信号
	go c.eventLoop(chain.CurrentHeader(), events, sub)
}

// Close tears down all goroutines belonging to the indexer and returns any error
// that might have occurred internally.
func (c *ChainIndexer) Close() error {
	var errs []error

	c.ctxCancel()

	// Tear down the primary update loop
	errc := make(chan error)
	c.quit <- errc
	if err := <-errc; err != nil {
		errs = append(errs, err)
	}
	// If needed, tear down the secondary event loop
	if atomic.LoadUint32(&c.active) != 0 {
		c.quit <- errc
		if err := <-errc; err != nil {
			errs = append(errs, err)
		}
	}
	// Close all children
	for _, child := range c.children {
		if err := child.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	// Return any failures
	switch {
	case len(errs) == 0:
		return nil

	case len(errs) == 1:
		return errs[0]

	default:
		return fmt.Errorf("%v", errs)
	}
}

// eventLoop is a secondary - optional - event loop of the indexer which is only
// started for the outermost indexer to push chain head events into a processing
// queue.
func (c *ChainIndexer) eventLoop(currentHeader *types.Header, events chan ChainEvent, sub event.Subscription) {
	// Mark the chain indexer as active, requiring an additional teardown
	atomic.StoreUint32(&c.active, 1)

	defer sub.Unsubscribe()

	// Fire the initial new head event to start any outstanding processing
	//
	// TODO 这里 会发 update 信号
	c.newHead(currentHeader.Number.Uint64(), false)

	var (
		prevHeader = currentHeader
		prevHash   = currentHeader.Hash()
	)
	for {
		select {
		case errc := <-c.quit:
			// Chain indexer terminating, report no failure and abort
			errc <- nil
			return

		case ev, ok := <-events:
			// Received a new event, ensure it's not nil (closing) and update
			if !ok {
				errc := <-c.quit
				errc <- nil
				return
			}
			header := ev.Block.Header()


			// 先找到 公共祖先
			if header.ParentHash != prevHash {
				// Reorg to the common ancestor (might not exist in light sync mode, skip reorg then)
				// TODO(karalabe, zsfelfoldi): This seems a bit brittle, can we detect this case explicitly?

				// TODO(karalabe): This operation is expensive and might block, causing the event system to
				// potentially also lock up. We need to do with on a different thread somehow.
				if h := rawdb.FindCommonAncestor(c.chainDb, prevHeader, header); h != nil {
					// TODO 这里 会发 update 信号
					c.newHead(h.Number.Uint64(), true)
				}
			}

			// TODO 这里 会发 update 信号
			c.newHead(header.Number.Uint64(), false)

			prevHeader, prevHash = header, header.Hash()
		}
	}
}

// newHead notifies the indexer about new chain heads and/or reorgs.
//
/**
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################

todo
	newHead:
	将新chain head 和/或 重组时都 通知索引器。

todo 这里的 update 信号最终会导致,去对端 peer 上拉取 CHT 和 BloomTrie 并更新本地

todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
todo #####################################################
 */
func (c *ChainIndexer) newHead(head uint64, reorg bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// If a reorg happened, invalidate all sections until that point
	//
	// 如果发生重组，请在此之前使所有部分无效
	if reorg {
		// Revert the known section number to the reorg point
		//
		// 将已知的 section number 还原为重组点
		changed := head / c.sectionSize
		if changed < c.knownSections {

			// 查看当前有多少个 已知的 需要完成的 section 数（按块计算）<这里头包含了已经 入库的和还未入库的>
			c.knownSections = changed
		}
		// Revert the stored sections from the database to the reorg point
		//
		// 将已经存储的 sections 从数据库还原到重组点
		if changed < c.storedSections {

			// 将有效的 section 的数量写入索引数据库
			c.setValidSections(changed)
		}
		// Update the new head number to the finalized section end and notify children
		//
		// 将新的 head number 更新到最终确定的  section 的末尾并通知子级 section
		//
		// 老外老喜欢做多余的动作 乘来除去的, 这里算到的head 就是入参的head 啊
		head = changed * c.sectionSize

		if head < c.cascadedHead {
			// 变更 最后完成的 section 的 Block number
			c.cascadedHead = head
			for _, child := range c.children {

				// TODO 这里 会发 update 信号
				// todo 进入递归调整
				child.newHead(c.cascadedHead, true)
			}
		}
		return
	}
	// No reorg, calculate the number of newly known sections and update if high enough
	var sections uint64
	if head >= c.confirmsReq {
		sections = (head + 1 - c.confirmsReq) / c.sectionSize
		if sections > c.knownSections {
			c.knownSections = sections

			select {
			// todo ############################################
			// todo ############################################
			// todo ############################################
			// todo ############################################
			// todo ############################################
			// todo ############################################
			//
			// todo 发起 更新 bloomtrie 和 CHT trie 的更新信号
			//
			// todo ############################################
			// todo ############################################
			// todo ############################################
			// todo ############################################
			// todo ############################################
			// todo ############################################
			case c.update <- struct{}{}:
			default:
			}
		}
	}
}

// updateLoop is the main event loop of the indexer which pushes chain segments
// down into the processing backend.
//
// updateLoop是索引器的主事件循环，该循环将链段 (section !?) 下推到 processing backend。
func (c *ChainIndexer) updateLoop() {
	var (
		updating bool
		updated  time.Time
	)

	for {
		select {
		case errc := <-c.quit:
			// Chain indexer terminating, report no failure and abort
			errc <- nil
			return

		/**
		TODO ##################################
		TODO ##################################
		TODO ##################################
		TODO ##################################
		TODO ##################################

		TODO 接收到 update 信号时

		TODO ##################################
		TODO ##################################
		TODO ##################################
		TODO ##################################
		TODO ##################################

		TODO 这里就是 server 和 client 间的相互同步更新的起点
		 */
		case <-c.update:
			// Section headers completed (or rolled back), update the index
			//
			// todo Section headers 完成（或回滚），更新索引
			c.lock.Lock()

			// todo 当已知的,需要完成的 section数 > 成功检索到db的section数
			if c.knownSections > c.storedSections {
				// Periodically print an upgrade log message to the user
				//
				// 定期向用户打印升级日志消息
				if time.Since(updated) > 8*time.Second {
					if c.knownSections > c.storedSections+1 {
						updating = true
						c.log.Info("Upgrading chain index", "percentage", c.storedSections*100/c.knownSections) // 百分比: 已存储/需要完成 * %
					}
					updated = time.Now()
				}
				// Cache the current section count and head to allow unlocking the mutex
				//
				// 缓存当前的 section 和 head，以允许解锁互斥锁
				section := c.storedSections
				var oldHead common.Hash
				if section > 0 {

					// 向前查找上一个 section 的head
					oldHead = c.SectionHead(section - 1)
				}
				// Process the newly defined section in the background
				c.lock.Unlock()

				/**
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################

				TODO 处理轻节点的  section

				todo 主要是 2 种实现会这么做
					BloomTrieIndexerBackend
					ChtIndexerBackend

				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				todo #######################################
				 */
				newHead, err := c.processSection(section, oldHead)
				if err != nil {
					select {
					case <-c.ctx.Done():
						<-c.quit <- nil
						return
					default:
					}
					c.log.Error("Section processing failed", "error", err)
				}
				c.lock.Lock()

				// If processing succeeded and no reorgs occcurred, mark the section completed
				if err == nil && oldHead == c.SectionHead(section-1) {
					c.setSectionHead(section, newHead)
					c.setValidSections(section + 1)
					if c.storedSections == c.knownSections && updating {
						updating = false
						c.log.Info("Finished upgrading chain index")
					}

					c.cascadedHead = c.storedSections*c.sectionSize - 1
					for _, child := range c.children {
						c.log.Trace("Cascading chain index update", "head", c.cascadedHead)

						// TODO 这里 会发 update 信号
						child.newHead(c.cascadedHead, false)
					}
				} else {
					// If processing failed, don't retry until further notification
					c.log.Debug("Chain index processing failed", "section", section, "err", err)
					c.knownSections = c.storedSections
				}
			}
			// If there are still further sections to process, reschedule
			//
			// 如果还有其他部分要处理，请重新安排时间
			//
			// todo 当已知的,需要完成的 section数 > 成功检索到db的section数
			if c.knownSections > c.storedSections {
				// todo 经过短暂的延迟后,发送 更新 section 的信号
				time.AfterFunc(c.throttling, func() {
					select {

					// todo  超时时, 发起 更新 BloomTrie 和 CHT trie 的信号
					case c.update <- struct{}{}:
					default:
					}
				})
			}
			c.lock.Unlock()
		}
	}
}

// processSection processes an entire section by calling backend functions while
// ensuring the continuity of the passed headers. Since the chain mutex is not
// held while processing, the continuity can be broken by a long reorg, in which
// case the function returns with an error.
//
/**
processSection:
通过调用backend functions <注意: backend 有三种实现> 来处理整个 section，同时确保传递的 head 的连续性。
由于在处理时不保留链互斥锁，因此长时间的重组可能会破坏连续性，在这种情况下，函数将返回错误。
 */
func (c *ChainIndexer) processSection(section uint64, lastHead common.Hash) (common.Hash, error) {
	c.log.Trace("Processing new chain section", "section", section)

	// Reset and partial processing
	//
	// 重置和部分处理
	/**
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################

	todo  这里会构建 发起 检索拉取 证明的 req

	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################
	todo #######################################

	todo 主要是 2 种实现会这么做
		BloomTrieIndexerBackend
		ChtIndexerBackend
	*/
	if err := c.backend.Reset(c.ctx, section, lastHead); err != nil {
		// 重置失败时, 将有效的 section 的数量写入索引数据库, 设置为 0
		c.setValidSections(0)
		return common.Hash{}, err
	}


	// eg. block number 从 1*32768 开始往 2*32768-1 处理
	for number := section * c.sectionSize; number < (section+1)*c.sectionSize; number++ {

		// 逐个拿这个 新的 section 内的 cht block 的hash
		hash := rawdb.ReadCanonicalHash(c.chainDb, number)
		if hash == (common.Hash{}) {
			return common.Hash{}, fmt.Errorf("canonical block #%d unknown", number)
		}

		// 然后去 light chain 上拿 header
		header := rawdb.ReadHeader(c.chainDb, hash, number)
		if header == nil {
			return common.Hash{}, fmt.Errorf("block #%d [%x…] not found", number, hash[:4])
		} else if header.ParentHash != lastHead {
			return common.Hash{}, fmt.Errorf("chain reorged during section processing")
		}

		/**
		todo 超级重要 一般就是 更新 trie (CHTIndexer 和 BloomIndexer)
		 */
		if err := c.backend.Process(c.ctx, header); err != nil {
			return common.Hash{}, err
		}
		lastHead = header.Hash()
	}
	// todo ##########################################
	// todo ##########################################
	// todo ##########################################
	// todo ##########################################
	// todo ##########################################
	// todo ##########################################
	//
	// 这里 server 变更 CHT 这棵树
	//
	// todo 重要Commit 对应的 indexer (CHTIndexer 和 BloomIndexer)
	//
	// todo ##########################################
	// todo ##########################################
	// todo ##########################################
	// todo ##########################################
	// todo ##########################################
	// todo ##########################################

	if err := c.backend.Commit(); err != nil {
		return common.Hash{}, err
	}

	// 返回处理了 新的 section之后的最后一个 block head
	return lastHead, nil
}

// Sections returns the number of processed sections maintained by the indexer
// and also the information about the last header indexed for potential canonical
// verifications.
//
/**
Sections:
	返回由索引器维护的已处理 section 的数量，以及有关为可能的 规范验证 而索引的最后一个 head Hash
 */
func (c *ChainIndexer) Sections() (uint64, uint64, common.Hash) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// todo 返回了
	//  成功索引到数据库中的section数
	//  section中的最后一个的那个block number
	//  最后一个 head的Hash
	return c.storedSections, c.storedSections*c.sectionSize - 1, c.SectionHead(c.storedSections - 1)
}

// AddChildIndexer adds a child ChainIndexer that can use the output of this one
//
/**
AddChildIndexer:
添加一个子ChainIndexer，可以使用此子项的输出
 */
func (c *ChainIndexer) AddChildIndexer(indexer *ChainIndexer) {
	c.lock.Lock()
	defer c.lock.Unlock()


	// 添加新的 子索引器
	c.children = append(c.children, indexer)

	// Cascade any pending updates to new children too
	//
	// 也可以级联对新子级的所有待处理更新
	if c.storedSections > 0 {

		// 这里为什么需要递归调整!?
		// 因为 一般每个 索引器存储处理 一个section也就是 一般是 32768个block !?
		//
		// TODO 这里 会发 update 信号
		// todo 这里将 进入递归调整
		indexer.newHead(c.storedSections*c.sectionSize-1, false)
	}
}

// loadValidSections reads the number of valid sections from the index database
// and caches is into the local state.
//
/**
loadValidSections:
从索引数据库中读取有效 section 的数量，并且缓存进入本地状态
 */
func (c *ChainIndexer) loadValidSections() {
	data, _ := c.indexDb.Get([]byte("count"))
	if len(data) == 8 {
		c.storedSections = binary.BigEndian.Uint64(data[:])
	}
}

// setValidSections writes the number of valid sections to the index database
//
/**
setValidSections:
将有效的 section 的数量写入索引数据库
 */
func (c *ChainIndexer) setValidSections(sections uint64) {
	// Set the current number of valid sections in the database
	//
	// 设置数据库中当前有效 sections 的数量
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], sections)
	c.indexDb.Put([]byte("count"), data[:])

	// Remove any reorged sections, caching the valids in the mean time
	//
	// 删除所有重组的 sections ，同时缓存有效内容
	for c.storedSections > sections {
		// 如果field storedSections 的值 > sections, 说明之前技术记错了,这里应当修正
		c.storedSections--

		// 并且移除掉这些 section的 左后一个block hash
		c.removeSectionHead(c.storedSections)
	}

	// 否则, new > old 时,更新
	c.storedSections = sections // needed if new > old
}

// SectionHead retrieves the last block hash of a processed section from the
// index database.
//
/**
SectionHead:
从索引数据库中检索已处理的 section 的最后一个block Hash。

section是从0开始的


key: shead + sectionNum
value: section last block hash
 */
func (c *ChainIndexer) SectionHead(section uint64) common.Hash {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], section)

	hash, _ := c.indexDb.Get(append([]byte("shead"), data[:]...))
	if len(hash) == len(common.Hash{}) {
		return common.BytesToHash(hash)
	}
	return common.Hash{}
}

// setSectionHead writes the last block hash of a processed section to the index
// database.
//
/**
setSectionHead:
将已处理的 section 的最后一个 block hash 写入索引数据库。

key: shead + sectionNum
value: section last block hash
 */
func (c *ChainIndexer) setSectionHead(section uint64, hash common.Hash) {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], section)

	c.indexDb.Put(append([]byte("shead"), data[:]...), hash.Bytes())
}

// removeSectionHead removes the reference to a processed section from the index
// database.
//
/**
removeSectionHead:
从索引数据库中删除对已处理的 section 的引用。

key: shead + sectionNum
value: section last block hash
 */
func (c *ChainIndexer) removeSectionHead(section uint64) {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], section)

	c.indexDb.Delete(append([]byte("shead"), data[:]...))
}
