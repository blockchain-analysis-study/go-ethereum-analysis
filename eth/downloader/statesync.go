// Copyright 2017 The github.com/go-ethereum-analysis Authors
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

package downloader

import (
	"fmt"
	"hash"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/core/rawdb"
	"github.com/go-ethereum-analysis/core/state"
	"github.com/go-ethereum-analysis/crypto/sha3"
	"github.com/go-ethereum-analysis/ethdb"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/trie"
)

// stateReq represents a batch of state fetch requests grouped together into
// a single data retrieval network packet.
//
/**
stateReq 代表一批 state 获取请求，这些请求被组合到一个数据检索网络数据包中。
 */
type stateReq struct {

	// 同步过来的 state的item的hash
	items    []common.Hash              // Hashes of the state items to download
	// 缓存所有的 同步任务以跟踪 之前的尝试 (什么尝试? 之前去各个peers上拉 state trie node 数据的尝试)
	tasks    map[common.Hash]*stateTask // Download tasks to track previous attempts
	// 完成此操作所需的最大往返时间
	timeout  time.Duration              // Maximum round trip time for this to complete
	// RTT超时到期时触发计时器
	timer    *time.Timer                // Timer to fire when the RTT timeout expires
	// 表示 当前peer 请求回来的对端peer
	peer     *peerConnection            // Peer that we're requesting from
	// 对端peer的响应数据（超时为零）
	response [][]byte                   // Response data of the peer (nil for timeouts)
	// 标记 对端peer 是否 提早被移除
	dropped  bool                       // Flag whether the peer dropped off early
}

// timedOut returns if this request timed out.
func (req *stateReq) timedOut() bool {
	return req.response == nil
}

// stateSyncStats is a collection of progress stats to report during a state trie
// sync to RPC requests as well as to display in user logs.
type stateSyncStats struct {
	processed  uint64 // Number of state entries processed
	duplicate  uint64 // Number of state entries downloaded twice
	unexpected uint64 // Number of non-requested state entries received
	pending    uint64 // Number of still pending state entries
}

// syncState starts downloading state with the given root hash.
//
// syncState开始使用给定的root哈希值下载state
func (d *Downloader) syncState(root common.Hash) *stateSync {
	s := newStateSync(d, root)
	select {
	case d.stateSyncStart <- s:
	case <-d.quitCh:
		s.err = errCancelStateFetch
		close(s.done)
	}
	return s
}

// stateFetcher manages the active state sync and accepts requests
// on its behalf.
//
// stateFetcher管理活动state同步并代表其接受请求
func (d *Downloader) stateFetcher() {
	for {
		select {
		// 接收到发起的同步state的信号
		case s := <-d.stateSyncStart:
			for next := s; next != nil; {

				// 将运行state同步，直到完成同步或请求将另一个 root 哈希切换到该state
				next = d.runStateSync(next)
			}
		case <-d.stateCh:
			// Ignore state responses while no sync is running.
		case <-d.quitCh:
			return
		}
	}
}

// runStateSync runs a state synchronisation until it completes or another root
// hash is requested to be switched over to.
//
// runStateSync将运行state同步，直到完成同步或请求将另一个 root 哈希切换到该state
func (d *Downloader) runStateSync(s *stateSync) *stateSync {
	var (
		active   = make(map[string]*stateReq) // Currently in-flight requests      	当前进行中的请求
		finished []*stateReq                  // Completed or failed requests		完成或失败的请求
		timeout  = make(chan *stateReq)       // Timed out active requests			活动请求超时
	)
	defer func() {
		// Cancel active request timers on exit. Also set peers to idle so they're
		// available for the next sync.
		//
		// 退出时,取消活动的请求计时器。 还要将 peer 设置为空闲，以便下次同步时可用。
		for _, req := range active {
			req.timer.Stop()
			req.peer.SetNodeDataIdle(len(req.items))
		}
	}()
	// Run the state sync.
	go s.run()   // todo 这个 是真的 state 同步
	defer s.Cancel()

	// Listen for peer departure events to cancel assigned tasks
	peerDrop := make(chan *peerConnection, 1024)
	peerSub := s.d.peers.SubscribePeerDrops(peerDrop)
	defer peerSub.Unsubscribe()

	for {
		// Enable sending of the first buffered element if there is one.
		var (
			deliverReq   *stateReq
			deliverReqCh chan *stateReq
		)
		if len(finished) > 0 {
			deliverReq = finished[0]
			deliverReqCh = s.deliver
		}

		select {
		// The stateSync lifecycle:
		case next := <-d.stateSyncStart:
			return next

		case <-s.done:
			return nil

		// Send the next finished request to the current sync:
		case deliverReqCh <- deliverReq:
			// Shift out the first request, but also set the emptied slot to nil for GC
			copy(finished, finished[1:])
			finished[len(finished)-1] = nil
			finished = finished[:len(finished)-1]

		// Handle incoming state packs:
		case pack := <-d.stateCh:
			// Discard any data not requested (or previously timed out)
			req := active[pack.PeerId()]
			if req == nil {
				log.Debug("Unrequested node data", "peer", pack.PeerId(), "len", pack.Items())
				continue
			}
			// Finalize the request and queue up for processing
			req.timer.Stop()
			req.response = pack.(*statePack).states

			finished = append(finished, req)
			delete(active, pack.PeerId())

			// Handle dropped peer connections:
		case p := <-peerDrop:
			// Skip if no request is currently pending
			req := active[p.id]
			if req == nil {
				continue
			}
			// Finalize the request and queue up for processing
			req.timer.Stop()
			req.dropped = true

			finished = append(finished, req)
			delete(active, p.id)

		// Handle timed-out requests:
		case req := <-timeout:
			// If the peer is already requesting something else, ignore the stale timeout.
			// This can happen when the timeout and the delivery happens simultaneously,
			// causing both pathways to trigger.
			if active[req.peer.id] != req {
				continue
			}
			// Move the timed out data back into the download queue
			finished = append(finished, req)
			delete(active, req.peer.id)

		// Track outgoing state requests:
		case req := <-d.trackStateReq:
			// If an active request already exists for this peer, we have a problem. In
			// theory the trie node schedule must never assign two requests to the same
			// peer. In practice however, a peer might receive a request, disconnect and
			// immediately reconnect before the previous times out. In this case the first
			// request is never honored, alas we must not silently overwrite it, as that
			// causes valid requests to go missing and sync to get stuck.
			if old := active[req.peer.id]; old != nil {
				log.Warn("Busy peer assigned new state fetch", "peer", old.peer.id)

				// Make sure the previous one doesn't get siletly lost
				old.timer.Stop()
				old.dropped = true

				finished = append(finished, old)
			}
			// Start a timer to notify the sync loop if the peer stalled.
			req.timer = time.AfterFunc(req.timeout, func() {
				select {
				case timeout <- req:
				case <-s.done:
					// Prevent leaking of timer goroutines in the unlikely case where a
					// timer is fired just before exiting runStateSync.
				}
			})
			active[req.peer.id] = req
		}
	}
}

// stateSync schedules requests for downloading a particular state trie defined
// by a given state root.
//
/**
stateSync 计划请求那种根据给定的root 定义特定state的下载任务
 */
type stateSync struct {
	// Downloader实例引用 为了访问和管理当前 peerSet
	d *Downloader // Downloader instance to access and manage current peerset

	// State的trie同步调度而定义任务
	sched  *trie.Sync                 // State trie sync scheduler defining the tasks
	// Keccak256哈希器 去做验证交付
	keccak hash.Hash                  // Keccak256 hasher to verify deliveries with
	// 当前队列等待检索的任务集 (这个应该是查看该 state trie node hash 同步的任务已经发给了 哪些 peer)
	tasks  map[common.Hash]*stateTask // Set of tasks currently queued for retrieval

	/**
	计数器
	 */
	numUncommitted   int
	bytesUncommitted int

	// 交付通道 (Delivery channel) 处理多路复用对等响应
	// 代表一批 state 获取请求，这些请求被组合到一个数据检索网络数据包中
	deliver    chan *stateReq // Delivery channel multiplexing peer responses
	// 发出终止请求信号的通道
	cancel     chan struct{}  // Channel to signal a termination request
	// 确保取消仅一次被调用
	cancelOnce sync.Once      // Ensures cancel only ever gets called once
	// 发出完成信号的通道
	done       chan struct{}  // Channel to signal termination completion
	// 接受任何在 sync 过程中出现的 error
	err        error          // Any error hit during sync (set before completion)

}

// stateTask represents a single trie node download task, containing a set of
// peers already attempted retrieval from to detect stalled syncs and abort.
//
/**
stateTask表示单个trie节点下载任务，其中包含一组已经尝试从中检索以检测停止的同步和中止的 peers。
 */
type stateTask struct {
	// 缓存 peerId
	attempts map[string]struct{}
}

// newStateSync creates a new state trie download scheduler. This method does not
// yet start the sync. The user needs to call run to initiate.
func newStateSync(d *Downloader, root common.Hash) *stateSync {
	return &stateSync{
		d:       d,
		sched:   state.NewStateSync(root, d.stateDB),
		keccak:  sha3.NewKeccak256(),
		tasks:   make(map[common.Hash]*stateTask),
		deliver: make(chan *stateReq),
		cancel:  make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// run starts the task assignment and response processing loop, blocking until
// it finishes, and finally notifying any goroutines waiting for the loop to
// finish.
//
/**
run启动任务分配和响应处理循环，阻塞直到完成，最后通知所有等待循环的goroutine。
 */
func (s *stateSync) run() {
	s.err = s.loop()
	close(s.done)
}

// Wait blocks until the sync is done or canceled.
func (s *stateSync) Wait() error {
	<-s.done
	return s.err
}

// Cancel cancels the sync and waits until it has shut down.
func (s *stateSync) Cancel() error {
	s.cancelOnce.Do(func() { close(s.cancel) })
	return s.Wait()
}

// loop is the main event loop of a state trie sync. It it responsible for the
// assignment of new tasks to peers (including sending it to them) as well as
// for the processing of inbound data. Note, that the loop does not directly
// receive data from peers, rather those are buffered up in the downloader and
// pushed here async. The reason is to decouple processing from data receipt
// and timeouts.
//
/**
TODO loop是state Trie同步的主要事件循环。
它负责将新任务分配给 对端peers（包括将其发送给 peers）以及入站数据的处理。

请注意，循环不会直接从 对端的 peers 接收数据，而是将这些数据在downloader中缓冲并异步推送到此处。
原因是将数据接收和超时 解耦处理。
 */
func (s *stateSync) loop() (err error) {
	// Listen for new peer events to assign tasks to them
	//
	// 侦听新的peer 事件并分配任务给它
	newPeer := make(chan *peerConnection, 1024)
	peerSub := s.d.peers.SubscribeNewPeers(newPeer)
	defer peerSub.Unsubscribe()
	defer func() {
		// 这里处理 state 同步过来的数据 刷到 leveldb
		cerr := s.commit(true)
		if err == nil {
			err = cerr
		}
	}()

	// Keep assigning new tasks until the sync completes or aborts
	//
	// 继续分配新任务，直到同步完成或中止
	for s.sched.Pending() > 0 { // 如果当前调度器中的 同步请求数目 > 0

		/** TODO 大头, 这里处理 state 同步过来的数据 刷到 leveldb  */
		if err = s.commit(false); err != nil {
			return err
		}

		/** todo  */
		s.assignTasks()
		// Tasks assigned, wait for something to happen
		select {
		case <-newPeer:
			// New peer arrived, try to assign it download tasks

		case <-s.cancel:
			return errCancelStateFetch

		case <-s.d.cancelCh:
			return errCancelStateFetch

		case req := <-s.deliver:
			// Response, disconnect or timeout triggered, drop the peer if stalling
			log.Trace("Received node data response", "peer", req.peer.id, "count", len(req.response), "dropped", req.dropped, "timeout", !req.dropped && req.timedOut())
			if len(req.items) <= 2 && !req.dropped && req.timedOut() {
				// 2 items are the minimum requested, if even that times out, we've no use of
				// this peer at the moment.
				log.Warn("Stalling state sync, dropping peer", "peer", req.peer.id)
				s.d.dropPeer(req.peer.id)
			}
			// Process all the received blobs and check for stale delivery
			if err = s.process(req); err != nil {
				log.Warn("Node data write error", "err", err)
				return err
			}
			req.peer.SetNodeDataIdle(len(req.response))
		}
	}
	return nil
}

// 这里处理 state 同步过来的数据 刷到 leveldb
func (s *stateSync) commit(force bool) error {
	if !force && s.bytesUncommitted < ethdb.IdealBatchSize {
		return nil
	}
	start := time.Now()

	// 获取 leveldb 的batch 实例
	b := s.d.stateDB.NewBatch()

	/** todo 大头, 处理 state 同步过来的数据 刷到 leveldb */
	if written, err := s.sched.Commit(b); written == 0 || err != nil {
		// 如果写到 batch 中的条目数为0 或者 err 不为空,都直接返回
		return err
	}
	// 将同步过来的数据 (batch中的数据,刷入 leveldb
	if err := b.Write(); err != nil {
		return fmt.Errorf("DB write error: %v", err)
	}

	// 刷新 相关统计数据
	s.updateStats(s.numUncommitted, 0, 0, time.Since(start))
	// 置空 没有commit(写入db)的数据条目数 和 置空 没有commit(写入db)的数据byte数
	s.numUncommitted = 0
	s.bytesUncommitted = 0
	return nil
}

// assignTasks attempts to assign new tasks to all idle peers, either from the
// batch currently being retried, or fetching new data from the trie sync itself.
//
// AssignTasks尝试将新任务分配给具有空闲 peers，这些任务是从当前正在重试的 batch中，或者是从trie同步本身中获取新数据。
func (s *stateSync) assignTasks() {
	// Iterate over all idle peers and try to assign them state fetches
	//
	// 遍历所有空闲 peer，并尝试分配 state获取
	peers, _ := s.d.peers.NodeDataIdlePeers()
	for _, p := range peers {
		// Assign a batch of fetches proportional to the estimated latency/bandwidth
		cap := p.NodeDataCapacity(s.d.requestRTT())
		req := &stateReq{peer: p, timeout: s.d.requestTTL()}
		s.fillTasks(cap, req)

		// If the peer was assigned tasks to fetch, send the network request
		if len(req.items) > 0 {
			req.peer.log.Trace("Requesting new batch of data", "type", "state", "count", len(req.items))
			select {
			case s.d.trackStateReq <- req:

				/** todo  去对端peer 请求 state trie node 的数据 */
				req.peer.FetchNodeData(req.items)
			case <-s.cancel:
			case <-s.d.cancelCh:
			}
		}
	}
}

// fillTasks fills the given request object with a maximum of n state download
// tasks to send to the remote peer.
func (s *stateSync) fillTasks(n int, req *stateReq) {
	// Refill available tasks from the scheduler.
	if len(s.tasks) < n {
		new := s.sched.Missing(n - len(s.tasks))
		for _, hash := range new {
			s.tasks[hash] = &stateTask{make(map[string]struct{})}
		}
	}
	// Find tasks that haven't been tried with the request's peer.
	req.items = make([]common.Hash, 0, n)
	req.tasks = make(map[common.Hash]*stateTask, n)
	for hash, t := range s.tasks {
		// Stop when we've gathered enough requests
		if len(req.items) == n {
			break
		}
		// Skip any requests we've already tried from this peer
		if _, ok := t.attempts[req.peer.id]; ok {
			continue
		}
		// Assign the request to this peer
		t.attempts[req.peer.id] = struct{}{}
		req.items = append(req.items, hash)
		req.tasks[hash] = t
		delete(s.tasks, hash)
	}
}

// process iterates over a batch of delivered state data, injecting each item
// into a running state sync, re-queuing any items that were requested but not
// delivered.
func (s *stateSync) process(req *stateReq) error {
	// Collect processing stats and update progress if valid data was received
	duplicate, unexpected := 0, 0

	defer func(start time.Time) {
		if duplicate > 0 || unexpected > 0 {
			s.updateStats(0, duplicate, unexpected, time.Since(start))
		}
	}(time.Now())

	// Iterate over all the delivered data and inject one-by-one into the trie
	progress := false

	for _, blob := range req.response {
		prog, hash, err := s.processNodeData(blob)
		switch err {
		case nil:

			// todo 计数器!?
			s.numUncommitted++
			s.bytesUncommitted += len(blob)


			progress = progress || prog
		case trie.ErrNotRequested:
			unexpected++
		case trie.ErrAlreadyProcessed:
			duplicate++
		default:
			return fmt.Errorf("invalid state node %s: %v", hash.TerminalString(), err)
		}
		if _, ok := req.tasks[hash]; ok {
			delete(req.tasks, hash)
		}
	}
	// Put unfulfilled tasks back into the retry queue
	npeers := s.d.peers.Len()
	for hash, task := range req.tasks {
		// If the node did deliver something, missing items may be due to a protocol
		// limit or a previous timeout + delayed delivery. Both cases should permit
		// the node to retry the missing items (to avoid single-peer stalls).
		if len(req.response) > 0 || req.timedOut() {
			delete(task.attempts, req.peer.id)
		}
		// If we've requested the node too many times already, it may be a malicious
		// sync where nobody has the right data. Abort.
		if len(task.attempts) >= npeers {
			return fmt.Errorf("state node %s failed with all peers (%d tries, %d peers)", hash.TerminalString(), len(task.attempts), npeers)
		}
		// Missing item, place into the retry queue.
		s.tasks[hash] = task
	}
	return nil
}

// processNodeData tries to inject a trie node data blob delivered from a remote
// peer into the state trie, returning whether anything useful was written or any
// error occurred.
func (s *stateSync) processNodeData(blob []byte) (bool, common.Hash, error) {
	res := trie.SyncResult{Data: blob}
	s.keccak.Reset()
	s.keccak.Write(blob)
	s.keccak.Sum(res.Hash[:0])
	committed, _, err := s.sched.Process([]trie.SyncResult{res})
	return committed, res.Hash, err
}

// updateStats bumps the various state sync progress counters and displays a log
// message for the user to see.
func (s *stateSync) updateStats(written, duplicate, unexpected int, duration time.Duration) {
	s.d.syncStatsLock.Lock()
	defer s.d.syncStatsLock.Unlock()

	s.d.syncStatsState.pending = uint64(s.sched.Pending())
	s.d.syncStatsState.processed += uint64(written)
	s.d.syncStatsState.duplicate += uint64(duplicate)
	s.d.syncStatsState.unexpected += uint64(unexpected)

	if written > 0 || duplicate > 0 || unexpected > 0 {
		log.Info("Imported new state entries", "count", written, "elapsed", common.PrettyDuration(duration), "processed", s.d.syncStatsState.processed, "pending", s.d.syncStatsState.pending, "retry", len(s.tasks), "duplicate", s.d.syncStatsState.duplicate, "unexpected", s.d.syncStatsState.unexpected)
	}
	if written > 0 {
		rawdb.WriteFastTrieProgress(s.d.stateDB, s.d.syncStatsState.processed)
	}
}
