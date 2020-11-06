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
todo 超级重要的一个req
stateReq 代表一批 state 获取请求，这些请求被组合到一个数据检索网络数据包中。
 */
type stateReq struct {

	// 准备去 同步的 state 的 item 的hash
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
// todo 同步StateDB数据
//
// syncState开始使用给定的root哈希值下载state
func (d *Downloader) syncState(root common.Hash) *stateSync {
	s := newStateSync(d, root)
	select {
	case d.stateSyncStart <- s:  /** todo 发送state 同步信号 */
	case <-d.quitCh:
		s.err = errCancelStateFetch

		// 退出同步时,关闭完成通道
		close(s.done)
	}
	return s
}

// stateFetcher manages the active state sync and accepts requests
// on its behalf.
//
// stateFetcher() 管理活动state同步并代表其接受请求
func (d *Downloader) stateFetcher() {  // 在 New Downloader 时, 起一个 协程调用
	for {
		select {
		/**
		TODO 超级重要
		TODO 接收到发起的同步state的信号

		这是第一次接收到的入口, 后续都是  d.runStateSync(next) 里头接收到了
		 */
		case s := <-d.stateSyncStart:   // todo 收到 pivot block 的 statedb 的同步信号

			// 为什么这么写？
			//
			// todo 原因: d.syncState() 会因为 pivot 的变化而被多次调用. 那么每次  d.stateSyncStart通道 收到的 s 都会是不一样的,
			//		这时候,  就 可能进入了 新的 for next ...  todo 里面会有一句:  go s.run() 才是真正的去同步 statedb ...
			//
			//  代码这么写是为了在同步某个 state 数据的同时，能够及时发现新的 state 同步请求并进行处理，而处理方式就是停掉之前的同步进程.
			//	（注意 Downloader.runStateSync 中 defer s.Cancel() 这条语句），然后返回新的请求并重新调用 Downloader.runStateSync 进行处理.
			//
			//  从而做到, 在整个区块同步过程中，同一时间只有一个区块的 state 数据被同步；如果要同步新的 state，需要先停掉旧的同步过程.
			//
			/**
			todo 注意:

			（在 Downloader.processFastSyncContent 中发起新的 state 同步之前，已经调用了 stateSync.Cannel 方法，并且这个方法会一直等待同步过程真的退出了才会返回.
			因此我认为代码实际运行时，Downloader.runStateSync 方法中应该接收到 stateSync.done 的消息的概率远大于 收到 Downloader.stateSyncStart 消息的概率，
			甚至没有必要在 Downloader.stateFetcher 中弄一个 for 循环和在 Downloader.runStateSync 中接收处理 Downloader.stateSyncStart 消息.）

			（无论如何，我都觉得 Downloader.stateFetcher 中的这个 for 循环设计得相当另类，完全有其它更清淅的方法实现同步的功能和逻辑）
			 */
			for next := s; next != nil; {

				// 将运行state同步，直到完成同步或请求将另一个 root 哈希切换到该state
				next = d.runStateSync(next)  // 这里面也监听了  `d.stateSyncStart`
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
//
// todo 这个方法是连接接收返回的 state 数据和 stateSync 对象的中枢，它记录 stateSync 对象发出的请求，并将对方返回的数据传送给 stateSync 对象.
//
func (d *Downloader) runStateSync(s *stateSync) *stateSync {
	var (
		// 正在处理中的请求集合
		// todo 这个相当有用,用来记录是否活跃
		active   = make(map[string]*stateReq) // Currently in-flight requests

		// 已经完成的请求集合（不管成功或失败）
		finished []*stateReq                  // Completed or failed requests

		// 如果正在处理的请求发生超时，使用这个 channel 进行通知
		timeout  = make(chan *stateReq)       // Timed out active requests
	)
	defer func() {
		// Cancel active request timers on exit. Also set peers to idle so they're
		// available for the next sync.
		//
		/**
		退出时取消活动的请求计时器。 还要将对等端设置为空闲，以便下次同步时可用。
		 */
		for _, req := range active {
			req.timer.Stop()
			// 将对应req中的 peer 设置为空闲
			req.peer.SetNodeDataIdle(len(req.items))
		}
	}()
	// Run the state sync.
	go s.run()   /** todo 这个 是真的 state 同步 */
	defer s.Cancel() // 代码这么写是为了在同步某个 state 数据的同时，能够及时发现新的 state 同步请求并进行处理，而处理方式就是停掉之前的同步进程 ...

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
		// The stateSync lifecycle:    在外面调用 当前本方法: runStateSync() 的地方, 也监听了 d.stateSyncStart
		case next := <-d.stateSyncStart:   // todo 在 执行 statedb 的 同步过程中, 收到了新的 pivot block 的 statedb 的同步信号
			return next		// 收到然后 立马将信号返回出去

		case <-s.done:  // 代表 state 同步完成了 ...
			return nil

		// Send the next finished request to the current sync:
		case deliverReqCh <- deliverReq:   // 不管是正常接收到数据还是超时，都会将结果写入 finished 变量中，然后就该 deliverReqCh 发挥作用了

			// 因为 deliverReqCh 是 for 循环的内部变量，因此循环一遍，deliverReqCh 都会被重新定义.
			// 		如果有完成的请求（finished 的长度大于 0），则 deliverReqCh 的值为 stateSync.deliver， 而另一个局部变量 deliverReq 的值为 finished 的第一个元素;
			// 		否则 deliverReqCh 和 deliverReq 都为默认值 nil.
			//
			// 接下来在 select/case 语句中，如果 deliverReqCh 和 deliverReq 两个变量都是有效值，
			// 那么 deliverReq 中的值就会发送给 deliverReqCh，也就是说 finished 集合中的第一个已完成的请求就会发送给 stateSync.deliver.
			// 而消息处理中则将 finished 中的第一个元素抹掉（因为这个元素已经通知给 stateSync.deliver 了）.
			//
			//
			// 可以看到，deliverReqCh 这个 channel 实际上是为了将已经完成的请求发送给 stateSync.deliver.

			// Shift out the first request, but also set the emptied slot to nil for GC
			copy(finished, finished[1:])
			finished[len(finished)-1] = nil
			finished = finished[:len(finished)-1]

		// Handle incoming state packs:
		case pack := <-d.stateCh:   // 成功接收到 req 的数据

			// 当 eth 模块接收到 「NodeDataMsg」消息时会调用 Downloader.DeliverNodeData() 方法，而 Downloader.stateCh 正在在这个方法中被触发的.
			//
			// 接收到 对端peer 返回的数据后，首先判断是否在 active 中.
			// 如果在则将返回的数据放到 req.response 中，并将 req 写入 finished 中，然后从 active中删除.


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
		case p := <-peerDrop:   // 代表 有节点 断开连接了，因此要作一些相应的处理
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
		//
		// 处理超时的请求
		case req := <-timeout:

			// 当 timeout 收到消息时，代表某个请求超时了 ...
			//
			// 如果超时的请求在 active 中，则将其从 active 中删除，并将其加入到 finished 中（完成但失败了）...

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
		//
		// 跟踪传出 state req：
		case req := <-d.trackStateReq:  // 首先接收到的消息是 Downloader.trackStateReq，它实际上代表 stateSync 对象发起了一次请求


			// 收到请求数据 req 后，首先通过 active 判断这个节点是否有正在处理的请求，
			// 如果是则将旧的请求中断并加入 finished中（完成但失败了）.
			// 然后为新的 req 设置一个 timer 后，将 req 加入到 active 中.


			// If an active request already exists for this peer, we have a problem. In
			// theory the trie node schedule must never assign two requests to the same
			// peer. In practice however, a peer might receive a request, disconnect and
			// immediately reconnect before the previous times out. In this case the first
			// request is never honored, alas we must not silently overwrite it, as that
			// causes valid requests to go missing and sync to get stuck.
			//
			/**
			如果此 peer 已经存在活动请求(active req)，则我们有问题。
			理论上，state trie node 的调度程序绝不能将两个请求分配给同一 peer。
			但是，实际上，peer可能会收到请求，断开连接并在之前的超时之前立即重新连接。
			在这种情况下，永远不会满足第一个请求，因为我们决不能无声地覆盖它，
			因为这会导致有效请求丢失并导致同步卡住
			 */
			if old := active[req.peer.id]; old != nil { // assigned: 分配
				log.Warn("Busy peer assigned new state fetch", "peer", old.peer.id)

				// Make sure the previous one doesn't get siletly lost
				//
				// 确保前一个 req 不会丢失
				old.timer.Stop()   // 关闭掉  超时触发器
				old.dropped = true // 标识为 移除状态

				finished = append(finished, old)
			}
			// Start a timer to notify the sync loop if the peer stalled.
			//
			// 启动一个计时器以通知同步循环（如果对等方停止）
			// 启动req 的超市触发器
			req.timer = time.AfterFunc(req.timeout, func() {
				select {

				// 当超时时,将本 req 发送至 timeout 通道
				case timeout <- req:
				case <-s.done:
					// Prevent leaking of timer goroutines in the unlikely case where a
					// timer is fired just before exiting runStateSync.
					/**
					在不太可能发生的情况下，防止定时器goroutine泄漏，这是在退出runStateSync之前触发定时器的情况
					 */
				}
			})

			// 在 active (活跃中 )集中记录当前req
			active[req.peer.id] = req
		}
	}
}

// stateSync schedules requests for downloading a particular state trie defined
// by a given state root.
//
/**

todo statedb的同步数据结构  StateDB的同步数据结构

stateSync 计划请求那种根据给定的root 定义特定state的下载任务
 */
type stateSync struct {
	// Downloader实例引用 为了访问和管理当前 peerSet
	d *Downloader // Downloader instance to access and manage current peerset

	// State的trie同步调度而定义任务
	sched  *trie.Sync                 // State trie sync scheduler defining the tasks
	// Keccak256哈希器 去做验证交付
	keccak hash.Hash                  // Keccak256 hasher to verify deliveries with
	// 当前队列等待拉取的任务集 (这个应该是查看该 state trie node hash 同步的任务已经发给了 哪些 peer)
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
	// 记录之前所有尝试过peer
	// attempts: 尝试
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
todo 重要的方法
run启动任务分配和响应处理循环，阻塞直到完成，最后通知所有等待循环的goroutine。
 */
func (s *stateSync) run() {  // todo  真正去做 statedb 同步的最底层方法

	/** TODO 重要的方法 */
	s.err = s.loop()

	// 一直持续到 同步完成或者最终失败,时关闭done,表示结束
	close(s.done)
}

// Wait blocks until the sync is done or canceled.
// Wait 阻止直到同步完成或取消
func (s *stateSync) Wait() error {
	<-s.done
	return s.err
}

// Cancel cancels the sync and waits until it has shut down.
// Cancel 取消同步并等待直到它关闭
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
TODO loop 是state Trie同步的主要事件循环
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
				s.d.dropPeer(req.peer.id)  // 将该对端peer 从本地 ProtocolManager.peerSet 和 Downloader.peerSet 中移除   `ProtocolManager.removePeer()` 函数指针
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
/**  assign  分配
AssignTasks
尝试将新任务分配给具有空闲 peers，这些任务是从当前正在重试的 batch中，或者是从trie同步本身中获取新数据。
 */
func (s *stateSync) assignTasks() {
	// Iterate over all idle peers and try to assign them state fetches
	//
	// 遍历所有空闲 peer，并尝试分配 state 获取
	peers, _ := s.d.peers.NodeDataIdlePeers()
	for _, p := range peers {
		// Assign a batch of fetches proportional to the estimated latency/bandwidth
		//
		// 分配与估计的延迟/带宽成比例的一批提取 (batch)
		cap := p.NodeDataCapacity(s.d.requestRTT())
		// 组装 req 实例
		req := &stateReq{peer: p, timeout: s.d.requestTTL()}

		/** todo 给该req填充一些拉取 state trie node 数据的 task*/
		s.fillTasks(cap, req)

		// If the peer was assigned tasks to fetch, send the network request
		//
		// 如果 peer 被分配了要提取的任务，请发送网络请求
		// 根据 req中的 items (state trie node条目数) 来判断
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
//
/**
fillTasks:
使用最多n个 state 下载任务填充给定的请求对象以发送给远程对等方
 */
func (s *stateSync) fillTasks(n int, req *stateReq) {
	// Refill available tasks from the scheduler.
	//
	// 从scheduler中重新填充可用任务。
	// 入参的n代表 req去对端peer 拉取数据的量
	// 入参的req表示去对端peer拉取state的请求封装
	if len(s.tasks) < n {
		// 从优先级队列中弹出max个req
		new := s.sched.Missing(n - len(s.tasks))

		// 分别根据这些req组装新的 task直到完整到达n的大小
		for _, hash := range new {
			s.tasks[hash] = &stateTask{make(map[string]struct{})}
		}
	}
	// Find tasks that haven't been tried with the request's peer.
	//
	// 查找尚未与req中的peer尝试过拉取的 task
	req.items = make([]common.Hash, 0, n)
	req.tasks = make(map[common.Hash]*stateTask, n)
	// 遍历所有 task
	for hash, t := range s.tasks {
		// Stop when we've gathered enough requests
		//
		// 当我们收集到足够的请求时停止
		if len(req.items) == n {
			break
		}
		// Skip any requests we've already tried from this peer
		//
		// 跳过我们已经尝试过的来自此peer的任何 req
		if _, ok := t.attempts[req.peer.id]; ok {
			continue
		}
		// Assign the request to this peer
		//
		// 分配req给这个peer
		// 在尝试记录中添加该peer的记录
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
