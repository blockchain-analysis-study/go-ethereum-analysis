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

// Package les implements the Light Ethereum Subprotocol.
package les

import (
	"math/rand"
)

// wrsItem interface should be implemented by any entries that are to be selected from
// a weightedRandomSelect set. Note that recalculating monotonously decreasing item
// weights on-demand (without constantly calling update) is allowed
type wrsItem interface {
	Weight() int64
}

// weightedRandomSelect is capable of weighted random selection from a set of items
//
// weightedRandomSelect能够从一组项目中进行加权随机选择
type weightedRandomSelect struct {
	root *wrsNode
	idx  map[wrsItem]int
}

// newWeightedRandomSelect returns a new weightedRandomSelect structure
func newWeightedRandomSelect() *weightedRandomSelect {
	return &weightedRandomSelect{root: &wrsNode{maxItems: wrsBranches}, idx: make(map[wrsItem]int)}
}

// update updates an item's weight, adds it if it was non-existent or removes it if
// the new weight is zero. Note that explicitly updating decreasing weights is not necessary.
//
// update: 将更新项目的权重，如果不存在则将其添加，如果新权重为零，则将其删除。 请注意，无需显式更新减小的权重。
func (w *weightedRandomSelect) update(item wrsItem) {
	w.setWeight(item, item.Weight())
}

// remove removes an item from the set
func (w *weightedRandomSelect) remove(item wrsItem) {
	w.setWeight(item, 0)
}

// setWeight sets an item's weight to a specific value (removes it if zero)
func (w *weightedRandomSelect) setWeight(item wrsItem, weight int64) {
	idx, ok := w.idx[item]
	if ok {
		w.root.setWeight(idx, weight)
		if weight == 0 {
			delete(w.idx, item)
		}
	} else {
		if weight != 0 {
			if w.root.itemCnt == w.root.maxItems {
				// add a new level
				newRoot := &wrsNode{sumWeight: w.root.sumWeight, itemCnt: w.root.itemCnt, level: w.root.level + 1, maxItems: w.root.maxItems * wrsBranches}
				newRoot.items[0] = w.root
				newRoot.weights[0] = w.root.sumWeight
				w.root = newRoot
			}
			w.idx[item] = w.root.insert(item, weight)
		}
	}
}

// choose randomly selects an item from the set, with a chance proportional to its
// current weight. If the weight of the chosen element has been decreased since the
// last stored value, returns it with a newWeight/oldWeight chance, otherwise just
// updates its weight and selects another one
//
/**
choose: 从集合中随机选择一个项目，其机会与其当前重量成正比。
如果自上次存储的值以来所选元素的权重已减小，
则以newWeight / oldWeight机会返回它，
否则只需更新其权重并选择另一个
 */
func (w *weightedRandomSelect) choose() wrsItem {
	for {
		if w.root.sumWeight == 0 {
			return nil
		}
		// 现根据 trei上所有item 的总权重,随机出一个值
		val := rand.Int63n(w.root.sumWeight)
		// 返回一个第一个满足条件的 item 和 某个权重
		choice, lastWeight := w.root.choose(val)
		// 或全部Item自己的权重
		weight := choice.Weight()
		// 对比一下权重
		if weight != lastWeight {
			// 重置权重
			w.setWeight(choice, weight)
		}

		// 如果满足条件则,直接返回 item
		if weight >= lastWeight || rand.Int63n(lastWeight) < weight {
			return choice
		}
	}
}

const wrsBranches = 8 // max number of branches in the wrsNode tree

// wrsNode is a node of a tree structure that can store wrsItems or further wrsNodes.
type wrsNode struct {
	items                    [wrsBranches]interface{}
	weights                  [wrsBranches]int64
	sumWeight                int64
	level, itemCnt, maxItems int
}

// insert recursively inserts a new item to the tree and returns the item index
func (n *wrsNode) insert(item wrsItem, weight int64) int {
	branch := 0
	for n.items[branch] != nil && (n.level == 0 || n.items[branch].(*wrsNode).itemCnt == n.items[branch].(*wrsNode).maxItems) {
		branch++
		if branch == wrsBranches {
			panic(nil)
		}
	}
	n.itemCnt++
	n.sumWeight += weight
	n.weights[branch] += weight
	if n.level == 0 {
		n.items[branch] = item
		return branch
	}
	var subNode *wrsNode
	if n.items[branch] == nil {
		subNode = &wrsNode{maxItems: n.maxItems / wrsBranches, level: n.level - 1}
		n.items[branch] = subNode
	} else {
		subNode = n.items[branch].(*wrsNode)
	}
	subIdx := subNode.insert(item, weight)
	return subNode.maxItems*branch + subIdx
}

// setWeight updates the weight of a certain item (which should exist) and returns
// the change of the last weight value stored in the tree
func (n *wrsNode) setWeight(idx int, weight int64) int64 {
	if n.level == 0 {
		oldWeight := n.weights[idx]
		n.weights[idx] = weight
		diff := weight - oldWeight
		n.sumWeight += diff
		if weight == 0 {
			n.items[idx] = nil
			n.itemCnt--
		}
		return diff
	}
	branchItems := n.maxItems / wrsBranches
	branch := idx / branchItems
	diff := n.items[branch].(*wrsNode).setWeight(idx-branch*branchItems, weight)
	n.weights[branch] += diff
	n.sumWeight += diff
	if weight == 0 {
		n.itemCnt--
	}
	return diff
}

// choose recursively selects an item from the tree and returns it along with its weight
//
// choose: 从trie中递归地选择一个项目，并将其连同其权重一起返回
func (n *wrsNode) choose(val int64) (wrsItem, int64) {
	for i, w := range n.weights {
		if val < w {
			if n.level == 0 {
				return n.items[i].(wrsItem), n.weights[i]
			}
			return n.items[i].(*wrsNode).choose(val)
		}
		val -= w
	}
	panic(nil)
}
