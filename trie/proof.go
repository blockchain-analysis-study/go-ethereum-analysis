// Copyright 2015 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package trie

import (
	"bytes"
	"fmt"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/ethdb"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/log"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rlp"
)

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
//
/**
todo 这个方法一般只有 轻节点用

Prove: 构造入参的key的Merkle proof

proofDb: 用来 接收 证明 路径的  list

todo 根据给定的key，在trie中，将满足key中最大长度前缀的路径上的节点都加入到proofDb 返回（队列中每个元素满足：未编码的hash以及对应rlp编码后的节点）


如果trie不包含key的值，
则返回的证明将包含key的现有前缀最长的所有节点（至少是根节点），
并以证明不存在key的节点结尾.   (这句话的意思是, 只返回了 key前缀匹配到的node, 而后缀没匹配到node)

*/
func (t *Trie) Prove(key []byte, fromLevel uint, proofDb ethdb.Putter) error {
	// Collect all nodes on the path to key.
	//
	// 收集 key 路径上的所有 node


	// 现将 bytes 转成 hex
	key = keybytesToHex(key)
	nodes := []node{}

	// 先拿当前trie root
	tn := t.root

	/**
	todo 遍历出所有该key路径上经历的node
	 */
	for len(key) > 0 && tn != nil {
		switch n := tn.(type) {

		// 如果是 短节点
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				// The trie doesn't contain the key.
				//
				// 遍历到最后, 如果对应的key在树上没找到
				tn = nil
			} else {
				tn = n.Val // 得到valueNode
				key = key[len(n.Key):] // 置空 key
			}
			nodes = append(nodes, n)
		case *fullNode:
			tn = n.Children[key[0]]
			key = key[1:]
			nodes = append(nodes, n)
		case hashNode:
			var err error
			tn, err = t.resolveHash(n, nil)
			if err != nil {
				log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
				return err
			}
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}

	// 构建一个 hash (用来计算各个 node 的hash用)
	hasher := newHasher(0, 0, nil)

	// todo 遍历出所有该key路径上经历的node
	for i, n := range nodes {
		// Don't bother checking for errors here since hasher panics
		// if encoding doesn't work and we're not writing to any database.
		//
		/**
		此处无需打扰检查错误，因为如果编码不起作用并且我们未写入任何数据库，则会加剧恐慌
		 */
		// 获取,key经过折叠之后的 node (只针对 shortNode 和 fullNode)
		// (valueNode和hashNode返回的是原值,因为它们没有子节点)
		n, _, _ = hasher.hashChildren(n, nil)
		hn, _ := hasher.store(n, nil, false)  // 这里 返回 hash
		if hash, ok := hn.(hashNode); ok || i == 0 {
			// If the node's database encoding is a hash (or is the
			// root node), it becomes a proof element.
			//
			// 如果节点的数据库编码是  hashNode 或  根节点 ，则它将成为证明元素
			if fromLevel > 0 {
				fromLevel--
			} else {
				enc, _ := rlp.EncodeToBytes(n)
				if !ok {
					hash = crypto.Keccak256(enc)
				}

				//  todo 将  node的Hash值 和  node原数据   存入proof
				proofDb.Put(hash, enc)   // 妈的 key 并没用, 就是 hash 根本没用
			}
		}
	}
	return nil
}

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
//
/**
Prove: 构造入参的key的Merkle proof。
结果包含键值上路径上的所有编码节点。 该值本身也包含在最后一个节点中，可以通过验证证明来检索.


如果trie不包含key的值，
则返回的证明将包含key的现有前缀最长的所有节点（至少是根节点），
并以证明不存在key的节点结尾.
 */
func (t *SecureTrie) Prove(key []byte, fromLevel uint, proofDb ethdb.Putter) error {
	return t.trie.Prove(key, fromLevel, proofDb)
}


// todo 校验  Prove() 返回的 proofDb 数组 和  key 的关系
//
//    以此来得知 key 是否在该  MPT 的路径上 ?
//
//   验证proffDb中是否存在满足输入的hash，和对应key的节点，如果满足，则返回rlp解码后的该节点
//
// todo 因为 key 对应的 value 肯定是 valueNode. 所以 证明 某个node是否在 tire上. 只需要早 proof 路径上找到 key 对应的 valueNode 即可
//
// VerifyProof checks merkle proofs. The given proof must contain the value for
// key in a trie with the given root hash. VerifyProof returns an error if the
// proof contains invalid trie nodes or the wrong value.
func VerifyProof(rootHash common.Hash, key []byte, proofDb DatabaseReader) (value []byte, nodes int, err error) {

	// key 先做 byte -> hex
	key = keybytesToHex(key)
	wantHash := rootHash
	for i := 0; ; i++ {

		// 首先  key 路径上 肯定要有 入参的 rootHash的.  否则 直接 证明失败
		buf, _ := proofDb.Get(wantHash[:])  // proofDb 有两种实现 nodeSet 和 nodeList. 目前有效的报文中都是用 nodeSet.  其底层为 map   nodeHash -> node原数据
		if buf == nil {
			return nil, i, fmt.Errorf("proof node %d (hash %064x) missing", i, wantHash)
		}


		// 使用 nodeHash 和 node原数据 封装成一个 node实例   （第一次 for 是 rootNode, 后续都是 key 路径上的 node）
		n, err := decodeNode(wantHash[:], buf, 0)
		if err != nil {
			return nil, i, fmt.Errorf("bad proof node %d: %v", i, err)
		}
		keyrest, cld := get(n, key)   // 根据 node 和 key 返回 key路径上下一级 node  (及对应的 child node)  而  keyrest： key 剩余的后缀部分
		switch cld := cld.(type) {

		// todo 因为 key 对应的 value 肯定是 valueNode. 所以 证明 某个node是否在 tire上. 只需要早 proof 路径上找到 key 对应的 valueNode 即可

		// 找到某个后缀处时, 返回了 nil, 说明提前终止了, 说明 proof 路径上 并没有包含 该 key
		case nil:
			// The trie doesn't contain the key.
			return nil, i, nil

		// 如果 child 是 hashNode, 将 该hash 复制给  wantHash 变量, 继续往下查找
		case hashNode:
			key = keyrest
			copy(wantHash[:], cld)

		// todo 找到了该 key 对应的 node. 说明 proof 路径上 存在 该 key
		case valueNode:
			return cld, i + 1, nil
		}
	}
}

func get(tn node, key []byte) ([]byte, node) {
	for {
		switch n := tn.(type) {
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				return nil, nil
			}
			tn = n.Val
			key = key[len(n.Key):]
		case *fullNode:
			tn = n.Children[key[0]]
			key = key[1:]
		case hashNode:
			return key, n
		case nil:
			return key, nil
		case valueNode:
			return nil, n
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}
}
