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

package trie

import (
	"bytes"
	"fmt"

	"github.com/go-ethereum-analysis/common"
	"github.com/go-ethereum-analysis/crypto"
	"github.com/go-ethereum-analysis/ethdb"
	"github.com/go-ethereum-analysis/log"
	"github.com/go-ethereum-analysis/rlp"
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

Prove: 构造入参的key的Merkle proof。
结果包含键值上路径上的所有编码节点。 该值本身也包含在最后一个节点中，可以通过验证证明来检索.


如果trie不包含key的值，
则返回的证明将包含key的现有前缀最长的所有节点（至少是根节点），
并以证明不存在key的节点结尾.
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
		hn, _ := hasher.store(n, nil, false)
		if hash, ok := hn.(hashNode); ok || i == 0 {
			// If the node's database encoding is a hash (or is the
			// root node), it becomes a proof element.
			//
			// 如果节点的数据库编码是哈希（或根节点），则它将成为证明元素。
			if fromLevel > 0 {
				fromLevel--
			} else {
				enc, _ := rlp.EncodeToBytes(n)
				if !ok {
					hash = crypto.Keccak256(enc)
				}

				// 将node的Hash值存入proof
				proofDb.Put(hash, enc)
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

// VerifyProof checks merkle proofs. The given proof must contain the value for
// key in a trie with the given root hash. VerifyProof returns an error if the
// proof contains invalid trie nodes or the wrong value.
func VerifyProof(rootHash common.Hash, key []byte, proofDb DatabaseReader) (value []byte, nodes int, err error) {
	key = keybytesToHex(key)
	wantHash := rootHash
	for i := 0; ; i++ {
		buf, _ := proofDb.Get(wantHash[:])
		if buf == nil {
			return nil, i, fmt.Errorf("proof node %d (hash %064x) missing", i, wantHash)
		}
		n, err := decodeNode(wantHash[:], buf, 0)
		if err != nil {
			return nil, i, fmt.Errorf("bad proof node %d: %v", i, err)
		}
		keyrest, cld := get(n, key)
		switch cld := cld.(type) {
		case nil:
			// The trie doesn't contain the key.
			return nil, i, nil
		case hashNode:
			key = keyrest
			copy(wantHash[:], cld)
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
