// Copyright 2014 The github.com/go-ethereum-analysis Authors
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

// Trie keys are dealt with in three distinct encodings:
//
// KEYBYTES encoding contains the actual key and nothing else. This encoding is the
// input to most API functions.
//
// HEX encoding contains one byte for each nibble of the key and an optional trailing
// 'terminator' byte of value 0x10 which indicates whether or not the node at the key
// contains a value. Hex key encoding is used for nodes loaded in memory because it's
// convenient to access.
//
// COMPACT encoding is defined by the Ethereum Yellow Paper (it's called "hex prefix
// encoding" there) and contains the bytes of the key and a flag. The high nibble of the
// first byte contains the flag; the lowest bit encoding the oddness of the length and
// the second-lowest encoding whether the node at the key is a value node. The low nibble
// of the first byte is zero in the case of an even number of nibbles and the first nibble
// in the case of an odd number. All remaining nibbles (now an even number) fit properly
// into the remaining bytes. Compact encoding is used for nodes stored on disk.


/**
todo 节点放入数据库时候的key用到的就是Compact编码，可以节约磁盘空间

Compact 编码:
又叫 hex prefix 编码，它的主要意图是将 Hex 格式的字符串恢复到 keybytes 的格式，
同时要加入当前 Compact 格式的标记位，还要考虑在 `奇偶不同长度 Hex 格式字符串下`，
避免引入多余的 byte.




1) Compact 编码首先将 Hex 尾部标记 byte 去掉，然后将原本每 2 nibble 的数据合并到 1byte；
2) 增添 1byte 在输出数据头部以放置 Compact 格式标记位00100000；
3) 如果输入 Hex 格式字符串有效长度为奇数，还可以将 Hex 字符串的第一个 nibble 放置在标记位 byte 里的低 4bit,并增加奇数位标志 0011xxxx

 */
func hexToCompact(hex []byte) []byte {

	// 如果最后一位是16，则terminator为1，否则为0
	terminator := byte(0)
	// 包含terminator这个的肯定是叶子节点
	if hasTerm(hex) {
		terminator = 1

		// 去除Hex标志位
		hex = hex[:len(hex)-1]
	}

	// 定义Compact字节数组
	buf := make([]byte, len(hex)/2+1)

	// Compact格式标记位,如果最后一位是16，才会有Compact格式标记位
	// 因为要恢复nibble时，有Compact标志的，要在最后添加16
	buf[0] = terminator << 5 // the flag byte  todo 00000000或者00100000

	// 如果为奇数，添加奇数位标志，并把第一个nibble字节放入buf[0]的低四位
	if len(hex)&1 == 1 {

		// odd flag 奇数标志 00110000
		buf[0] |= 1 << 4 // odd flag

		// 第一个`半字节`包含在第一个字节中, 如: 0011xxxx
		buf[0] |= hex[0] // first nibble is contained in the first byte
		hex = hex[1:]
	}

	// 将两个nibble字节合并成一个字节
	decodeNibbles(hex, buf[1:])
	return buf
}


/**
将compact编码转化为Hex编码
*/
func compactToHex(compact []byte) []byte {
	base := keybytesToHex(compact)
	// delete terminator flag
	if base[0] < 2 {
		base = base[:len(base)-1]

		// apply terminator flag
		// base[0]包括四种情况
		// 00000000 扩展节点偶数位
		// 00000001 扩展节点奇数位
		// 00000010 叶子节点偶数位
		// 00000011 叶子节点奇数位


	}



	// apply odd flag
	//
	// 如果是偶数位，chop等于2，否则等于1
	chop := 2 - base[0]&1

	// 去除compact标志位。偶数位去除2个字节，奇数位去除1个字节（因为奇数位的低四位放的是nibble数据）
	return base[chop:]
}

func keybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1

	// 将一个keybyte转化成两个字节
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}

	// 末尾加入Hex标志位16
	nibbles[l-1] = 16
	return nibbles
}

// hexToKeybytes turns hex nibbles into key bytes.
// This can only be used for keys of even length.
func hexToKeybytes(hex []byte) []byte {
	if hasTerm(hex) {
		hex = hex[:len(hex)-1]
	}
	if len(hex)&1 != 0 {
		panic("can't convert hex key of odd length")
	}
	key := make([]byte, len(hex)/2)
	decodeNibbles(hex, key)
	return key
}

func decodeNibbles(nibbles []byte, bytes []byte) {
	for bi, ni := 0, 0; ni < len(nibbles); bi, ni = bi+1, ni+2 {
		bytes[bi] = nibbles[ni]<<4 | nibbles[ni+1]
	}
}

// prefixLen returns the length of the common prefix of a and b.
//
// prefixLen返回a和b的公共前缀的长度
func prefixLen(a, b []byte) int {
	var i, length = 0, len(a)
	if len(b) < length {
		length = len(b)
	}
	for ; i < length; i++ {
		if a[i] != b[i] {
			break
		}
	}
	return i
}

// hasTerm returns whether a hex key has the terminator flag.
func hasTerm(s []byte) bool {
	return len(s) > 0 && s[len(s)-1] == 16
}
