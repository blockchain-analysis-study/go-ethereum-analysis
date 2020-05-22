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

package rlp

import (
	"io"
	"reflect"
)

// todo 于处理编码后的rlp数据，比如计算长度、分离等
/**
todo RLP:
	Recursive Length Prefix，递归长度前缀
 */

// RawValue represents an encoded RLP value and can be used to delay
// RLP decoding or to precompute an encoding. Note that the decoder does
// not verify whether the content of RawValues is valid RLP.
//
// todo RawValue: 表示已编码的RLP值，可用于延迟RLP解码或预编码.
//          todo 注意，解码器不会验证RawValues的内容是否为有效的RLP.
type RawValue []byte

// RawValue的反射类型
var rawValueType = reflect.TypeOf(RawValue{})

// ListSize returns the encoded size of an RLP list with the given
// content size.
func ListSize(contentSize uint64) uint64 {
	return uint64(headsize(contentSize)) + contentSize
}

// Split returns the content of first RLP value and any
// bytes after the value as subslices of b.
//
// todo  Split:
// 	返回第一个RLP值的内容以及该值之后的任何字节，作为b的子切片。
func Split(b []byte) (k Kind, content, rest []byte, err error) {
	k, ts, cs, err := readKind(b)
	if err != nil {
		return 0, nil, b, err
	}
	return k, b[ts : ts+cs], b[ts+cs:], nil
}

// SplitString splits b into the content of an RLP string
// and any remaining bytes after the string.
//
// SplitString:
// 将b拆分为RLP字符串的内容以及该字符串之后的所有剩余字节。
// todo 主要用来解 多字段编码的第二层内容
//  用经过拆出 [list总前缀, 第一个元素前缀, 第一个元素[]byte, 第二个元素前缀, 第二个元素[]byte, ...] 中的
//  list前缀 之后的 后面的内容 作为 第一个元素并返回作为入参，返回里面第一个字段和后面的N个字段的rlp
func SplitString(b []byte) (content, rest []byte, err error) {
	k, content, rest, err := Split(b)
	if err != nil {
		return nil, b, err
	}
	if k == List {
		return nil, b, ErrExpectedString
	}
	return content, rest, nil
}

// SplitList splits b into the content of a list and any remaining
// bytes after the list.
//
// SplitList：
// 将b拆分为列表的内容和列表之后的所有剩余字节。
// todo 主要用来解 多字段编码的第一层list
//  拆出 [list总前缀, 第一个元素前缀, 第一个元素[]byte, 第二个元素前缀, 第二个元素[]byte, ...] 中的
//  list前缀 并将 后面的内容 <就是第一前缀到 末尾> 作为第一个元素并返回， 第二个元素是个空<这里不管>
func SplitList(b []byte) (content, rest []byte, err error) {
	k, content, rest, err := Split(b)
	if err != nil {
		return nil, b, err
	}
	if k != List {
		return nil, b, ErrExpectedList
	}
	return content, rest, nil
}

// CountValues counts the number of encoded values in b.
// todo  CountValues: 计算b中编码值的数量.
// todo  其实就是说，
// todo  其实就是说，
// todo 取出第一个字节 <前缀>
//    如果有多个字段，则编码格式为:
//   [list总前缀, 第一个元素前缀, 第一个元素[]byte, 第二个元素前缀, 第二个元素[]byte, ...]
//  所以入参应该为: 第一个元素前缀, 第一个元素[]byte, 第二个元素前缀, 第二个元素[]byte, ...]
//  才可以知道，得到的num是 几
func CountValues(b []byte) (int, error) {
	i := 0
	for ; len(b) > 0; i++ {
		_, tagsize, size, err := readKind(b)
		if err != nil {
			return 0, err
		}
		b = b[tagsize+size:]
	}
	return i, nil
}
/**
todo  RLP 解码 规则

todo RLP编码的解码规则是编码规则的逆运算。首先根据编码结果的第一个字节f，执行以下的规则判断：

todo 判断1：如果f∈[0，127]，那么反序列化后是一个字节，就是f。

todo 判断2：如果f∈[128，183]，那么反序列化后是一个长度len<=55的字节数组，字节数组的长度为len=f-128。

todo 判断3：如果f∈[184，192]，那么反序列化后是一个长度len>55的字节数组，字节数组长度的编码的长度lenOfLen=f-183，然后从第二个字节开始读取lenOfLen个字节，按照大端模式转换成整数len，len即为字节数组的长度。

todo 判断4：如果f∈[193，247]，那么反序列化后是一个编码后长度len<=55的列表，列表长度为len=f-192。递归使用判断1~4进行解码。

todo 判断5：如果f∈[247，255]，那么反序列化后是编码后长度len>55的列表，列表长度的编码的长度lenOfLen=f-247，然后从第二个字节开始读取lenOfLen个字节，按照大端模式转换成整数len，len即为子列表总长度。然后递归使用判断1~5进行解码。
 */


// todo 读取出rlp中第一个元素的 rlp类型 和 起始位置 和 内容长度
func readKind(buf []byte) (k Kind, tagsize, contentsize uint64, err error) {
	if len(buf) == 0 {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}

	// todo 取出第一个字节 <前缀>
	//    如果有多个字段，则编码格式为:
	//   [list总前缀, 第一个元素前缀, 第一个元素[]byte, 第二个元素前缀, 第二个元素[]byte, ...]
	b := buf[0]
	switch {
	case b < 0x80: // 128, [0, 127]， todo 符合 decode.go 【解码规则1】
		k = Byte
		tagsize = 0
		contentsize = 1 // (1 byte)
	case b < 0xB8: // 184, [128, 183], todo 符合 decode.go 【解码规则2】
		k = String
		tagsize = 1 // 起点为下标 1
		contentsize = uint64(b - 0x80) // len = f-128
		// Reject strings that should've been single bytes.
		//
		// 拒绝应该是单个字节的字符串。
		if contentsize == 1 && len(buf) > 1 && buf[1] < 128 {
			return 0, 0, 0, ErrCanonSize
		}
	case b < 0xC0: // 192, [184, 191], todo 符合 decode.go 【解码规则3】
		k = String
		tagsize = uint64(b-0xB7) + 1 // 从第二个字节开始
		contentsize, err = readSize(buf[1:], b-0xB7) // lenOfLen = f-183
	case b < 0xF8: // 248,  [193，247] todo 符合 decode.go 【解码规则4】
		k = List
		tagsize = 1
		contentsize = uint64(b - 0xC0)  // len = f-192
	default: // [247，255], todo 符合 decode.go 【解码规则5】
		k = List
		tagsize = uint64(b-0xF7) + 1 // 从第二个字节开始
		contentsize, err = readSize(buf[1:], b-0xF7) // lenOfLen = f-247
	}
	if err != nil {
		return 0, 0, 0, err
	}
	// Reject values larger than the input slice.
	//
	// 拒绝大于输入slice的值。
	if contentsize > uint64(len(buf))-tagsize {
		return 0, 0, 0, ErrValueTooLarge
	}
	return k, tagsize, contentsize, err
}

// 读取b中的内容终止下标
func readSize(b []byte, slen byte) (uint64, error) {
	if int(slen) > len(b) {
		return 0, io.ErrUnexpectedEOF
	}
	var s uint64
	switch slen {
	// 如果只有一个元素，则直接拿第一个
	case 1:
		s = uint64(b[0])
	case 2:
		s = uint64(b[0])<<8 | uint64(b[1])
	case 3:
		s = uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
	case 4:
		s = uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	case 5:
		s = uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	case 6:
		s = uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
	case 7:
		s = uint64(b[0])<<48 | uint64(b[1])<<40 | uint64(b[2])<<32 | uint64(b[3])<<24 | uint64(b[4])<<16 | uint64(b[5])<<8 | uint64(b[6])
	case 8:
		s = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	}
	// Reject sizes < 56 (shouldn't have separate size) and sizes with
	// leading zero bytes.
	//
	// 拒绝大小<56（不应有单独的大小）和前导零字节的大小。
	//
	// todo 从这里可以看出，len 的长度就是和 55 相关的
	if s < 56 || b[0] == 0 {
		// 非规范尺寸信息错误
		return 0, ErrCanonSize
	}
	return s, nil
}
