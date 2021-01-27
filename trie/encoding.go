// Copyright 2014 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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
 todo 在以太坊中，key bytes encoding不会直接转位COMPACT encoding，需要先经过HEX encoding

	todo 三种编码中，目前以太坊只支持如下转换：

		KEYBYTES encoding转HEX encoding
		HEX encoding转KEYBYTES encoding
		HEX encoding转COMPACT encoding
		COMPACT encoding转HEX encoding


	todo Hex 是在 sha3的 key 操作 MPT 之前计算的,  而 compact 是在 MPT 的节点 遍历 <各个节点计算各自的Hash> 时计算的,这时候node上的key可能只是完整key的某部分前缀而已, 需要判断是否为前缀 .

 */


/**
todo 节点放入数据库时候的key用到的就是Compact编码，可以节约磁盘空间

Compact 编码:
又叫 hex prefix 编码，它的主要意图是将 Hex 格式的字符串恢复到 keybytes 的格式，
同时要加入当前 Compact 格式的标记位，还要考虑在 `奇偶不同长度 Hex 格式字符串下`，
避免引入多余的 byte.

todo Hex 是在 sha3的 key 操作 MPT 之前计算的,  而 compact 是在 MPT 的节点 遍历 <各个节点计算各自的Hash> 时计算的,这时候node上的key可能只是完整key的某部分前缀而已, 需要判断是否为前缀 .

todo Compact 编码:又叫 hex prefix 编码，它的主要意图是将 Hex 格式的字符串恢复到 keybytes 的格式，同时要加入当前 Compact 格式的标记位，还要考虑在奇偶不同长度 Hex 格式字符串下，避免引入多余的 byte



1) Compact 编码首先将 Hex 尾部标记 byte 去掉，然后将原本每 2 nibble 的数据合并到 1byte；
2) 增添 1byte 在输出数据头部以放置 Compact 格式标记位00100000；
3) 如果输入 Hex 格式字符串有效长度为奇数，还可以将 Hex 字符串的第一个 nibble 放置在标记位 byte 里的低 4bit,并增加奇数位标志 0011xxxx

 */
func hexToCompact(hex []byte) []byte { // node 计算Hash时, key 一定是 compact编码之后的 ...

	/**
		todo 入参的 hex 可能的几种情况
		hex字节数组如果不是经过KEYBYTES encoding编码得到的，可能会有前缀(姑且这么称呼)这么一个东西，具体生成的hex结果会分为如下 4 种情况：

						hex字节数组长度为奇数，最后一个是后缀，标记为16，此时无前缀这种就是前面所讲的经过KEYBYTES encoding编码得到的.

						hex字节数组长度为奇数，最后一个不是后缀，此时会认为hex字节数组的第一个是其的前缀.

						hex字节数组长度为偶数，最后一个是后缀，此时hex字节数组的第一个一定是其前缀.

						hex字节数组长度为偶数，最后一个不是后缀，并且无前缀.
	 */


	// 如果最后一位是16，则terminator为1，否则为0
	terminator := byte(0)
	// 包含terminator这个的肯定是叶子节点
	if hasTerm(hex) {
		terminator = 1

		// 去除Hex标志位  (去掉 16)
		hex = hex[:len(hex)-1]
	}

	// Compact 开辟的空间长度为hex编码的一半再加1，这个1对应的空间是Compact的前缀
	buf := make([]byte, len(hex)/2+1)

	// Compact格式标记位,如果最后一位是16，才会有Compact格式标记位
	//
	// todo 仅仅是为了 compact -> hex 时 决定是否在尾巴 追加 16 而定
	//
	// 因为要恢复nibble时，有Compact标志的，要在最后添加16
	buf[0] = terminator << 5 // the flag byte  todo 00000000 或者 00100000

	// 如果为奇数，添加奇数位标志，并把第一个nibble字节放入buf[0]的低四位
	//
	// hex 长度为奇数，则逻辑上说明 hex有前缀  (因为已经去掉 尾巴的16 还是  奇数,  说明 hex 是有前缀的)
	if len(hex)&1 == 1 {

		// odd flag 奇数标志 00110000
		buf[0] |= 1 << 4 // odd flag

		// 第一个`半字节`包含在第一个字节中, 如: 0011xxxx
		buf[0] |= hex[0] // first nibble is contained in the first byte
		hex = hex[1:]    //  此时获取的 hex 编码 无前缀无后缀
	}

	// 将两个nibble字节合并成一个字节
	//
	// 将 hex编码 映射到 compact编码 中
	decodeNibbles(hex, buf[1:])
	return buf
}


/**
将compact编码转化为Hex编码

todo Hex 是在 sha3的 key 操作 MPT 之前计算的,  而 compact 是在 MPT 的节点 遍历 <各个节点计算各自的Hash> 时计算的,这时候node上的key可能只是完整key的某部分前缀而已, 需要判断是否为前缀 .

todo Compact 编码:又叫 hex prefix 编码，它的主要意图是将 Hex 格式的字符串恢复到 keybytes 的格式，同时要加入当前 Compact 格式的标记位，还要考虑在奇偶不同长度 Hex 格式字符串下，避免引入多余的 byte
*/
func compactToHex(compact []byte) []byte {
	base := keybytesToHex(compact) // todo 先按照 bets 转 Hex 处理, 这时候末尾 肯定是被加了 16 休止符, 后面我们在决定 原先 hex转成 compact前的内容是否有 16 休止符，来决定是否去掉本次添加的 16 休止符
	// delete terminator flag
	if base[0] < 2 { // todo 说明 base 是 0001 或者 0000 <而非 0011 或者 0010 > 就是说 原来的 hex 在编成 compact 时是没有 16 休止符的，需要 去掉 bytes To hex 添加的末尾 16 休止符
		base = base[:len(base)-1]  // 去掉 bytes To hex 添加的末尾 16 休止符

		// apply terminator flag
		// base[0]包括四种情况
		// 00000000 扩展节点偶数位
		// 00000001 扩展节点奇数位
		// 00000010 叶子节点偶数位
		// 00000011 叶子节点奇数位


	}



	// apply odd flag
	//
	// 如果是偶数位，chop等于0，否则等于1
	chop := 2 - base[0]&1 // 到这里 base[0] 只会是 0000 <原来的hex是 偶数个byte原内容> 或者 0001 <原来的hex是 奇数个byte原内容>

	// 截取 base 的内容
	return base[chop:]
}


// todo 将 []byte 的 key  转成 16进制 的 []byte数组
//
//
// todo Hex 是在 sha3的 key 操作 MPT 之前计算的,  而 compact 是在 MPT 的节点 遍历 <各个节点计算各自的Hash> 时计算的,这时候node上的key可能只是完整key的某部分前缀而已, 需要判断是否为前缀 .
func keybytesToHex(str []byte) []byte {

	// hex编码 str 总共会用到的空间大小     +1 是因为最后需要放入  `16` 数字 作为休止符
	l := len(str)*2 + 1

	// 将一个 key byte 转化成 两个字节
	var nibbles = make([]byte, l)

	// todo 其中依次 高4位 放在nibbles[]的 偶数位，低4位 放在nibbles[]的 奇数位，最后一位设置为16（二进制表示00010000），表示这个hex编码是通过 key  bytes 编码转换的

	for i, b := range str {

		/**
		例如:

		要将byte值为249的数据转为hex编码，首先将249转为二进制表示：11111001，看清楚，高4位是1111，低4位是1001

		249除以16得到的值为15，15的二进制表示是：1111，看清楚了吗？这就是249的高4位
		249模以16得到的值为9，9的二进制表示是：1001，看清楚了吗？这就是249的低4位

		todo 最终 nibbles的 偶数位nibbles[0]存入249的高4位00001111，nibbles的奇数位nibbles[1]的低4位存入249的低4位00001001,最后一位nibbles[2]存入16（也就是二进制00010000）

		todo 发现了吗？  hex中的每一个byte都表示一个16进制数。 因此249最终hex编码结果为：[00001111,00001001,00010000]，也就是[15 9 16]

		 */

		// 将 b 的 高4位 存入nibbles的 第一个字节
		nibbles[i*2] = b / 16

		// 将 b 的 低4位 存入nibbles的 第二个字节
		nibbles[i*2+1] = b % 16
	}

	//  todo 末尾加入 Hex 标志位  `16`     在 判断 key 是否终止时 会用到   下面的 hasTerm() 中
	nibbles[l-1] = 16
	return nibbles

	/**
	todo  但是：

		hex字节数组如果不是经过KEYBYTES encoding编码得到的，可能会有前缀(姑且这么称呼)这么一个东西，具体生成的hex结果会分为如下 4 种情况：

						hex字节数组长度为奇数，最后一个是后缀，标记为16，此时无前缀这种就是前面所讲的经过KEYBYTES encoding编码得到的.

						hex字节数组长度为奇数，最后一个不是后缀，此时会认为hex字节数组的第一个是其的前缀.

						hex字节数组长度为偶数，最后一个是后缀，此时hex字节数组的第一个一定是其前缀.

						hex字节数组长度为偶数，最后一个不是后缀，并且无前缀.
	 */

}

// hexToKeybytes turns hex nibbles into key bytes.
// This can only be used for keys of even length.
//
// todo Hex 是在 sha3的 key 操作 MPT 之前计算的,  而 compact 是在 MPT 的节点 遍历 <各个节点计算各自的Hash> 时计算的,这时候node上的key可能只是完整key的某部分前缀而已, 需要判断是否为前缀 .
func hexToKeybytes(hex []byte) []byte {

	// 如果有尾缀 16
	if hasTerm(hex) {
		hex = hex[:len(hex)-1]   // 直接清掉尾缀 16
	}
	if len(hex)&1 != 0 {		// 这时候 必须为 偶数,  因为 如果 hex是有 key bytes 转过来的, 那么这里肯定是  偶数 + 16， 现在去掉 16, 剩下的就应该是 偶数
		panic("can't convert hex key of odd length")
	}
	key := make([]byte, len(hex)/2)
	decodeNibbles(hex, key)
	return key
}
// 逐个将  没有前缀没有后缀的 hex 映射到 compact 编码中  (映射到 compact[1:], 因为 compact[0] 存放了一些状态信息 用于 compact 恢复会 hex时用的)
func decodeNibbles(nibbles []byte, bytes []byte) {
	for bi, ni := 0, 0; ni < len(nibbles); bi, ni = bi+1, ni+2 {
		bytes[bi] = nibbles[ni]<<4 | nibbles[ni+1]    // 16 * nibbles[i] + nibbles[i+1]  todo 因为 在 byte -> hex 时,  byte 的高4位 放到 偶数索引,  低4位 放到 奇数索引    (看 keybytesToHex() 就明白了)
	}
}

// prefixLen returns the length of the common prefix of a and b.
//
// prefixLen返回  a 和 b 的公共前缀的长度
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
//
// hasTerm()  返回十六进制 key 是否具有终止符标志
//
// 判断 尾巴是否有 16
func hasTerm(s []byte) bool {
	return len(s) > 0 && s[len(s)-1] == 16    // 为什么判断 末尾的 `16`   todo  因为在 上面的 keybytesToHex()  加的 休止符
}
