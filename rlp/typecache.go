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

package rlp

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// todo 类型缓存，用于记录哪些类型数据应该如何处理（如何编码和解码）

var (
	typeCacheMutex sync.RWMutex
	// todo 全局缓存， 不同类型的 编码器和解码器  集
	typeCache      = make(map[typekey]*typeinfo)
)


// todo  类型的编解码器的 封装类
type typeinfo struct {
	decoder
	writer
}

// represents struct tags
//
// 代表结构标签
type tags struct {
	// rlp:"nil" controls whether empty input results in a nil pointer.
	//
	//rlp:"nil"  控制空输入是否导致nil指针。
	nilOK bool
	// rlp:"tail" controls whether this field swallows additional list
	// elements. It can only be set for the last field, which must be
	// of slice type.
	//
	// rlp:"tail"   控制此字段是否包含其他列表元素。 它只能设置为必须是切片类型的最后一个字段。
	tail bool
	// rlp:"-" ignores fields.
	//
	// rlp:"-"   需要忽略的field
	ignored bool
}


type typekey struct {

	// struct 中 field 的反射类型
	reflect.Type
	// the key must include the struct tags because they
	// might generate a different decoder.
	//
	// 该 key 必须包含struct标记，因为它们可能会生成不同的解码器。
	//
	// 该 field 的 tag 描述
	tags
}

type decoder func(*Stream, reflect.Value) error

type writer func(reflect.Value, *encbuf) error

func cachedTypeInfo(typ reflect.Type, tags tags) (*typeinfo, error) {

	// todo  先从缓存获取 该类型的 编解码器
	typeCacheMutex.RLock()
	info := typeCache[typekey{typ, tags}]
	typeCacheMutex.RUnlock()
	if info != nil {
		return info, nil
	}
	// not in the cache, need to generate info for this type.
	//
	// 不在缓存中，则需要为此类型生成 编解码器 返回，并加入缓存中
	typeCacheMutex.Lock()
	defer typeCacheMutex.Unlock()

	return cachedTypeInfo1(typ, tags)
}


// todo 生成 对应类型的 编解码器，并加入缓存中
func cachedTypeInfo1(typ reflect.Type, tags tags) (*typeinfo, error) {

	// 构建一个 field 的描述
	key := typekey{typ, tags}

	// todo 根据这个 typeKey 结构体，去全局的 编解码器缓存中查找对应的 编解码器实现
	info := typeCache[key]
	if info != nil {
		// another goroutine got the write lock first
		// 另一个goroutine首先获得了写锁定
		// todo 缓存中有该类型的 编解码器，则直接返回
		return info, nil
	}
	// put a dummy value into the cache before generating.
	// if the generator tries to lookup itself, it will get
	// the dummy value and won't call itself recursively.
	//
	// 在生成之前将 `虚拟值` (指针) 放入缓存。 如果生成器尝试自行查找，它将获取 `虚拟值`，并且不会递归调用自身。
	typeCache[key] = new(typeinfo)

	// todo 根据 field 的类型 和 tag 返回该类型对应的 编解码器封装
	info, err := genTypeInfo(typ, tags)
	if err != nil {
		// remove the dummy value if the generator fails
		//
		// 如果生成器发生故障，则删除 `虚拟值`
		delete(typeCache, key)
		return nil, err
	}

	// 否则， 赋值
	*typeCache[key] = *info
	return typeCache[key], err
}


// 结构体中的 field 的 编解码器 的封装
type field struct {

	// field 在结构体中的 索引
	index int
	// 该 field 类型对应的 编解码器
	info  *typeinfo
}

// todo 解析 结构体的 各个字段
// 		这里头会生成对应 field类型的 编解码器 到 cache 中
func structFields(typ reflect.Type) (fields []field, err error) {

	// 根据 对应结构体 的 field 的个数，进行for
	for i := 0; i < typ.NumField(); i++ {

		// 根据 field 的索引，获取对应的 field
		// PkgPath是限定小写（未导出）字段名称的程序包路径。 大写（导出）字段名称为空。
		if f := typ.Field(i); f.PkgPath == "" { // exported, todo 如果对应的 field 是可导出的
			// 解析该field上的 tag
			tags, err := parseStructTag(typ, i)
			if err != nil {
				return nil, err
			}

			// 如果 当前 field 是 ingore 标识, 则跳过 rlp 解码
			if tags.ignored {
				continue
			}

			// todo 根据 当前  filed 的类型， 和当前 field 的 tag， 生成该 field 类型对应的编解码器
			//      可能从缓存中拿
			info, err := cachedTypeInfo1(f.Type, tags)
			if err != nil {
				return nil, err
			}
			fields = append(fields, field{i, info})
		}
	}
	return fields, nil
}

/**
解释 结构体的 tag
 */
func parseStructTag(typ reflect.Type, fi int) (tags, error) {

	// 先根据 索引获取 struct 中对应的 field
	f := typ.Field(fi)
	var ts tags

	// 获取 tag 中指定 rlp 部分描述
	for _, t := range strings.Split(f.Tag.Get("rlp"), ",") {

		// 查看 `rlp:` 之后的内容
		switch t = strings.TrimSpace(t); t {
		// 如果是 "", 啥事都别做, todo  有此 tag 的都是些正常的 field
		case "":

		// 如果是 "-"
		case "-":
			ts.ignored = true
		// 如果是 "nil"
		case "nil":
			ts.nilOK = true
		// 如果是 "tail"
		case "tail":
			ts.tail = true

			// 如果当前 field 的下标不是 struct 中的最后一个 field的索引, 报错
			if fi != typ.NumField()-1 {
				return ts, fmt.Errorf(`rlp: invalid struct tag "tail" for %v.%s (must be on last field)`, typ, f.Name)
			}

			// 如果当前 field 的类型不是 slice, 则报错
			if f.Type.Kind() != reflect.Slice {
				return ts, fmt.Errorf(`rlp: invalid struct tag "tail" for %v.%s (field type is not slice)`, typ, f.Name)
			}
		default:
			return ts, fmt.Errorf("rlp: unknown struct tag %q on %v.%s", t, typ, f.Name)
		}
	}
	return ts, nil
}

// 根据 field 的类型和 tag 生成对应的 编解码器封装
func genTypeInfo(typ reflect.Type, tags tags) (info *typeinfo, err error) {

	// new 一个 编解码器的 封装指针
	info = new(typeinfo)

	// 构建解码器
	if info.decoder, err = makeDecoder(typ, tags); err != nil {
		return nil, err
	}

	// 构建编码器
	if info.writer, err = makeWriter(typ, tags); err != nil {
		return nil, err
	}

	return info, nil
}

func isUint(k reflect.Kind) bool {
	return k >= reflect.Uint && k <= reflect.Uintptr
}
