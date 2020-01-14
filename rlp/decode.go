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

package rlp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
)

var (
	// EOL is returned when the end of the current list
	// has been reached during streaming.
	EOL = errors.New("rlp: end of list")

	// Actual Errors
	ErrExpectedString   = errors.New("rlp: expected String or Byte")
	ErrExpectedList     = errors.New("rlp: expected List")
	ErrCanonInt         = errors.New("rlp: non-canonical integer format")
	// 非规范尺寸信息错误
	ErrCanonSize        = errors.New("rlp: non-canonical size information")
	ErrElemTooLarge     = errors.New("rlp: element is larger than containing list")
	ErrValueTooLarge    = errors.New("rlp: value size exceeds available input length")
	ErrMoreThanOneValue = errors.New("rlp: input contains more than one value")

	// internal errors
	errNotInList     = errors.New("rlp: call of ListEnd outside of any list")
	errNotAtEOL      = errors.New("rlp: call of ListEnd not positioned at EOL")
	errUintOverflow  = errors.New("rlp: uint overflow")
	errNoPointer     = errors.New("rlp: interface given to Decode must be a pointer")
	errDecodeIntoNil = errors.New("rlp: pointer given to Decode must not be nil")
)

// Decoder is implemented by types that require custom RLP
// decoding rules or need to decode into private fields.
//
// The DecodeRLP method should read one value from the given
// Stream. It is not forbidden to read less or more, but it might
// be confusing.
/**
解码器接口， 由需要自定义RLP解码规则或需要解码为私有字段的类型实现。

DecodeRLP方法应从给定的Stream中读取一个值。 禁止少读或多读，但这可能会造成混淆。
 */
type Decoder interface {
	DecodeRLP(*Stream) error
}

// Decode parses RLP-encoded data from r and stores the result in the
// value pointed to by val. Val must be a non-nil pointer. If r does
// not implement ByteReader, Decode will do its own buffering.
//
// 解码解析来自 `r` 的RLP编码数据，并将结果存储在val指向的值中。
// Val必须是非nil指针。 如果r未实现ByteReader，则Decode将执行其自身的缓冲。
//

// Decode uses the following type-dependent decoding rules:
//
// 解码使用以下与类型有关的解码规则：
//
// If the type implements the Decoder interface, decode calls
// DecodeRLP.
//
// 如果该类型实现了Decoder接口，则解码调用DecodeRLP。
//
// To decode into a pointer, Decode will decode into the value pointed
// to. If the pointer is nil, a new value of the pointer's element
// type is allocated. If the pointer is non-nil, the existing value
// will be reused.
//
// 要解码为指针，解码将解码为指向的值。
// 如果指针为nil，则分配该指针的元素类型的新值。
// 如果指针为非零，则现有值将被重用。
//
// To decode into a struct, Decode expects the input to be an RLP
// list. The decoded elements of the list are assigned to each public
// field in the order given by the struct's definition. The input list
// must contain an element for each decoded field. Decode returns an
// error if there are too few or too many elements.
//
// 为了解码成结构，Decode希望输入是RLP列表。
// 列表的解码元素按照结构定义给出的顺序分配给每个公共字段。
// 输入列表必须为每个解码字段包含一个元素。
// 如果元素太多或太多，解码将返回错误。
//
// The decoding of struct fields honours certain struct tags, "tail",
// "nil" and "-".
//
// 结构字段的解码采用某些结构标签“ tail”，“ nil”和“-”。
//
// The "-" tag ignores fields.
//
// “-”标签忽略字段。
//
// For an explanation of "tail", see the example.
//
// 有关“尾巴”的说明，请参见示例。
//
// The "nil" tag applies to pointer-typed fields and changes the decoding
// rules for the field such that input values of size zero decode as a nil
// pointer. This tag can be useful when decoding recursive types.
//
// “ nil”标签应用于指针类型的字段，并更改该字段的解码规则，以使大小为零的输入值解码为nil指针。 解码递归类型时，此标记很有用。
//
//     type StructWithEmptyOK struct {
//         Foo *[20]byte `rlp:"nil"`
//     }
//
// To decode into a slice, the input must be a list and the resulting
// slice will contain the input elements in order. For byte slices,
// the input must be an RLP string. Array types decode similarly, with
// the additional restriction that the number of input elements (or
// bytes) must match the array's length.
//
// 要解码为切片，输入必须是列表，并且所得切片将按顺序包含输入元素。
// 对于字节片，输入必须是RLP字符串。 数组类型的解码方式类似，
// 但附加的限制是输入元素（或字节）的数量必须与数组的长度匹配。
//
// To decode into a Go string, the input must be an RLP string. The
// input bytes are taken as-is and will not necessarily be valid UTF-8.
//
// 要解码为 `Go字符串`，输入必须是RLP字符串。 输入字节按原样使用，不一定是有效的UTF-8。
//
// To decode into an unsigned integer type, the input must also be an RLP
// string. The bytes are interpreted as a big endian representation of
// the integer. If the RLP string is larger than the bit size of the
// type, Decode will return an error. Decode also supports *big.Int.
// There is no size limit for big integers.
//
// 要解码为无符号整数类型，输入还必须是RLP字符串。
// 字节被解释为整数的 todo 【大端】表示。
// 如果RLP字符串大于该类型的位大小，则Decode将返回错误。
// 解码还支持* big.Int。 大整数没有大小限制。
//
// To decode into an interface value, Decode stores one of these
// in the value:
//
// 要将解码为 `interface{}` 值，Decode将其中之一存储在值中：
//
//	  []interface{}, for RLP lists
//	  []byte, for RLP strings
//
// Non-empty interface types are not supported, nor are booleans,
// signed integers, floating point numbers, maps, channels and
// functions.
//
// todo 不支持非空 `interface{}`类型，也不支持 bool值<额， 看下面的代码 bool 其实是支持的>，带符号整数，float，map，chan和 func。
//
// Note that Decode does not set an input limit for all readers
// and may be vulnerable to panics cause by huge value sizes. If
// you need an input limit, use
//
// 请注意，“解码” 并未为所有 `readers` 设置输入限制，并且可能因【值巨大】而引起恐慌。 如果需要输入限制，请使用
//
//     NewStream(r, limit).Decode(val)
func Decode(r io.Reader, val interface{}) error {
	// TODO: this could use a Stream from a pool.
	return NewStream(r, 0).Decode(val)
}

// DecodeBytes parses RLP data from b into val.
// Please see the documentation of Decode for the decoding rules.
// The input must contain exactly one value and no trailing data.
//
// todo DecodeBytes:
//		将RLP数据从 `b` 解析到 `val`。 请参阅解码文档以获取解码规则。 输入必须仅包含一个值，并且不包含尾随数据。
func DecodeBytes(b []byte, val interface{}) error {
	// TODO: this could use a Stream from a pool.
	r := bytes.NewReader(b)
	if err := NewStream(r, uint64(len(b))).Decode(val); err != nil {
		return err
	}

	// 如果在 decode完之后， r中海油内容，说明 b 不止一个 元素的 rlp
	// 可能为： append(rlp(a), rlp(b) ...) 之类的 多个 值的 rlp 拼接到一起的
	if r.Len() > 0 {
		return ErrMoreThanOneValue
	}
	return nil
}

// 封装解码错误类型
type decodeError struct {
	msg string
	typ reflect.Type
	ctx []string
}

// 输出 解码错误的 描述信息
func (err *decodeError) Error() string {
	ctx := ""
	if len(err.ctx) > 0 {
		ctx = ", decoding into "
		for i := len(err.ctx) - 1; i >= 0; i-- {
			ctx += err.ctx[i]
		}
	}
	return fmt.Sprintf("rlp: %s for %v%s", err.msg, err.typ, ctx)
}


// 输出解码错误信息
func wrapStreamError(err error, typ reflect.Type) error {
	switch err {
	case ErrCanonInt:
		return &decodeError{msg: "non-canonical integer (leading zero bytes)", typ: typ}
	case ErrCanonSize:
		return &decodeError{msg: "non-canonical size information", typ: typ}
	case ErrExpectedList:
		return &decodeError{msg: "expected input list", typ: typ}
	case ErrExpectedString:
		return &decodeError{msg: "expected input string or byte", typ: typ}
	case errUintOverflow:
		return &decodeError{msg: "input string too long", typ: typ}
	case errNotAtEOL:
		return &decodeError{msg: "input list has too many elements", typ: typ}
	}
	return err
}

// 叠加错误到 解码错误封装中
func addErrorContext(err error, ctx string) error {
	if decErr, ok := err.(*decodeError); ok {
		decErr.ctx = append(decErr.ctx, ctx)
	}
	return err
}

var (
	// 这是一个 rlp 解码器 接口类型的 反射类型
	decoderInterface = reflect.TypeOf(new(Decoder)).Elem()
	// 这是一个 big.Int 类型的反射类型
	bigInt           = reflect.TypeOf(big.Int{})
)


// todo 根据 field 的类型和 tag
func makeDecoder(typ reflect.Type, tags tags) (dec decoder, err error) {
	kind := typ.Kind()
	switch {
	// 已编码的RLP值 的 反射类型
	case typ == rawValueType:

		// 返回 解码rlp 值的 解码器
		return decodeRawValue, nil
	case typ.Implements(decoderInterface):
		return decodeDecoder, nil
	case kind != reflect.Ptr && reflect.PtrTo(typ).Implements(decoderInterface):
		return decodeDecoderNoPtr, nil
	case typ.AssignableTo(reflect.PtrTo(bigInt)):
		return decodeBigInt, nil
	case typ.AssignableTo(bigInt):
		return decodeBigIntNoPtr, nil
	case isUint(kind):
		return decodeUint, nil
	case kind == reflect.Bool:
		return decodeBool, nil
	case kind == reflect.String:
		return decodeString, nil
	case kind == reflect.Slice || kind == reflect.Array:
		return makeListDecoder(typ, tags)
	case kind == reflect.Struct:
		return makeStructDecoder(typ)
	case kind == reflect.Ptr:
		if tags.nilOK {
			return makeOptionalPtrDecoder(typ)
		}
		return makePtrDecoder(typ)
	case kind == reflect.Interface:
		return decodeInterface, nil
	default:
		return nil, fmt.Errorf("rlp: type %v is not RLP-serializable", typ)
	}
}


// 解码 rlp 值的解码器
// todo 将 rlp 中的真实类型的数组提取出来，赋值到对应的 接收val上
func decodeRawValue(s *Stream, val reflect.Value) error {

	// todo 读出 Stream 中的数据
	r, err := s.Raw()
	if err != nil {
		return err
	}

	// todo 以 []byte 的形式设置到该值中
	//
	// todo  这个就是 给字段 赋值了
	val.SetBytes(r)
	return nil
}

// 解码 uint 的解码器
func decodeUint(s *Stream, val reflect.Value) error {
	typ := val.Type()
	num, err := s.uint(typ.Bits())
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	val.SetUint(num)
	return nil
}


// 解码 bool 的解码器
func decodeBool(s *Stream, val reflect.Value) error {
	b, err := s.Bool()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	val.SetBool(b)
	return nil
}


// 解码 字符串 的解码器
func decodeString(s *Stream, val reflect.Value) error {
	b, err := s.Bytes()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	val.SetString(string(b))
	return nil
}

// 解码 big.Int 的解码器
func decodeBigIntNoPtr(s *Stream, val reflect.Value) error {
	return decodeBigInt(s, val.Addr())
}


// 解码 *big.Int 的解码器
func decodeBigInt(s *Stream, val reflect.Value) error {
	b, err := s.Bytes()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	i := val.Interface().(*big.Int)
	if i == nil {
		i = new(big.Int)
		val.Set(reflect.ValueOf(i))
	}
	// Reject leading zero bytes
	if len(b) > 0 && b[0] == 0 {
		return wrapStreamError(ErrCanonInt, val.Type())
	}
	i.SetBytes(b)
	return nil
}


// 解码 list 的解码器
func makeListDecoder(typ reflect.Type, tag tags) (decoder, error) {
	etype := typ.Elem()
	if etype.Kind() == reflect.Uint8 && !reflect.PtrTo(etype).Implements(decoderInterface) {
		if typ.Kind() == reflect.Array {
			return decodeByteArray, nil
		}
		return decodeByteSlice, nil
	}
	etypeinfo, err := cachedTypeInfo1(etype, tags{})
	if err != nil {
		return nil, err
	}
	var dec decoder
	switch {
	case typ.Kind() == reflect.Array:
		dec = func(s *Stream, val reflect.Value) error {
			return decodeListArray(s, val, etypeinfo.decoder)
		}
	case tag.tail:
		// A slice with "tail" tag can occur as the last field
		// of a struct and is supposed to swallow all remaining
		// list elements. The struct decoder already called s.List,
		// proceed directly to decoding the elements.
		dec = func(s *Stream, val reflect.Value) error {
			return decodeSliceElems(s, val, etypeinfo.decoder)
		}
	default:
		dec = func(s *Stream, val reflect.Value) error {
			return decodeListSlice(s, val, etypeinfo.decoder)
		}
	}
	return dec, nil
}


// 解码 list {slice} 的解码器
func decodeListSlice(s *Stream, val reflect.Value, elemdec decoder) error {
	size, err := s.List()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	if size == 0 {
		val.Set(reflect.MakeSlice(val.Type(), 0, 0))
		return s.ListEnd()
	}
	if err := decodeSliceElems(s, val, elemdec); err != nil {
		return err
	}
	return s.ListEnd()
}

// 解码 的slice 元素的解码器
func decodeSliceElems(s *Stream, val reflect.Value, elemdec decoder) error {
	i := 0
	for ; ; i++ {
		// grow slice if necessary
		if i >= val.Cap() {
			newcap := val.Cap() + val.Cap()/2
			if newcap < 4 {
				newcap = 4
			}
			newv := reflect.MakeSlice(val.Type(), val.Len(), newcap)
			reflect.Copy(newv, val)
			val.Set(newv)
		}
		if i >= val.Len() {
			val.SetLen(i + 1)
		}
		// decode into element
		if err := elemdec(s, val.Index(i)); err == EOL {
			break
		} else if err != nil {
			return addErrorContext(err, fmt.Sprint("[", i, "]"))
		}
	}
	if i < val.Len() {
		val.SetLen(i)
	}
	return nil
}


// 解码 list{Array} 的解码器
func decodeListArray(s *Stream, val reflect.Value, elemdec decoder) error {
	if _, err := s.List(); err != nil {
		return wrapStreamError(err, val.Type())
	}
	vlen := val.Len()
	i := 0
	for ; i < vlen; i++ {
		if err := elemdec(s, val.Index(i)); err == EOL {
			break
		} else if err != nil {
			return addErrorContext(err, fmt.Sprint("[", i, "]"))
		}
	}
	if i < vlen {
		return &decodeError{msg: "input list has too few elements", typ: val.Type()}
	}
	return wrapStreamError(s.ListEnd(), val.Type())
}


// 解码 []byte 的解码器 (切片)
func decodeByteSlice(s *Stream, val reflect.Value) error {
	b, err := s.Bytes()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	val.SetBytes(b)
	return nil
}

// 解码 [n]byte 的解码器 (数组)
func decodeByteArray(s *Stream, val reflect.Value) error {
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}
	vlen := val.Len()
	switch kind {
	case Byte:
		if vlen == 0 {
			return &decodeError{msg: "input string too long", typ: val.Type()}
		}
		if vlen > 1 {
			return &decodeError{msg: "input string too short", typ: val.Type()}
		}
		bv, _ := s.Uint()
		val.Index(0).SetUint(bv)
	case String:
		if uint64(vlen) < size {
			return &decodeError{msg: "input string too long", typ: val.Type()}
		}
		if uint64(vlen) > size {
			return &decodeError{msg: "input string too short", typ: val.Type()}
		}
		slice := val.Slice(0, vlen).Interface().([]byte)
		if err := s.readFull(slice); err != nil {
			return err
		}
		// Reject cases where single byte encoding should have been used.
		if size == 1 && slice[0] < 128 {
			return wrapStreamError(ErrCanonSize, val.Type())
		}
	case List:
		return wrapStreamError(ErrExpectedString, val.Type())
	}
	return nil
}


// todo 解码 struct 的解码器
//      这里头会 for 逐个 解码 struct 的各个 field
func makeStructDecoder(typ reflect.Type) (decoder, error) {

	// todo 解析该 struct 中所以的  field
	//      其中包括了 获取 对应 field 类型的 编解码器
	fields, err := structFields(typ)
	if err != nil {
		return nil, err
	}
	dec := func(s *Stream, val reflect.Value) (err error) {

		// todo 先校验下 输入的  `Stream`
		if _, err := s.List(); err != nil {
			return wrapStreamError(err, typ)
		}

		// todo 循环该结构体 的所有  field， 并逐个 构造对应 field 的 编解码器
		for _, f := range fields {

			// todo 根据 对应的 field 的 解码器去对 该 field 进行解码并 赋值
			err := f.info.decoder(s, val.Field(f.index))
			if err == EOL {
				return &decodeError{msg: "too few elements", typ: typ}
			} else if err != nil {
				return addErrorContext(err, "."+typ.Field(f.index).Name)
			}
		}
		return wrapStreamError(s.ListEnd(), typ)
	}
	return dec, nil
}

// makePtrDecoder creates a decoder that decodes into
// the pointer's element type.
//
// makePtrDecoder: 创建一个解码器，该解码器解码为指针的元素类型。
func makePtrDecoder(typ reflect.Type) (decoder, error) {
	etype := typ.Elem()
	etypeinfo, err := cachedTypeInfo1(etype, tags{})
	if err != nil {
		return nil, err
	}
	dec := func(s *Stream, val reflect.Value) (err error) {
		newval := val
		if val.IsNil() {
			newval = reflect.New(etype)
		}
		if err = etypeinfo.decoder(s, newval.Elem()); err == nil {
			val.Set(newval)
		}
		return err
	}
	return dec, nil
}

// makeOptionalPtrDecoder creates a decoder that decodes empty values
// as nil. Non-empty values are decoded into a value of the element type,
// just like makePtrDecoder does.
//
// makeOptionalPtrDecoder: 创建一个解码器，将 [空值解码为nil] 。 就像makePtrDecoder一样，非空值被解码为元素类型的值。
//
// This decoder is used for pointer-typed struct fields with struct tag "nil".
//
// 该解码器用于结构标签为 "nil" 的指针类型的结构字段。
func makeOptionalPtrDecoder(typ reflect.Type) (decoder, error) {
	etype := typ.Elem()
	etypeinfo, err := cachedTypeInfo1(etype, tags{})
	if err != nil {
		return nil, err
	}
	dec := func(s *Stream, val reflect.Value) (err error) {
		kind, size, err := s.Kind()
		if err != nil || size == 0 && kind != Byte {
			// rearm s.Kind. This is important because the input
			// position must advance to the next value even though
			// we don't read anything.
			s.kind = -1
			// set the pointer to nil.
			val.Set(reflect.Zero(typ))
			return err
		}
		newval := val
		if val.IsNil() {
			newval = reflect.New(etype)
		}
		if err = etypeinfo.decoder(s, newval.Elem()); err == nil {
			val.Set(newval)
		}
		return err
	}
	return dec, nil
}

// todo 定义 接口切片的 反射类型
var ifsliceType = reflect.TypeOf([]interface{}{})

// 解码  interface{} 的解码器
func decodeInterface(s *Stream, val reflect.Value) error {
	if val.Type().NumMethod() != 0 {
		return fmt.Errorf("rlp: type %v is not RLP-serializable", val.Type())
	}
	kind, _, err := s.Kind()
	if err != nil {
		return err
	}
	if kind == List {
		slice := reflect.New(ifsliceType).Elem()
		if err := decodeListSlice(s, slice, decodeInterface); err != nil {
			return err
		}
		val.Set(slice)
	} else {
		b, err := s.Bytes()
		if err != nil {
			return err
		}
		val.Set(reflect.ValueOf(b))
	}
	return nil
}

// This decoder is used for non-pointer values of types
// that implement the Decoder interface using a pointer receiver.
//
// 该解码器用于使用 `指针接收器` 实现 `解码器接口`的类型的 `非指针值`。
func decodeDecoderNoPtr(s *Stream, val reflect.Value) error {
	return val.Addr().Interface().(Decoder).DecodeRLP(s)
}

// 解码解码器的解码器
func decodeDecoder(s *Stream, val reflect.Value) error {
	// Decoder instances are not handled using the pointer rule if the type
	// implements Decoder with pointer receiver (i.e. always)
	// because it might handle empty values specially.
	// We need to allocate one here in this case, like makePtrDecoder does.
	if val.Kind() == reflect.Ptr && val.IsNil() {
		val.Set(reflect.New(val.Type().Elem()))
	}
	return val.Interface().(Decoder).DecodeRLP(s)
}

// Kind represents the kind of value contained in an RLP stream.
type Kind int

// todo 对于 rlp 来说，只有三种类型
/**
RLP编码只对3种数据类型编码：

类型1： 值在[0，127]之间的单个字节。使用下面的规则1。 todo Byte

类型2：字节数组（元素数可为0）。使用下面的规则2和规则3。todo String

类型3：列表（列表是以数组或列表为元素的数组，元素数不可为0）。使用下面的规则4和规则5。 todo List



todo  RLP编码的编码规则：

todo 规则1：对于值在[0，127]之间的 【单个字节, byte】，其编码是 字节自身。

9->9

todo 规则2：对于长度len<=55的 【字节数组, []byte】，其编码是 128+len，紧接着字节数组自身。

[9]->[129，9]

len=1
129=128+len


todo 规则3：对于长度len>55的 【字节数组, []byte】，其编码是 183+len 编码的长度，紧接着len的编码，紧接着字节数组自身。
			len的大小不能超过8字节能表示的值。

[97，97，...，97]->[185，4，0，97，97，...，97]

len=1024
[4，0]=len的编码（编码涉及多字节的数值表示时，使用大端模式）
185=183+[4，0]的长度

todo 规则4：如果列表长度len<=55，其编码是 192+len，紧接着各子列表的编码。列表长度是指子列表编码后的长度之和。这是递归定义。

[[97，98，99]，[100，101，102]]->[200，131，97，98，99，131，100，101，102]

131=128+3
200=192+4+4

todo 规则5：如果列表长度len>55，其编码是247+len的编码的长度，紧接着len的编码，紧接着各子列表的编码。
			len的大小不能超过8字节能表示的值。这是递归定义。

["The length of this sentence is more than 55 bytes, ", "I know it because I pre-designed it"]->[248 88 179 84 104 101 32 108 101 110 103 116 104 32 111 102 32 116 104 105 115 32 115 101 110 116 101 110 99 101 32 105 115 32 109 111 114 101 32 116 104 97 110 32 53 53 32 98 121 116 101 115 44 32 163 73 32 107 110 111 119 32 105 116 32 98 101 99 97 117 115 101 32 73 32 112 114 101 45 100 101 115 105 103 110 101 100 32 105 116]

179 = 128 + 51
163 = 128 + 35
88 = 51+35 + 2
248 = 247 +1

 */


/**
todo  RLP 解码 规则

todo RLP编码的解码规则是编码规则的逆运算。首先根据编码结果的第一个字节f，执行以下的规则判断：

todo 判断1：如果f∈[0，127]，那么反序列化后是一个字节，就是f。

todo 判断2：如果f∈[128，183]，那么反序列化后是一个长度len<=55的字节数组，字节数组的长度为len=f-128。

todo 判断3：如果f∈[184，191]，那么反序列化后是一个长度len>55的字节数组，字节数组长度的编码的长度lenOfLen=f-183，然后从第二个字节开始读取lenOfLen个字节，按照大端模式转换成整数len，len即为字节数组的长度。

todo 判断4：如果f∈[193，247]，那么反序列化后是一个编码后长度len<=55的列表，列表长度为len=f-192。递归使用判断1~4进行解码。

todo 判断5：如果f∈[247，255]，那么反序列化后是编码后长度len>55的列表，列表长度的编码的长度lenOfLen=f-247，然后从第二个字节开始读取lenOfLen个字节，按照大端模式转换成整数len，len即为子列表总长度。然后递归使用判断1~5进行解码。
*/
const (
	// 单个字节
	Byte Kind = iota
	// 字符串
	String
	// 列表
	List
)

func (k Kind) String() string {
	switch k {
	case Byte:
		return "Byte"
	case String:
		return "String"
	case List:
		return "List"
	default:
		return fmt.Sprintf("Unknown(%d)", k)
	}
}

// ByteReader must be implemented by any input reader for a Stream. It
// is implemented by e.g. bufio.Reader and bytes.Reader.
//
// ByteReader: 必须由Stream的任何 输入阅读器 实现。 它是由例如 bufio.Reader和bytes.Reader。
type ByteReader interface {
	io.Reader
	io.ByteReader
}

// Stream can be used for piecemeal decoding of an input stream. This
// is useful if the input is very large or if the decoding rules for a
// type depend on the input structure. Stream does not keep an
// internal buffer. After decoding a value, the input reader will be
// positioned just before the type information for the next value.
//
// `Stream` 可用于 todo 输入流的逐段解码。
// 如果输入很大或类型的解码规则取决于输入结构，这将很有用。
// `Stream` 不保留内部缓冲区。
// 解码一个值后，输入阅读器 (input reader) 将位于下一个值的类型信息之前。 【类似于 游标】
//
// When decoding a list and the input position reaches the declared
// length of the list, all operations will return error EOL.
// The end of the list must be acknowledged using ListEnd to continue
// reading the enclosing list.
//
// 当解码一个 list 并且输入位置达到 list 的声明 len 时，所有操作将返回错误EOL。
// 必须使用 `ListEnd` 确认列表的末尾，以继续读取封闭的列表。
//
// Stream is not safe for concurrent use.
//
// `Stream` 不适合同时(并发)使用。
type Stream struct {

	// 字节 阅读器
	r ByteReader

	// number of bytes remaining to be read from r.
	// 要从 `r` 读取的剩余字节数
	remaining uint64

	// 是否限制内容长短的标识位
	limited   bool

	// auxiliary buffer for integer decoding
	// 用于整数解码的 todo 辅助缓冲区, 主要是针对大整数 ？
	uintbuf []byte


	// 游标指向的元素的 种类
	kind    Kind   // kind of value ahead
	// 游标指向的元素的 大小
	size    uint64 // size of value ahead
	// 类型标签中 单字节的值
	byteval byte   // value of single byte in type tag
	// 记录 最后一次readKind的错误
	kinderr error  // error from last readKind

	// 一个游标栈
	stack   []listpos
}


// 一个 游标的 封装
type listpos struct{ pos, size uint64 }

// NewStream creates a new decoding stream reading from r.
//
// If r implements the ByteReader interface, Stream will
// not introduce any buffering.
//
// For non-toplevel values, Stream returns ErrElemTooLarge
// for values that do not fit into the enclosing list.
//
// Stream supports an optional input limit. If a limit is set, the
// size of any toplevel value will be checked against the remaining
// input length. Stream operations that encounter a value exceeding
// the remaining input length will return ErrValueTooLarge. The limit
// can be set by passing a non-zero value for inputLimit.
//
// If r is a bytes.Reader or strings.Reader, the input limit is set to
// the length of r's underlying data unless an explicit limit is
// provided.
func NewStream(r io.Reader, inputLimit uint64) *Stream {
	s := new(Stream)
	s.Reset(r, inputLimit)
	return s
}

// NewListStream creates a new stream that pretends to be positioned
// at an encoded list of the given length.
func NewListStream(r io.Reader, len uint64) *Stream {
	s := new(Stream)
	s.Reset(r, len)
	s.kind = List
	s.size = len
	return s
}

// Bytes reads an RLP string and returns its contents as a byte slice.
// If the input does not contain an RLP string, the returned
// error will be ErrExpectedString.
func (s *Stream) Bytes() ([]byte, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	switch kind {
	case Byte:
		s.kind = -1 // rearm Kind
		return []byte{s.byteval}, nil
	case String:
		b := make([]byte, size)
		if err = s.readFull(b); err != nil {
			return nil, err
		}
		if size == 1 && b[0] < 128 {
			return nil, ErrCanonSize
		}
		return b, nil
	default:
		return nil, ErrExpectedString
	}
}

// Raw reads a raw encoded value including RLP type information.
//
// todo Raw:
// 		读取包含RLP类型信息的原始编码值。
func (s *Stream) Raw() ([]byte, error) {


	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	if kind == Byte {
		s.kind = -1 // rearm Kind
		return []byte{s.byteval}, nil
	}
	// the original header has already been read and is no longer
	// available. read content and put a new header in front of it.
	start := headsize(size)
	buf := make([]byte, uint64(start)+size)
	if err := s.readFull(buf[start:]); err != nil {
		return nil, err
	}
	if kind == String {
		puthead(buf, 0x80, 0xB7, size)
	} else {
		puthead(buf, 0xC0, 0xF7, size)
	}
	return buf, nil
}

// Uint reads an RLP string of up to 8 bytes and returns its contents
// as an unsigned integer. If the input does not contain an RLP string, the
// returned error will be ErrExpectedString.
func (s *Stream) Uint() (uint64, error) {
	return s.uint(64)
}


//
func (s *Stream) uint (maxbits int) (uint64, error) {

	// todo 先获取 s 中的 下一个值【即当前游标指向的最新值】 的 类型 和 大小
	kind, size, err := s.Kind()
	if err != nil {
		return 0, err
	}
	switch kind {

	// 如果类型为 byte
	case Byte:

		// 如果 类型为 byte, 但是当前的值为0, 则报错
		if s.byteval == 0 {
			return 0, ErrCanonInt
		}
		s.kind = -1 // rearm Kind  重装种类

		// 将当前 byte 中的值返回
		return uint64(s.byteval), nil

	// 如果 类型为 String
	case String:

		// 如果字节数超纲, 则报溢出错误
		if size > uint64(maxbits/8) {
			return 0, errUintOverflow
		}

		// 根据 size 从 Stream 中解出 uint64
		v, err := s.readUint(byte(size))
		switch {
		case err == ErrCanonSize:
			// Adjust error because we're not reading a size right now.
			//
			// 调整错误，因为我们现在不读取尺寸。
			return 0, ErrCanonInt
		case err != nil:
			return 0, err
		case size > 0 && v < 128:
			return 0, ErrCanonSize
		default:
			return v, nil
		}
	default:
		return 0, ErrExpectedString
	}
}

// Bool reads an RLP string of up to 1 byte and returns its contents
// as a boolean. If the input does not contain an RLP string, the
// returned error will be ErrExpectedString.
//
// Bool:
// 读取最多1个字节的RLP字符串，并将其内容作为布尔值返回。
// 如果输入不包含RLP字符串，则返回的错误将为 ErrExpectedString。
func (s *Stream) Bool() (bool, error) {

	// 从 s 中拿出对应的  8 bit 并转成 uint64 返回
	num, err := s.uint(8)
	if err != nil {
		return false, err
	}

	// 根据里面的内容，返回对应的 bool 值
	switch num {
	case 0:
		return false, nil
	case 1:
		return true, nil

		// todo 当不是 0 或者 1 的时候, 报错
	default:
		return false, fmt.Errorf("rlp: invalid boolean value: %d", num)
	}
}

// List starts decoding an RLP list. If the input does not contain a
// list, the returned error will be ErrExpectedList. When the list's
// end has been reached, any Stream operation will return EOL.
//
// todo List:  开始解码RLP列表。
//		如果输入不包含 list，则返回的错误将为 `ErrExpectedList`。
//		到达列表的末尾时，任何Stream操作都将返回 `EOL`。
func (s *Stream) List() (size uint64, err error) {
	kind, size, err := s.Kind()
	if err != nil {
		return 0, err
	}
	if kind != List {
		return 0, ErrExpectedList
	}
	s.stack = append(s.stack, listpos{0, size})
	s.kind = -1
	s.size = 0
	return size, nil
}

// ListEnd returns to the enclosing list.
// The input reader must be positioned at the end of a list.
//
// ListEnd: 返回到 封闭列表。
// 输入阅读器 必须位于列表的末尾。
func (s *Stream) ListEnd() error {
	if len(s.stack) == 0 {
		return errNotInList
	}
	tos := s.stack[len(s.stack)-1]
	if tos.pos != tos.size {
		return errNotAtEOL
	}
	s.stack = s.stack[:len(s.stack)-1] // pop
	if len(s.stack) > 0 {
		s.stack[len(s.stack)-1].pos += tos.size
	}
	s.kind = -1
	s.size = 0
	return nil
}

// Decode decodes a value and stores the result in the value pointed
// to by val. Please see the documentation for the Decode function
// to learn about the decoding rules.
//
// Decode: 解码一个值，并将结果存储在val指向的值中。 请参阅解码功能的文档以了解解码规则。
func (s *Stream) Decode(val interface{}) error {
	// 先判断 nil 值
	if val == nil {
		return errDecodeIntoNil
	}

	// 先拿到 val值指向的 val对象
	rval := reflect.ValueOf(val)
	// 先拿到 type
	rtyp := rval.Type()
	// 如果用来接收decode 的val不是指针的话，就不行
	if rtyp.Kind() != reflect.Ptr {
		return errNoPointer
	}

	// 如果被指向的val如果是个空指针的话，不行
	if rval.IsNil() {
		return errDecodeIntoNil
	}

	// todo 根据对应的类型 获取 该类型的  编解码器 实例 (可能是从缓存拿，也可能实时构造)
	info, err := cachedTypeInfo(rtyp.Elem(), tags{})
	if err != nil {
		return err
	}

	// todo 对该类型 进行解码  `rval.Elem()` 返回类型对应的指针
	err = info.decoder(s, rval.Elem())

	// 如果有 解码err , 处理err
	if decErr, ok := err.(*decodeError); ok && len(decErr.ctx) > 0 {
		// add decode target type to error so context has more meaning
		decErr.ctx = append(decErr.ctx, fmt.Sprint("(", rtyp.Elem(), ")"))
	}
	return err
}

// Reset discards any information about the current decoding context
// and starts reading from r. This method is meant to facilitate reuse
// of a preallocated Stream across many decoding operations.
//
// If r does not also implement ByteReader, Stream will do its own
// buffering.
func (s *Stream) Reset(r io.Reader, inputLimit uint64) {
	if inputLimit > 0 {
		s.remaining = inputLimit
		s.limited = true
	} else {
		// Attempt to automatically discover
		// the limit when reading from a byte slice.
		switch br := r.(type) {
		case *bytes.Reader:
			s.remaining = uint64(br.Len())
			s.limited = true
		case *strings.Reader:
			s.remaining = uint64(br.Len())
			s.limited = true
		default:
			s.limited = false
		}
	}
	// Wrap r with a buffer if it doesn't have one.
	bufr, ok := r.(ByteReader)
	if !ok {
		bufr = bufio.NewReader(r)
	}
	s.r = bufr
	// Reset the decoding context.
	s.stack = s.stack[:0]
	s.size = 0
	s.kind = -1
	s.kinderr = nil
	if s.uintbuf == nil {
		s.uintbuf = make([]byte, 8)
	}
}

// Kind returns the kind and size of the next value in the
// input stream.
//
// todo Kind: 返回  输入流  中下一个值的 `种类` 和 `大小`。
//
// The returned size is the number of bytes that make up the value.
// For kind == Byte, the size is zero because the value is
// contained in the type tag.
//
// todo 返回的大小是  组成该值的字节数。
// 	对于 kind == Byte，大小为零，因为该值包含在type标记中。
//
// The first call to Kind will read size information from the input
// reader and leave it positioned at the start of the actual bytes of
// the value. Subsequent calls to Kind (until the value is decoded)
// will not advance the input reader and return cached information.
//
// todo 首次调用 `Kind` 将从 输入流的Reader 中读取大小信息，并将其放置在该值实际字节的开头。
// 	随后对 `Kind` 的调用（直到对值进行解码）将不会使 输入流的Reader 前进，也不会返回缓存的信息。
func (s *Stream) Kind() (kind Kind, size uint64, err error) {

	// 构建 游标
	var tos *listpos
	if len(s.stack) > 0 {
		tos = &s.stack[len(s.stack)-1]
	}
	if s.kind < 0 {
		s.kinderr = nil
		// Don't read further if we're at the end of the
		// innermost list.
		if tos != nil && tos.pos == tos.size {
			return 0, 0, EOL
		}



		// todo 解出 Stream 中下一个值的 类型 和 长度
		s.kind, s.size, s.kinderr = s.readKind()
		if s.kinderr == nil {
			if tos == nil {
				// At toplevel, check that the value is smaller
				// than the remaining input length.
				if s.limited && s.size > s.remaining {
					s.kinderr = ErrValueTooLarge
				}
			} else {
				// Inside a list, check that the value doesn't overflow the list.
				if s.size > tos.size-tos.pos {
					s.kinderr = ErrElemTooLarge
				}
			}
		}
	}
	// Note: this might return a sticky error generated
	// by an earlier call to readKind.
	return s.kind, s.size, s.kinderr
}

// 从 `Stream` 中 读取对应数据的  Kind 和在 rlp 数据中占有的长度
func (s *Stream) readKind() (kind Kind, size uint64, err error) {
	b, err := s.readByte()
	if err != nil {
		if len(s.stack) == 0 {
			// At toplevel, Adjust the error to actual EOF. io.EOF is
			// used by callers to determine when to stop decoding.
			switch err {
			case io.ErrUnexpectedEOF:
				err = io.EOF
			case ErrValueTooLarge:
				err = io.EOF
			}
		}
		return 0, 0, err
	}
	s.byteval = 0

	/**
	todo 这里就是根据 解码规则，解码
	 */
	switch {
	case b < 0x80:
		// For a single byte whose value is in the [0x00, 0x7F] range, that byte
		// is its own RLP encoding.
		s.byteval = b
		return Byte, 0, nil
	case b < 0xB8:
		// Otherwise, if a string is 0-55 bytes long,
		// the RLP encoding consists of a single byte with value 0x80 plus the
		// length of the string followed by the string. The range of the first
		// byte is thus [0x80, 0xB7].
		return String, uint64(b - 0x80), nil
	case b < 0xC0:
		// If a string is more than 55 bytes long, the
		// RLP encoding consists of a single byte with value 0xB7 plus the length
		// of the length of the string in binary form, followed by the length of
		// the string, followed by the string. For example, a length-1024 string
		// would be encoded as 0xB90400 followed by the string. The range of
		// the first byte is thus [0xB8, 0xBF].
		size, err = s.readUint(b - 0xB7)
		if err == nil && size < 56 {
			err = ErrCanonSize
		}
		return String, size, err
	case b < 0xF8:
		// If the total payload of a list
		// (i.e. the combined length of all its items) is 0-55 bytes long, the
		// RLP encoding consists of a single byte with value 0xC0 plus the length
		// of the list followed by the concatenation of the RLP encodings of the
		// items. The range of the first byte is thus [0xC0, 0xF7].
		return List, uint64(b - 0xC0), nil
	default:
		// If the total payload of a list is more than 55 bytes long,
		// the RLP encoding consists of a single byte with value 0xF7
		// plus the length of the length of the payload in binary
		// form, followed by the length of the payload, followed by
		// the concatenation of the RLP encodings of the items. The
		// range of the first byte is thus [0xF8, 0xFF].
		size, err = s.readUint(b - 0xF7)
		if err == nil && size < 56 {
			err = ErrCanonSize
		}
		return List, size, err
	}
}


// 根据 长度，从 Stream 中解出 uint64
func (s *Stream) readUint(size byte) (uint64, error) {
	switch size {
	case 0:
		s.kind = -1 // rearm Kind
		return 0, nil
	case 1:

		// 返回当个字节的 uint64
		b, err := s.readByte()
		return uint64(b), err
	default:

		// 解出 多个 bit 中的值，组装成 uint64
		start := int(8 - size)
		for i := 0; i < start; i++ {
			s.uintbuf[i] = 0
		}
		if err := s.readFull(s.uintbuf[start:]); err != nil {
			return 0, err
		}
		if s.uintbuf[start] == 0 {
			// Note: readUint is also used to decode integer
			// values. The error needs to be adjusted to become
			// ErrCanonInt in this case.
			return 0, ErrCanonSize
		}
		return binary.BigEndian.Uint64(s.uintbuf), nil
	}
}

func (s *Stream) readFull(buf []byte) (err error) {
	if err := s.willRead(uint64(len(buf))); err != nil {
		return err
	}
	var nn, n int
	for n < len(buf) && err == nil {
		nn, err = s.r.Read(buf[n:])
		n += nn
	}
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (s *Stream) readByte() (byte, error) {
	if err := s.willRead(1); err != nil {
		return 0, err
	}
	b, err := s.r.ReadByte()
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return b, err
}

func (s *Stream) willRead(n uint64) error {
	s.kind = -1 // rearm Kind

	if len(s.stack) > 0 {
		// check list overflow
		tos := s.stack[len(s.stack)-1]
		if n > tos.size-tos.pos {
			return ErrElemTooLarge
		}
		s.stack[len(s.stack)-1].pos += n
	}
	if s.limited {
		if n > s.remaining {
			return ErrValueTooLarge
		}
		s.remaining -= n
	}
	return nil
}
