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

package vm

import (
	"fmt"
)

// OpCode is an EVM opcode
// 定义EVM的执行码
type OpCode byte

// IsPush specifies if an opcode is a PUSH opcode.
// 判断当前执行码是否 push操作的执行码
func (op OpCode) IsPush() bool {
	switch op {
	case PUSH1, PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8, PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16, PUSH17, PUSH18, PUSH19, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24, PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH30, PUSH31, PUSH32:
		return true
	}
	return false
}

// IsStaticJump specifies if an opcode is JUMP.
// 判断是否是 jump 操作的执行码
func (op OpCode) IsStaticJump() bool {
	return op == JUMP
}

// 0x0 range - arithmetic ops.
const (
	STOP OpCode = iota 	// 0 == 0x00
	ADD					// 1 == 0x01
	MUL					// 2
	SUB					// 3
	DIV					// 4
	SDIV				// 5
	MOD					// 6
	SMOD				// 7
	ADDMOD				// 8
	MULMOD				// 9
	EXP					// 10  == 0x0a
	SIGNEXTEND			// 11  == 0x0b
)

// 0x10 range - comparison ops.
const (
	LT OpCode = iota + 0x10		// 0x10 == 16
	GT							// 0x11 == 17
	SLT							// 0x12
	SGT							// 0x13
	EQ							// 0x14
	ISZERO						// 0x15
	AND							// 0x16
	OR							// 0x17
	XOR							// 0x18
	NOT							// 0x19
	BYTE						// 0x1a	== 26
	SHL							// 0x1b
	SHR							// 0x1c
	SAR							// 0x1d == 29

	SHA3 = 0x20					// 32
)

// 0x30 range - closure state.
const (
	ADDRESS OpCode = 0x30 + iota 	// 0x30 == 48
	BALANCE							// 0x31 == 49
	ORIGIN							// 0x32
	CALLER							// 0x33
	CALLVALUE						// 0x34
	CALLDATALOAD					// 0x35
	CALLDATASIZE					// 0x36
	CALLDATACOPY					// 0x37
	CODESIZE						// 0x38
	CODECOPY						// 0x39
	GASPRICE						// 0x3a == 58
	EXTCODESIZE						// 0x3b
	EXTCODECOPY						// 0x3c
	RETURNDATASIZE					// 0x3d
	RETURNDATACOPY					// 0x3e
	EXTCODEHASH						// 0x3f == 63
)

// 0x40 range - block operations.
const (
	BLOCKHASH OpCode = 0x40 + iota		// 0x40 == 64
	COINBASE							// 0x41
	TIMESTAMP							// 0x42
	NUMBER								// 0x43
	DIFFICULTY							// 0x44
	GASLIMIT							// 0x45 == 69
)

// 0x50 range - 'storage' and execution.
const (
	POP OpCode = 0x50 + iota		// 0x50 == 80
	MLOAD							// 0x51
	MSTORE							// 0x52
	MSTORE8							// 0x53
	SLOAD							// 0x54
	SSTORE							// 0x55
	JUMP							// 0x56
	JUMPI							// 0x57
	PC								// 0x58
	MSIZE							// 0x59
	GAS								// 0x5a == 90
	JUMPDEST						// 0x5b == 91
)

// 0x60 range.
const (
	PUSH1 OpCode = 0x60 + iota		// 0x60 == 96
	PUSH2							// 0x61
	PUSH3							// 0x62
	PUSH4							// 0x63
	PUSH5							// 0x64
	PUSH6							// 0x65
	PUSH7							// 0x66
	PUSH8							// 0x67
	PUSH9							// 0x68
	PUSH10							// 0x69
	PUSH11							// 0x6a == 106
	PUSH12							// 0x6b
	PUSH13							// 0x6c
	PUSH14							// 0x6d
	PUSH15							// 0x6e
	PUSH16							// 0x6f
	PUSH17							// 0x70 == 112
	PUSH18							// 0x71
	PUSH19							// 0x72
	PUSH20							// 0x73
	PUSH21							// 0x74
	PUSH22							// 0x75
	PUSH23							// 0x76
	PUSH24							// 0x77
	PUSH25							// 0x78
	PUSH26							// 0x79
	PUSH27							// 0x7a == 122
	PUSH28							// 0x7b
	PUSH29							// 0x7c
	PUSH30							// 0x7d
	PUSH31							// 0x7e
	PUSH32							// 0x7f
	DUP1							// 0x80 == 128
	DUP2							// 0x81
	DUP3							// 0x82
	DUP4							// 0x83
	DUP5							// 0x84
	DUP6							// 0x85
	DUP7							// 0x86
	DUP8							// 0x87
	DUP9							// 0x88
	DUP10							// 0x89
	DUP11							// 0x8a == 138
	DUP12							// 0x8b
	DUP13							// 0x8c
	DUP14							// 0x8d
	DUP15							// 0x8e
	DUP16							// 0x8f
	SWAP1							// 0x90 == 144
	SWAP2							// 0x91
	SWAP3							// 0x92
	SWAP4							// 0x93
	SWAP5							// 0x94
	SWAP6							// 0x95
	SWAP7							// 0x96
	SWAP8							// 0x97
	SWAP9							// 0x98
	SWAP10							// 0x99
	SWAP11							// 0x9a == 154
	SWAP12							// 0x9b
	SWAP13							// 0x9c
	SWAP14							// 0x9d
	SWAP15							// 0x9e
	SWAP16							// 0x9f == 159
)

// 0xa0 range - logging ops.
const (
	LOG0 OpCode = 0xa0 + iota 		// 0xa0 == 160
	LOG1							// 0xa1 == 161
	LOG2							// 0xa2
	LOG3							// 0xa3
	LOG4							// 0xa4 == 164
)

// unofficial opcodes used for parsing.
const (
	PUSH OpCode = 0xb0 + iota		// 0xb0 == 176
	DUP								// 0xb1
	SWAP							// 0xb2 == 178
)

// 0xf0 range - closures.
// 取值为 0xf0 - 0xff
const (
	CREATE OpCode = 0xf0 + iota  	// 0xf0 == 15 * 16 == 240
	CALL							// 0xf1  这个一个执行码对应的 execute 中会再次调用EVM.Call() 函数，使得Call函数形成 【间接递归】
	CALLCODE						// 0xf2
	RETURN							// 0xf3
	DELEGATECALL					// 0xf4
	CREATE2							// 0xf5
	STATICCALL = 0xfa				// 0xfa == 250

	REVERT       = 0xfd				// 0xfd	== 253
	SELFDESTRUCT = 0xff				// 0xff	== 255
)

/** 下面是上述的执行码对应的字符串 */
// Since the opcodes aren't all in order we can't use a regular slice.
var opCodeToString = map[OpCode]string{
	// 0x0 range - arithmetic ops.
	STOP:       "STOP",
	ADD:        "ADD",
	MUL:        "MUL",
	SUB:        "SUB",
	DIV:        "DIV",
	SDIV:       "SDIV",
	MOD:        "MOD",
	SMOD:       "SMOD",
	EXP:        "EXP",
	NOT:        "NOT",
	LT:         "LT",
	GT:         "GT",
	SLT:        "SLT",
	SGT:        "SGT",
	EQ:         "EQ",
	ISZERO:     "ISZERO",
	SIGNEXTEND: "SIGNEXTEND",

	// 0x10 range - bit ops.
	AND:    "AND",
	OR:     "OR",
	XOR:    "XOR",
	BYTE:   "BYTE",
	SHL:    "SHL",
	SHR:    "SHR",
	SAR:    "SAR",
	ADDMOD: "ADDMOD",
	MULMOD: "MULMOD",

	// 0x20 range - crypto.
	SHA3: "SHA3",

	// 0x30 range - closure state.
	ADDRESS:        "ADDRESS",
	BALANCE:        "BALANCE",
	ORIGIN:         "ORIGIN",
	CALLER:         "CALLER",
	CALLVALUE:      "CALLVALUE",
	CALLDATALOAD:   "CALLDATALOAD",
	CALLDATASIZE:   "CALLDATASIZE",
	CALLDATACOPY:   "CALLDATACOPY",
	CODESIZE:       "CODESIZE",
	CODECOPY:       "CODECOPY",
	GASPRICE:       "GASPRICE",
	EXTCODESIZE:    "EXTCODESIZE",
	EXTCODECOPY:    "EXTCODECOPY",
	RETURNDATASIZE: "RETURNDATASIZE",
	RETURNDATACOPY: "RETURNDATACOPY",
	EXTCODEHASH:    "EXTCODEHASH",

	// 0x40 range - block operations.
	BLOCKHASH:  "BLOCKHASH",
	COINBASE:   "COINBASE",
	TIMESTAMP:  "TIMESTAMP",
	NUMBER:     "NUMBER",
	DIFFICULTY: "DIFFICULTY",
	GASLIMIT:   "GASLIMIT",

	// 0x50 range - 'storage' and execution.
	POP: "POP",
	//DUP:     "DUP",
	//SWAP:    "SWAP",
	MLOAD:    "MLOAD",
	MSTORE:   "MSTORE",
	MSTORE8:  "MSTORE8",
	SLOAD:    "SLOAD",
	SSTORE:   "SSTORE",
	JUMP:     "JUMP",
	JUMPI:    "JUMPI",
	PC:       "PC",
	MSIZE:    "MSIZE",
	GAS:      "GAS",
	JUMPDEST: "JUMPDEST",

	// 0x60 range - push.
	PUSH1:  "PUSH1",
	PUSH2:  "PUSH2",
	PUSH3:  "PUSH3",
	PUSH4:  "PUSH4",
	PUSH5:  "PUSH5",
	PUSH6:  "PUSH6",
	PUSH7:  "PUSH7",
	PUSH8:  "PUSH8",
	PUSH9:  "PUSH9",
	PUSH10: "PUSH10",
	PUSH11: "PUSH11",
	PUSH12: "PUSH12",
	PUSH13: "PUSH13",
	PUSH14: "PUSH14",
	PUSH15: "PUSH15",
	PUSH16: "PUSH16",
	PUSH17: "PUSH17",
	PUSH18: "PUSH18",
	PUSH19: "PUSH19",
	PUSH20: "PUSH20",
	PUSH21: "PUSH21",
	PUSH22: "PUSH22",
	PUSH23: "PUSH23",
	PUSH24: "PUSH24",
	PUSH25: "PUSH25",
	PUSH26: "PUSH26",
	PUSH27: "PUSH27",
	PUSH28: "PUSH28",
	PUSH29: "PUSH29",
	PUSH30: "PUSH30",
	PUSH31: "PUSH31",
	PUSH32: "PUSH32",

	DUP1:  "DUP1",
	DUP2:  "DUP2",
	DUP3:  "DUP3",
	DUP4:  "DUP4",
	DUP5:  "DUP5",
	DUP6:  "DUP6",
	DUP7:  "DUP7",
	DUP8:  "DUP8",
	DUP9:  "DUP9",
	DUP10: "DUP10",
	DUP11: "DUP11",
	DUP12: "DUP12",
	DUP13: "DUP13",
	DUP14: "DUP14",
	DUP15: "DUP15",
	DUP16: "DUP16",

	SWAP1:  "SWAP1",
	SWAP2:  "SWAP2",
	SWAP3:  "SWAP3",
	SWAP4:  "SWAP4",
	SWAP5:  "SWAP5",
	SWAP6:  "SWAP6",
	SWAP7:  "SWAP7",
	SWAP8:  "SWAP8",
	SWAP9:  "SWAP9",
	SWAP10: "SWAP10",
	SWAP11: "SWAP11",
	SWAP12: "SWAP12",
	SWAP13: "SWAP13",
	SWAP14: "SWAP14",
	SWAP15: "SWAP15",
	SWAP16: "SWAP16",
	LOG0:   "LOG0",
	LOG1:   "LOG1",
	LOG2:   "LOG2",
	LOG3:   "LOG3",
	LOG4:   "LOG4",

	// 0xf0 range.
	CREATE:       "CREATE",
	CALL:         "CALL",
	RETURN:       "RETURN",
	CALLCODE:     "CALLCODE",
	DELEGATECALL: "DELEGATECALL",
	CREATE2:      "CREATE2",
	STATICCALL:   "STATICCALL",
	REVERT:       "REVERT",
	SELFDESTRUCT: "SELFDESTRUCT",

	PUSH: "PUSH",
	DUP:  "DUP",
	SWAP: "SWAP",
}

func (op OpCode) String() string {
	str := opCodeToString[op]
	if len(str) == 0 {
		return fmt.Sprintf("Missing opcode 0x%x", int(op))
	}

	return str
}

// 字符串对应的执行码
var stringToOp = map[string]OpCode{
	"STOP":           STOP,
	"ADD":            ADD,
	"MUL":            MUL,
	"SUB":            SUB,
	"DIV":            DIV,
	"SDIV":           SDIV,
	"MOD":            MOD,
	"SMOD":           SMOD,
	"EXP":            EXP,
	"NOT":            NOT,
	"LT":             LT,
	"GT":             GT,
	"SLT":            SLT,
	"SGT":            SGT,
	"EQ":             EQ,
	"ISZERO":         ISZERO,
	"SIGNEXTEND":     SIGNEXTEND,
	"AND":            AND,
	"OR":             OR,
	"XOR":            XOR,
	"BYTE":           BYTE,
	"SHL":            SHL,
	"SHR":            SHR,
	"SAR":            SAR,
	"ADDMOD":         ADDMOD,
	"MULMOD":         MULMOD,
	"SHA3":           SHA3,
	"ADDRESS":        ADDRESS,
	"BALANCE":        BALANCE,
	"ORIGIN":         ORIGIN,
	"CALLER":         CALLER,
	"CALLVALUE":      CALLVALUE,
	"CALLDATALOAD":   CALLDATALOAD,
	"CALLDATASIZE":   CALLDATASIZE,
	"CALLDATACOPY":   CALLDATACOPY,
	"DELEGATECALL":   DELEGATECALL,
	"STATICCALL":     STATICCALL,
	"CODESIZE":       CODESIZE,
	"CODECOPY":       CODECOPY,
	"GASPRICE":       GASPRICE,
	"EXTCODESIZE":    EXTCODESIZE,
	"EXTCODECOPY":    EXTCODECOPY,
	"RETURNDATASIZE": RETURNDATASIZE,
	"RETURNDATACOPY": RETURNDATACOPY,
	"EXTCODEHASH":    EXTCODEHASH,
	"BLOCKHASH":      BLOCKHASH,
	"COINBASE":       COINBASE,
	"TIMESTAMP":      TIMESTAMP,
	"NUMBER":         NUMBER,
	"DIFFICULTY":     DIFFICULTY,
	"GASLIMIT":       GASLIMIT,
	"POP":            POP,
	"MLOAD":          MLOAD,
	"MSTORE":         MSTORE,
	"MSTORE8":        MSTORE8,
	"SLOAD":          SLOAD,
	"SSTORE":         SSTORE,
	"JUMP":           JUMP,
	"JUMPI":          JUMPI,
	"PC":             PC,
	"MSIZE":          MSIZE,
	"GAS":            GAS,
	"JUMPDEST":       JUMPDEST,
	"PUSH1":          PUSH1,
	"PUSH2":          PUSH2,
	"PUSH3":          PUSH3,
	"PUSH4":          PUSH4,
	"PUSH5":          PUSH5,
	"PUSH6":          PUSH6,
	"PUSH7":          PUSH7,
	"PUSH8":          PUSH8,
	"PUSH9":          PUSH9,
	"PUSH10":         PUSH10,
	"PUSH11":         PUSH11,
	"PUSH12":         PUSH12,
	"PUSH13":         PUSH13,
	"PUSH14":         PUSH14,
	"PUSH15":         PUSH15,
	"PUSH16":         PUSH16,
	"PUSH17":         PUSH17,
	"PUSH18":         PUSH18,
	"PUSH19":         PUSH19,
	"PUSH20":         PUSH20,
	"PUSH21":         PUSH21,
	"PUSH22":         PUSH22,
	"PUSH23":         PUSH23,
	"PUSH24":         PUSH24,
	"PUSH25":         PUSH25,
	"PUSH26":         PUSH26,
	"PUSH27":         PUSH27,
	"PUSH28":         PUSH28,
	"PUSH29":         PUSH29,
	"PUSH30":         PUSH30,
	"PUSH31":         PUSH31,
	"PUSH32":         PUSH32,
	"DUP1":           DUP1,
	"DUP2":           DUP2,
	"DUP3":           DUP3,
	"DUP4":           DUP4,
	"DUP5":           DUP5,
	"DUP6":           DUP6,
	"DUP7":           DUP7,
	"DUP8":           DUP8,
	"DUP9":           DUP9,
	"DUP10":          DUP10,
	"DUP11":          DUP11,
	"DUP12":          DUP12,
	"DUP13":          DUP13,
	"DUP14":          DUP14,
	"DUP15":          DUP15,
	"DUP16":          DUP16,
	"SWAP1":          SWAP1,
	"SWAP2":          SWAP2,
	"SWAP3":          SWAP3,
	"SWAP4":          SWAP4,
	"SWAP5":          SWAP5,
	"SWAP6":          SWAP6,
	"SWAP7":          SWAP7,
	"SWAP8":          SWAP8,
	"SWAP9":          SWAP9,
	"SWAP10":         SWAP10,
	"SWAP11":         SWAP11,
	"SWAP12":         SWAP12,
	"SWAP13":         SWAP13,
	"SWAP14":         SWAP14,
	"SWAP15":         SWAP15,
	"SWAP16":         SWAP16,
	"LOG0":           LOG0,
	"LOG1":           LOG1,
	"LOG2":           LOG2,
	"LOG3":           LOG3,
	"LOG4":           LOG4,
	"CREATE":         CREATE,
	"CREATE2":        CREATE2,
	"CALL":           CALL,
	"RETURN":         RETURN,
	"CALLCODE":       CALLCODE,
	"REVERT":         REVERT,
	"SELFDESTRUCT":   SELFDESTRUCT,
}

// StringToOp finds the opcode whose name is stored in `str`.
func StringToOp(str string) OpCode {
	return stringToOp[str]
}
