package vm

import (
	"go-ethereum/common"
	"go-ethereum/params"
	"go-ethereum/log"
	"fmt"
	"encoding/hex"
	"bytes"
	"go-ethereum/rlp"
	"go-ethereum/core/types"
	"go-ethereum/crypto"
)


const (
	GavinEvent       = "CandidateDepositEvent"
)

var PrecompiledContractsGavin = map[common.Address]PrecompiledContract{
	common.GavinAddr: &GavinContract{},
}

type GavinContract struct {
	Contract *Contract
	Evm      *EVM
}

func (c *GavinContract) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

func (c *GavinContract) Run(input []byte) ([]byte, error) {


	log.Debug("Setting Call EncodeBytes", "Key's content:", fmt.Sprintf(" Value：%+v, Content' Hash：%v", common.BytesToHash(common.GetKey()), hex.EncodeToString(common.BytesToHash(common.GetKey()).Bytes())))
	log.Debug("Setting Call EncodeBytes", "Value's content:", fmt.Sprintf(" Value：%+v, Content' Hash：%v", common.BytesToHash(common.GetValue()), hex.EncodeToString(common.BytesToHash(common.GetValue()).Bytes())))
	c.Evm.StateDB.SetState(common.GavinAddr, common.BytesToHash(common.GetKey()), common.BytesToHash(common.GetValue()))
	c.addLog(GavinEvent, string("Hello Gavin !!!!!!"))
	return nil, nil
}


func (c *GavinContract) addLog (event, data string) {
	var logdata [][]byte
	logdata = make([][]byte, 0)
	logdata = append(logdata, []byte(data))
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, logdata); nil != err {
		log.Error("addlog Err==> ", "rlp encode fail: ", err.Error())
	}
	c.Evm.StateDB.AddLog(&types.Log{
		Address:     common.GavinAddr,
		Topics:      []common.Hash{common.BytesToHash(crypto.Keccak256([]byte(event)))},
		Data:        buf.Bytes(),
		BlockNumber: c.Evm.Context.BlockNumber.Uint64(),
	})
}